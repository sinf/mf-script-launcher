package main

import (
    "encoding/json"
    "log"
    "fmt"
    "io/ioutil"
    "net"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "html/template"
    "context"
    // for totp:
    "time"
    "crypto/hmac"
    "crypto/sha1"
    "encoding/binary"
    "encoding/base32"
)

type Config struct {
    Port       int       `json:"port"`
    BindIP     string    `json:"bind_ip"`
    TlsPrivKey string    `json:"tls_privkey"`
    TlsCert    string    `json:"tls_cert"`
    Passphrase string    `json:"passphrase"`
    TotpSecret string    `json:"totpsecret"`
    Services   []Service `json:"services"`
}

type Service struct {
    Name    string `json:"name"`
    Command []string `json:"command"`
    // optional extra description to show on web form
    Descr   string `json:"descr"`
}

const SCRIPT_TIMEOUT_SEC = 30

const EXAMPLE_CONFIG string = `{
    "port": 3000,
    "bind_ip": "127.0.0.1",
    "tls_privkey": "blah.key",
    "tls_cert": "blah.crt",
    "passphrase": "supersecret123",
    "totpsecret": "banaani",
    "services": [
        {"name": "Test button", "command": ["id"]},
        {"name": "Test button 2", "command": ["date"], "descr": "additional text"},
        {"name": "Test button 3", "command": ["echo", "client ip", "%IP%", "port", "%PORT%"]}
    ]
}`

var STYLESHEET string = ""

func readFile(filename string) ([]byte, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    return ioutil.ReadAll(file)
}

func loadStyle(filename string) {
    data, err := readFile(filename)
    if err == nil {
        STYLESHEET = string(data)
        log.Println("Loaded", filename)
    } else {
        STYLESHEET = ""
        log.Println("Failed to load", filename, err)
    }
}

func loadConfig(filename string) (*Config, error) {
    data, err := readFile(filename)
    if err != nil {
        return nil, err
    }
    var config Config
    err = json.Unmarshal(data, &config)
    if err != nil {
        return nil, err
    }
    return &config, nil
}

type FrontPageData struct {
    Style string
    CurrentTime string
    Services []Service
}

func generateForm(services []Service) string {
    data := FrontPageData {
        CurrentTime: time.Now().UTC().Format(time.RFC3339),
        Services: services,
    }
    formTemplate := `<!DOCTYPE html>
<html>
<head>
<title>MFA service portal</title>
<link rel="stylesheet" href="style.css" type="text/css">
</head>
<body>
    <h3>MFA service portal</h3>
    <form action="/submit" method="post">
        <label for="passphrase-input">Enter passphrase:</label>
        <input id="passphrase-input" type="password" name="passphrase" required autocomplete="current-password">
        <br>
        <label for="totp-input">Enter secret code:</label>
        <input id="totp-input" type="text" name="secret_code" required>
        <br>
        <label>Select service:<br/>
            {{range .Services}}
                <label>
                    <input type="checkbox" name="service" value="{{.Name}}" />
                    {{.Name}}
                </label> <span class="descr">{{ .Descr }}</span>
                <br>
            {{end}}
        </label><br>
        <button type="submit">Submit</button>
    </form>
    <p>
    Current server timestamp: {{ .CurrentTime }} <br>
    Current client timestamp: <span id="servertime"><noscript>(dunno, js disabled)</noscript></span>
    </p>
    <script>document.getElementById("servertime").textContent = new Date().toISOString(); </script>
</body>
</html>`
    tmpl := template.Must(template.New("form").Parse(formTemplate))
    var renderedForm strings.Builder
    err := tmpl.Execute(&renderedForm, data)
    if err != nil {
        return "Error generating form."
    }
    return renderedForm.String()
}

func handleForm(config *Config, w http.ResponseWriter, r *http.Request) {
    formHTML := generateForm(config.Services)
    fmt.Fprint(w, formHTML)
}

func TOTP(secretKey string, timestamp int64) uint32 {
    // https://rednafi.com/go/totp_client/

    // The base32 encoded secret key string is decoded to a byte slice
    base32Decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
    secretKey = strings.ToUpper(strings.TrimSpace(secretKey)) // preprocess
    secretBytes, _ := base32Decoder.DecodeString(secretKey) // decode

    // The truncated timestamp / 30 is converted to an 8-byte big-endian
    // unsigned integer slice
    timeBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(timeBytes, uint64(timestamp) / 30)

    // The timestamp bytes are concatenated with the decoded secret key
    // bytes. Then a 20-byte SHA-1 hash is calculated from the byte slice
    hash := hmac.New(sha1.New, secretBytes)
    hash.Write(timeBytes) // Concat the timestamp byte slice
    h := hash.Sum(nil)    // Calculate 20-byte SHA-1 digest

    // AND the SHA-1 with 0x0F (15) to get a single-digit offset
    offset := h[len(h)-1] & 0x0F

    // Truncate the SHA-1 by the offset and convert it into a 32-bit
    // unsigned int. AND the 32-bit int with 0x7FFFFFFF (2147483647)
    // to get a 31-bit unsigned int.
    truncatedHash := binary.BigEndian.Uint32(h[offset:]) & 0x7FFFFFFF

    // Take modulo 1_000_000 to get a 6-digit code
    return truncatedHash % 1_000_000
}

func validateTOTP(config *Config, userCode string) bool {
    secret := config.TotpSecret
    now := time.Now().Unix()
    // comparing at most 2 adjacent codes. base32 decode happens 3 times needlessly lol
    for _, num := range []int64{0, -15, 15} {
        totp := fmt.Sprintf("%06d", TOTP(secret, int64(now + num)))
        if totp == userCode {
            return true
        }
    }
    return false
}

func validateCode(config *Config, passphrase string, totp_code string) bool {
    return passphrase == config.Passphrase && validateTOTP(config, totp_code)
}

func findServiceByName(services []Service, inputName string) *Service {
    for _, service := range services {
        if service.Name == inputName {
            return &service
        }
    }
    return nil
}

func submitOK(config *Config, w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
<title>Submission Successful</title>
<link rel="stylesheet" href="style.css" type="text/css">
</head>
<body>
    <p>OK</p>
    <p><a href="/">Go back to form</a></p>
</body>
</html>`)
}

func serveErrorPage(w http.ResponseWriter, errorMessage string, statusCode int) {
    w.WriteHeader(statusCode)
    fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Error</title>
<link rel="stylesheet" href="style.css" type="text/css">
</head>
<body>
    <p style="color: red;">Error %d: %s</p>
    <p><a href="/">Go back to form</a></p>
</body>
</html>`, statusCode, errorMessage)
}

func backgroundCmd(srv *Service, clientIp string, clientPort string) {
    logprefix := "[" + srv.Name + "] " + clientIp + "_" + clientPort + " "

    args := make([]string, len(srv.Command))
    copy(args, srv.Command)
    for i, arg := range args {
        if arg == "%IP%" {
            args[i] = clientIp
        }
        if arg == "%PORT%" {
            args[i] = clientPort
        }
        if arg == "%DESCR%" {
            args[i] = srv.Descr
        }
        if arg == "%NAME%" {
            args[i] = srv.Name
        }
    }
    log.Println(logprefix, args)

    ctx, cancel := context.WithTimeout(context.Background(), SCRIPT_TIMEOUT_SEC*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, args[0], args[1:]...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    err := cmd.Start()
    if err != nil {
        log.Println(logprefix, "Tried to run command:\n", args, "\nError:\n", err)
        return
    }
    err = cmd.Wait()
    if ctx.Err() == context.DeadlineExceeded {
        log.Println(logprefix, "command timed out")
    } else if err != nil {
        log.Println(logprefix, err)
    } else {
        log.Println(logprefix, "complete")
    }
}

func runServices(config *Config, serviceNames []string, clientAddr string) {
    ip, port, err := net.SplitHostPort(clientAddr)
    if err != nil {
        log.Println("Client has bad address", err)
        return
    }

    for _, serviceName := range serviceNames {
        srv := findServiceByName(config.Services, serviceName)
        if srv != nil && len(srv.Command)>0  {
            go backgroundCmd(srv, ip, port)
        }
    }

    log.Println("Service start goroutine exit")
}

func handleSubmit(config *Config, w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        serveErrorPage(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }
    userPass := r.FormValue("passphrase")
    userSecret := r.FormValue("secret_code")

    if validateCode(config, userPass, userSecret) {
        selectedServices := r.Form["service"]
        go runServices(config, selectedServices, r.RemoteAddr)
        submitOK(config, w, r)
    } else {
        serveErrorPage(w, "Unauthorized", http.StatusUnauthorized)
    }
}

func handleStyle(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }
    if len(STYLESHEET)==0 {
        http.Error(w, "No css available. Use your browser default style", http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "text/css")
    fmt.Fprint(w, STYLESHEET)
}

func test_totp_generator(secret string) {
    now := time.Now().Unix()
    log.Println("Testing TOTP generator")
    log.Printf("TOTP -30s: %06d\n", TOTP(secret, (now - 30)))
    log.Printf("TOTP + 0s: %06d\n", TOTP(secret, now))
    log.Printf("TOTP +30s: %06d\n", TOTP(secret, (now + 30)))
}

func main() {
    log.Println("Startup")
    config, err := loadConfig("config.json")
    if err != nil {
        fmt.Println("Error loading config:", err)
        fmt.Println("Example config.json")
        fmt.Println(EXAMPLE_CONFIG)
        fmt.Println("You could also put services section into services.json")
    }
    log.Println("Loaded config.json")

    service_config, err := loadConfig("services.json")
    if err == nil && service_config.Services != nil {
        if config.Services == nil {
            config.Services = service_config.Services
        } else {
            config.Services = append(config.Services, service_config.Services...)
        }
        log.Println("Loaded additional service lines from services.json")
    }

    // if this fails, whatever
    loadStyle("style.css")

    if len(config.Services) == 0 {
        log.Println("No services defined. Include a \"services\" key in either config")
        os.Exit(1)
    }

    if len(os.Args)>1 && os.Args[1] == "-t" {
        // Test mode: validate config syntax and TOTP generator output
        test_totp_generator(config.TotpSecret)
        return
    }

    http.HandleFunc("/style.css", handleStyle)
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        handleForm(config, w, r)
    })
    http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
        handleSubmit(config, w, r)
    })

    serverAddr := fmt.Sprintf("%s:%d", config.BindIP, config.Port)

    if len(config.TlsPrivKey)>0 && len(config.TlsCert)>0 {
        log.Println("Listening on https://" + serverAddr)
        err = http.ListenAndServeTLS(serverAddr, config.TlsCert, config.TlsPrivKey, nil)
    } else {
        log.Println("WARNING! unencrypted http")
        log.Println("Listening on http://" + serverAddr)
        err = http.ListenAndServe(serverAddr, nil)
    }
    if err != nil {
        log.Println("Error starting server:", err)
    }
}


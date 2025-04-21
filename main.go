package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "html/template"

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
}

/* example config:

{
    "port": 3000,
    "bind_ip": "127.0.0.1",
    "tls_privkey": "blah.key",
    "tls_cert": "blah.crt",
    "passphrase": "supersecret123",
    "totpsecret": "banaani",
    "services": [
        {"name": "List Files", "command": ["ls"]},
        {"name": "Show Date", "command": ["date"]},
        {"name": "Current User", "command": ["whoami"]},
        {"name": "Echo stuff", "command": ["echo", "client ip", "%IP%", "port", "%PORT%"]}
    ]
}

*/

func loadConfig(filename string) (*Config, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    data, err := ioutil.ReadAll(file)
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

func generateForm(services []Service) string {
    formTemplate := `
    <!DOCTYPE html>
    <html>
    <head><title>Service Selector</title></head>
    <body>
        <form action="/submit" method="post">
            <label>Enter passphrase: <input type="text" name="passphrase" required></label><br>
            <label>Enter secret code: <input type="text" name="secret_code" required></label><br>
            <label>Select service:<br/>
                {{range .}}
                    <label>
                        <input type="checkbox" name="service" value="{{.Name}}" />
                        {{.Name}}
                    </label><br/>
                {{end}}
            </label><br>
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    `
    tmpl := template.Must(template.New("form").Parse(formTemplate))
    var renderedForm strings.Builder
    err := tmpl.Execute(&renderedForm, services)
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
<head><title>Submission Successful</title></head>
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
<head><title>Error</title></head>
<body>
    <p style="color: red;">Error %d: %s</p>
    <p><a href="/">Go back to form</a></p>
</body>
</html>`, statusCode, errorMessage)
}

func backgroundCmd(srv *Service, clientIp string, clientPort string) {
    fmt.Println("Client", clientIp, ":", clientPort, "called service", srv.Name)

    args := make([]string, len(srv.Command))
    copy(args, srv.Command)

    for i, arg := range args {
        if arg == "%IP%" {
            args[i] = clientIp
        }
        if arg == "%PORT%" {
            args[i] = clientPort
        }
    }
    fmt.Println(args)

    cmd := exec.Command(args[0], args[1:]...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    err := cmd.Start()
    if err != nil {
        fmt.Println("Tried to run command:\n", args, "\nError:\n", err)
    }
}

func runServices(config *Config, serviceNames []string, clientAddr string) {

    // IPv6 not supported. TODO / FIXME
    parts := strings.Split(clientAddr, ":")
    if len(parts) != 2 {
        fmt.Println("Client has bad address", clientAddr)
        return
    }
    ip := parts[0]
    port := parts[1]

    for _, serviceName := range serviceNames {
        srv := findServiceByName(config.Services, serviceName)
        if srv != nil && len(srv.Command)>0  {
            backgroundCmd(srv, ip, port)
        }
    }
}

func handleSubmit(config *Config, w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        serveErrorPage(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    userPass := r.FormValue("passphrase")
    userSecret := r.FormValue("secret_code")
    selectedServices := r.Form["service"]

    if ! validateCode(config, userPass, userSecret) {
        serveErrorPage(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    go runServices(config, selectedServices, r.RemoteAddr)
    submitOK(config, w, r)
}

func main() {
    config, err := loadConfig("config.json")
    if err != nil {
        fmt.Println("Error loading config:", err)
        return
    }

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        handleForm(config, w, r)
    })
    http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
        handleSubmit(config, w, r)
    })

    serverAddr := fmt.Sprintf("%s:%d", config.BindIP, config.Port)

    if len(config.TlsPrivKey)>0 && len(config.TlsCert)>0 {
        fmt.Println("Listening on https://" + serverAddr)
        err = http.ListenAndServeTLS(serverAddr, config.TlsCert, config.TlsPrivKey, nil)
    } else {
        fmt.Println("WARNING: unencrypted http")
        fmt.Println("Listening on http://" + serverAddr)
        err = http.ListenAndServe(serverAddr, nil)
    }
    if err != nil {
        fmt.Println("Error starting server:", err)
    }
}

func main1() {
    secret := "banaani"
    now := time.Now().Unix()
    fmt.Printf("TOTP -30s: %06d\n", TOTP(secret, (now - 30)))
    fmt.Printf("TOTP + 0s: %06d\n", TOTP(secret, now))
    fmt.Printf("TOTP +30s: %06d\n", TOTP(secret, (now + 30)))
}


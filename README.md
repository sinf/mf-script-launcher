# mf-script-launcher

This tiny web service has a predefined list of commands (only title shown to user, not command). When user inputs a list of requested commands, a password and a TOTP code, the web service launches the requested commands. It can optionally substitute client IP and port into the command. Command output is not shown to user (only printed to console for logging).  

The main usecase is adding temporary short lived firewall rules specifically for the same client who submitted the input form. This can protect any generic web service with MFA that wouldn't otherwise have any MFA.  

Example config.json  
```
{
    "port": 3000,
    "bind_ip": "127.0.0.1",
    "tls_privkey": "blah.key",
    "tls_cert": "blah.crt",
    "passphrase": "supersecret123",
    "totpsecret": "blahblahinbase32"
}
```
Example services.json  
```
{
    "services": [
        {
            "name": "Example 1 - verify this thing runs as unprivileged user",
            "command": ["id"]
        },
        {
            "name": "Example 2 - parameters",
            "command": ["echo", "client ip", "%IP%", "port", "%PORT%"],
            "descr": "additional text"
        },
        {
            "name": "Example 3 - let me browse cool secret page just for a moment",
            "command": [
                "./make-temporary-firewall-opening.sh",
                "--source-ip", "%IP%",
                "--destination-ip", "xxxxxxxxxxxx",
                "--destination-port", "443",
                "--opening-duration", "600"
            ]
        }
    ]
}
```

Form shown to user on https://127.0.0.1:3000  
```
Enter passphrase: _____
Enter secret code: _____
Select service:
[ ] Example 1 - verify this thing runs as unprivileged user
[ ] Example 2 - parameters
    additional text
[ ] Example 3 - let me browse cool secret page just for a moment
( Submit )
```


# mf-script-launcher

This tiny web service has a predefined list of commands (only title shown to user, not command). When user inputs a list of requested commands, a password and a TOTP code, the web service launches the requested commands. It can optionally substitute client IP and port into the command. Command output is not shown.  

The main usecase is adding temporary short lived firewall rules specifically for the same client who submitted the input form. This can protect any generic web service with MFA that wouldn't otherwise have any MFA.  

Example config:
```
{
    "port": 3000,
    "bind_ip": "127.0.0.1",
    "tls_privkey": "blah.key",
    "tls_cert": "blah.crt",
    "passphrase": "supersecret123",
    "totpsecret": "blahblahinbase32",
    "services": [
        {"name": "Service 1", "command": ["ls"]},
        {"name": "Service 2", "command": ["date"]},
        {"name": "Service 3", "command": ["echo", "client ip", "%IP%", "port", "%PORT%"]}
    ]
}
```

Form shown to user on https://127.0.0.1:3000  
```
Enter passphrase: _____
Enter secret code: _____
Select service:
[ ] Service 1
[ ] Service 2
[ ] Service 3
( Submit )
```


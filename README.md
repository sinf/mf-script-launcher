# mf-script-launcher

This program provides multifactor authentication for anything accessible over network.  

Usecase: Open html form. Enter password, TOTP code and tick checkboxes for which webpages/services you need to access. Submit. Then you get short lived firewall rules allowing momentary access from your client IP to requested server IP & port.  

Minimal code, no processing of user inputs other than simple equality comparison. Only minimal information is shown to user. Denial of service is possible but nothing else should be.  

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
            ],
            "link": "https://xxxxxxxxxxxxxxxxx"
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

Ingredients for a iptables-based firewall script that creates short-lived temporary rules.  
```
# Only need one firewall rule and ipset.
# - Source/destination IP's must be in predefined subnet, regardless of ipset content
# - Source/destination interface must be something
# - New connections only. Another preexisting rule handles established connections
# - ipset must have a match for (source ip, destination port, destination ip)
# - ipset rows get automatically deleted when timeout expires

# One-time initial setup:
ipset create $ipset_name hash:ip,port,ip timeout 1 comment
iptables -I $chain -i $interface_in -o $interface_out -s $net_in -d $net_out -m conntrack --ctstate NEW -m set --match-set $ipset_name src,dst,dst -j ACCEPT

# This is for firewall script called by the MFA portal, which adds a temporary row to ipset.
# proto_port could be something like tcp:443
# To reset timer to maximum value when entry already exists, it must be deleted and re-added
ipset del "$ipset_name" "$src_ip,$proto_port,$dst_ip"
ipset add "$ipset_name" "$src_ip,$proto_port,$dst_ip" timeout "$timeout" comment "$comment"

# Shutdown
iptables -D $chain .....
ipset destroy $ipset_name
```



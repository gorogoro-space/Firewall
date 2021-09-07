# Firewall
Deny connections from VPNs, proxies, and harmful networks.

# Git Repository
- https://github.com/gorogoro-space/Firewall.git
- git@github.com:gorogoro-space/Firewall.git

# You may want to refer to the following for a list of IP addresses that you want to block.
- https://github.com/ejrv/VPNs
- https://github.com/firehol/blocklist-ipsets

# Command
```
/firewall reload - Reload config.
/firewall check ipaddr <ip address> - Check block ip address.
/firewall check uuid <UUID> - Check unblock UUID.
/firewall add uuid <UUID> - Add unblock UUID.
/firewall delete uuid <UUID> - Delete unblock UUID.
/firewall long cidr <CIDR> - Convert a CIDR to a value of type Long.
```
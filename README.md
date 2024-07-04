# Firewall 

### Features
1) Block IP addresses
2) Block access to certain ports 
### setup

1) For testing change the IP address according to your local IP address in code as well as in firewallrules.json in my case IP is 192.168.18.x you can write any number from 0 to 255 in place of x.

2) You can run the script like this:
   - sudo venv/bin/python3 firwall.py
### Requirements
1) Os ubuntu
1) netfilterqueue
2) scapy

### Testing

- To check ip you can run ping and the IP that you want to test.
- `ping IP`

- To check port first you have to listen on any port that you want to test. you can use the following command.
- `sudo nc -l -p 8080 -vv`

- Then you can curl with the IP address and port like `curl 192.168.18.4:8080`
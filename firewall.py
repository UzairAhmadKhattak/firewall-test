from netfilterqueue import NetfilterQueue
from scapy.all import IP,TCP,UDP
import os
import json

class FireWall:
    
    
    def __init__(self):
        try:
            with open("firewallrules.json","r") as file:
                rules = json.load(file)
            
            if("ListOfBannedIpAddr" in rules):
                if(type(rules["ListOfBannedIpAddr"])==list):
                    self.ListOfBannedIpAddr = rules["ListOfBannedIpAddr"]
                else:
                    print("Invalid ListOfBannedIpAddr in rule file. Defaulting to []")
                    self.ListOfBannedIpAddr = []
            else:
                print("ListOfBannedIpAddr missing in rule file. Defaulting to []")
                self.ListOfBannedIpAddr = []
                    
            if("ListOfBannedPorts" in rules):
                if(type(rules["ListOfBannedPorts"])==list):
                    self.ListOfBannedPorts = rules["ListOfBannedPorts"]
                else:
                    print("Invalid ListOfBannedPorts in rule file. Defaulting to []")
                    self.ListOfBannedPorts = []
            else:
                print("ListOfBannedPorts missing in rule file. Defaulting to []")
                self.ListOfBannedPorts = []
                    

        except FileNotFoundError:
            print("Rule file (firewallrules.json) not found, setting default values")
            self.ListOfBannedIpAddr = [] 
            self.ListOfBannedPorts = []

    def firewall(self,pkt):
        sca = IP(pkt.get_payload())

        if(sca.src in self.ListOfBannedIpAddr):
            print(sca.src, "is a incoming IP address that is banned by the firewall.")
            pkt.drop()
            return 

        if(sca.haslayer(TCP)):
            t = sca.getlayer(TCP)
            if(t.dport in self.ListOfBannedPorts):
                print(t.dport, "is a destination port that is blocked by the firewall.")
                pkt.drop()
                return 

        if(sca.haslayer(UDP)):
            t = sca.getlayer(UDP)
            if(t.dport in self.ListOfBannedPorts):
                print(t.dport, "is a destination port that is blocked by the firewall.")
                pkt.drop()
                return 

        
        pkt.accept()
    def main(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(1,self.firewall)


        try:
            os.system("iptables -I INPUT -d 192.168.18.0/24 -j NFQUEUE --queue-num 1")
            print("Waiting for packets...")
            nfqueue.run()
        except KeyboardInterrupt:
            pass
        finally:
            print("Iptables rules is reset")
            os.system("sudo iptables -D INPUT -d 192.168.18.0/24 -j NFQUEUE --queue-num 1")
            nfqueue.unbind()


firewall = FireWall()
firewall.main()
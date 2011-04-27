#!/usr/bin/env python

class ClientSideAttacks():
    def __init__(self, target):
        self.payloads = []
        self._target = target
        self._sudo  = "/usr/bin/sudo"
        self._nmap = "/usr/bin/nmap"
        self._niktobin = "/pentest/scanners/nikto-2.1.4/nikto.pl"
        self._niktocnf = "/pentest/scanners/nikto-2.1.4/nikto.conf"

    def getPayloads(self):

        return self.payloads

if __name__ == "__main__":
    print ClientSideAttacks("192.168.100.48").getPayloads()
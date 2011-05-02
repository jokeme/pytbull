#!/usr/bin/env python
"""
This module tests the ability of the server to track multiple
failed logins, which could be brute forcing attemps. The example
provided in this module is composed of 5 login attemps against the
FTP service.
"""

import ConfigParser

class MultipleFailedLogins():
    def __init__(self, target):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read('config.cfg')

        self._target = target
        self.payloads = []

    def getPayloads(self):

        self.payloads.append(['albert', 'abc'])
        self.payloads.append(['bernadette', 'bcd'])
        self.payloads.append(['christian', 'cde'])
        self.payloads.append(['dolores', 'def'])
        self.payloads.append(['erik', 'efg'])

        return self.payloads

if __name__ == "__main__":
    print MultipleFailedLogins("192.168.100.48").getPayloads()
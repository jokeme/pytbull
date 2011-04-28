#!/usr/bin/env python

import ConfigParser

class MultipleFailedLogins():
    def __init__(self, target):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read('config.cfg')

        self._target = target
        self.payloads = []

    def getPayloads(self):

        return self.payloads

if __name__ == "__main__":
    print MultipleFailedLogins("192.168.100.48").getPayloads()
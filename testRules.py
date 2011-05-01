#!/usr/bin/env python

import ConfigParser

class TestRules():
    def __init__(self, target):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read('config.cfg')

        self._target = target
        self.payloads = []

    def getPayloads(self):
        ### Simple LFI
        self.payloads.append([
            "Simple LFI",
            "socket",
            80,
            "GET /index.php?page=../../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5) Gecko/20041202 Firefox/1.0\r\n\r\n",
            "1:1122:8"
            ])

        ### LFI using NULL byte
        self.payloads.append([
            "LFI using NULL byte",
            "socket",
            80,
            "GET /index.php?page=../../../etc/passwd%00 HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5) Gecko/20041202 Firefox/1.0\r\n\r\n",
            "1:1122:8"
            ])

        ### Full SYN Scan
        self.payloads.append([
            "Full SYN Scan",
            "command",
            [self.config.get('PATHS','sudo'), self.config.get('PATHS','nmap'), '-sS', '-p-', self._target],
            "122:1:1"
            ])

        ### Full Connect() Scan
        self.payloads.append([
            "Full Connect() Scan",
            "command",
            [self.config.get('PATHS','nmap'), '-sT', '-p-', self._target],
            "122:1:1"
            ])

        ### SQL Injection
        self.payloads.append([
            "SQL Injection",
            "socket",
            80,
            "GET /form.php?q=1+UNION+SELECT+VERSION%28%29 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "(?i)UNION"
            ])

        ### Netcat Reverse Shell
        self.payloads.append([
            "Netcat Reverse Shell",
            "socket",
            22,
            "/bin/sh",
            "1:1324:10"
            ])

        ### Nikto Scan
        self.payloads.append([
            "Nikto Scan",
            "command",
            [self.config.get('PATHS','sudo'), self.config.get('PATHS','nikto'), '-config', self.config.get('PATHS','niktoconf'), '-h', self._target, '-Plugins', 'cgi'],
            "(?i)nikto"
            ])

        return self.payloads

if __name__ == "__main__":
    print TestRules("192.168.100.48").getPayloads()
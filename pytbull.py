#!/usr/bin/env python

"""
Pytbull is an IDS/IPS testing framework for Snort & Suricata developed by
Sebastien Damaye (sebastien #dot# damaye #at# gmail #dot# com).
It is shipped with 300 tests grouped in 8 testing modules. For more information,
please refer to <http://www.aldeid.com/index.php/Pytbull>.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from optparse import OptionParser
import ConfigParser
import socket
import time
from ftplib import FTP
from scapy.all import *
import subprocess
import os
import os.path
import sys
import datetime
import re

import testRules
import badTraffic
import fragmentedPackets
import multipleFailedLogins
import evasionTechniques
import shellCodes
import denialOfService
import clientSideAttacks

class Pytbull():
    def __init__(self, banner, target, idstype):
        print banner + "\n"
        
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read('config.cfg')

        # Vars initialization
        self._target    = target
        self._idstype   = idstype
        self.testnum    = 1
        self.tmpreport  = "/tmp/pytbull.tmp"

        # Check if prgm is called with root privs
        # Needed for generating raw packets (e.g. some nmap scans)
        print "BASIC CHECKS"
        print "------------"
        print "Checking root privileges".ljust(65, '.'),
        if(os.getuid() != 0):
            print "[ Failed ]"
            print "\nRoot privileges required!"
            sys.exit(0)
        print "[   OK   ]"

        print "Checking remote port 21/tcp (FTP)".ljust(65, '.'),
        try:
            ftp = FTP(self._target)
            ftp.login(config.get('CREDENTIALS','ftpuser'),config.get('CREDENTIALS','ftppasswd'))
            f.close()
            ftp.quit()
            print "[   OK   ]"
        except:
            print "[ Failed ]"
            print "\nFTP Connection refused on port 21/tcp!"
            sys.exit(0)
        
        # Remove temp file
        print "Removing temporary file".ljust(65, '.'),
        if os.path.exists("/tmp/pytbull.tmp"):
            os.remove("/tmp/pytbull.tmp")
        print "[   OK   ]"

        # Print tests selection
        print "\nTESTS"
        print "------------"

        print "Client Side Attacks".ljust(65, '.'),
        if self.config.get('TESTS', 'clientSideAttacks') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print "Test Rules".ljust(65, '.'),
        if self.config.get('TESTS', 'testRules') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print "Bad Traffic".ljust(65, '.'),
        if self.config.get('TESTS', 'badTraffic') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print "Fragmented Packets".ljust(65, '.'),
        if self.config.get('TESTS', 'fragmentedPackets') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print "Multiple Failed Logins".ljust(65, '.'),
        if self.config.get('TESTS', 'multipleFailedLogins') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print "Evasion Techniques".ljust(65, '.'),
        if self.config.get('TESTS', 'evasionTechniques') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print "ShellCodes".ljust(65, '.'),
        if self.config.get('TESTS', 'shellCodes') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print "Denial of Service".ljust(65, '.'),
        if self.config.get('TESTS', 'denialOfService') == '1':
            print "[   yes  ]"
        else:
            print "[   no   ]"

        print ""
        # Chek if paths are valid
        # ...to be completed...
        
    def testRules(self):
        payloads = TestRules(self._target).getPayloads()
        tests(payloads)

    def doTest(self, payloads):
        for payload in payloads:
            # Perform test & write report
            str = "TEST #%s - %s" % (self.testnum, payload[0])
            print str[:62].ljust(65,'.'),
            content  = """<p>[<a href="#">top</a>]</p>"""
            content += """<table border="1">"""
            content += """<tr><th>Test num</th><td>%s</td></tr>""" % self.testnum
            self.testnum += 1
            content += """<tr><th>Time</th><td>%s</td></tr>""" % datetime.datetime.now()
            content += """<tr><th>Test name</th><td>%s</td></tr>""" % payload[0]
            pattern = ""

            if payload[1] == "socket":
                content += """<tr><th>Port</th><td>%s/tcp</td></tr>""" % payload[2]
                content += """<tr><th style="vertical-align:top">Payload</th><td><textarea style="width:800px;height:60px;">%s</textarea></td></tr>""" % payload[3]
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self._target,payload[2]))
                s.send(payload[3])
                pattern = payload[4]
                s.close()
            elif payload[1] == "command":
                content += """<tr><th style="vertical-align:top">Payload</th><td><textarea style="width:800px;height:60px;">%s</textarea></td></tr>""" % ' '.join(payload[2])
                subprocess.call(payload[2], stdout=subprocess.PIPE)
                pattern = payload[3]
            elif payload[1] == "scapy":
                content += """<tr><th style="vertical-align:top">Payload</th><td><textarea style="width:800px;height:60px;">%s</textarea></td></tr>""" % payload[2]
                eval(payload[2])
                pattern = payload[3]

            # Sleep before getting alerts
            time.sleep(5)

            # Get new alerts and calculate new offset
            self.getAlertsFile(self._idstype)
            res = self.getAlertsFromOffset(self.tmpreport, self.offset)

            # Sig matching
            if pattern != "":
                if re.search(pattern, res):
                    color = '#30D021'
                    test = 'OK'
                else:
                    color = '#ff0000;color:#fff'
                    test = 'KO'
                content += """<tr><th>Sig matching</th>
                <td><div style="float:left;text-align:center;background:%s;width:60px;">%s</div>
                <div style="float:left;margin-left:10px;">Used pattern: %s</div><div style="clear:both"></div></td></tr>""" % (color, test, pattern)
            else:
                content += """<tr><th>Sig matching</th><td>None</td></tr>"""

            content += """<tr><th style="vertical-align:top">Alerts</th><td><textarea style="width:800px;height:200px;">%s</textarea></td></tr>""" % res
            self.offset = self.getOffset(self.tmpreport)

            content += """</table>"""
            self.writeReport(content)

            print "[  done  ]"
            
            # Sleep before next test
            time.sleep(3)

    def doClientSideAttacksTest(self, payloads):
        # Open socket (it will be closed at the end of the tests)
        # on port 12345/tcp
        # Check whether reverseshell is running on remote server (port 12345/tcp)
        print "Checking if reverse shell is running on remote host".ljust(65,'.'),
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self._target,12345))
        except:
            print "[ Failed ]"
            print "\n***ERROR: Please setup reverse shell on remote server first!"
            sys.exit(0)
        print "[   OK   ]"

        for payload in payloads:
            # Perform test & write report
            str = "TEST #%s - %s" % (self.testnum, payload[0])
            print str[:62].ljust(65,'.'),
            self.testnum += 1
            content  = """<p>[<a href="#">top</a>]</p>"""
            content += """<table border="1">"""
            content += """<tr><th>Test num</th><td>%s</td></tr>""" % self.testnum
            content += """<tr><th>Time</th><td>%s</td></tr>""" % datetime.datetime.now()
            content += """<tr><th>File</th><td>%s</td></tr>""" % payload[0]

            # Send cmd to execute on server side (wget file)
            s.send(payload[1])

            # Sleep before getting alerts
            time.sleep(5)

            # Get new alerts and calculate new offset
            self.getAlertsFile(self._idstype)
            res = self.getAlertsFromOffset(self.tmpreport, self.offset)
            content += """<tr><th style="vertical-align:top">Alerts</th><td><textarea style="width:800px;height:200px;">%s</textarea></td></tr>""" % res
            self.offset = self.getOffset(self.tmpreport)

            content += """</table>"""
            self.writeReport(content)
            print "[  done  ]"

        # Close socket
        s.close()

    def doMultipleFailedLoginsTest(self, payloads):
        # Open FTP Connection
        ftp = FTP(self._target)
        for payload in payloads:
            str = "TEST #%s - FTP Login attempt with %s/%s" % (self.testnum, payload[0], payload[1])
            print str[:62].ljust(65,'.'),
            self.testnum += 1
            try:
                ftp.login(payload[0],payload[1])
            except:
                pass
            print "[  done  ]"
            # Wait 5 seconds between 2 failed auth attempts
            time.sleep(5)

        # Close FTP connection
        ftp.close()

        # Perform test & write report
        content  = """<p>[<a href="#">top</a>]</p>"""
        content += """<table border="1">"""
        content += """<tr><th>Test num</th><td>%s</td></tr>""" % self.testnum
        self.testnum += 1
        content += """<tr><th>Time</th><td>%s</td></tr>""" % datetime.datetime.now()
        content += """<tr><th>Payload</th><td>Multiple failed logins attempts</td></tr>"""

        # Get new alerts and calculate new offset
        self.getAlertsFile(self._idstype)
        res = self.getAlertsFromOffset(self.tmpreport, self.offset)
        content += """<tr><th style="vertical-align:top">Alerts</th><td><textarea style="width:800px;height:200px;">%s</textarea></td></tr>""" % res
        self.offset = self.getOffset(self.tmpreport)
        content += """</table>"""
        self.writeReport(content)

    def doAllTests(self):
        # Initialize report
        self.initializeReport()

        # Initial offset
        self.getAlertsFile(self._idstype)
        self.offset = self.getOffset(self.tmpreport)

        # Do all tests
        # As the socket is not persistent, client side attacks have to be done before all tests
        if self.config.get('TESTS', 'clientSideAttacks') == '1':
            self.writeReport("""<h2 id="client-side-attacks">Client Side Attacks</h2>""")
            print "\nCLIENT SIDE ATTACKS\n------------"
            self.doClientSideAttacksTest( clientSideAttacks.ClientSideAttacks(self._target).getPayloads() )

        if self.config.get('TESTS', 'testRules') == '1':
            self.writeReport("""<h2 id="test-rules">Test Rules</h2>""")
            print "\nTEST RULES\n------------"
            self.doTest( testRules.TestRules(self._target).getPayloads() )

        if self.config.get('TESTS', 'badTraffic') == '1':
            self.writeReport("""<h2 id="bad-traffic">Bad Traffic</h2>""")
            print "\nBAD TRAFFIC\n------------"
            self.doTest( badTraffic.BadTraffic(self._target).getPayloads() )

        if self.config.get('TESTS', 'fragmentedPackets') == '1':
            self.writeReport("""<h2 id="fragmented-packets">Fragmented Packets</h2>""")
            print "\nFRAGMENTED PACKETS\n------------"
            self.doTest( fragmentedPackets.FragmentedPackets(self._target).getPayloads() )

        if self.config.get('TESTS', 'multipleFailedLogins') == '1':
            self.writeReport("""<h2 id="multiple-failed-logins">Multiple Failed Logins</h2>""")
            print "\nMULTIPLE FAILED LOGINS\n------------"
            self.doMultipleFailedLoginsTest( multipleFailedLogins.MultipleFailedLogins(self._target).getPayloads() )

        if self.config.get('TESTS', 'evasionTechniques') == '1':
            self.writeReport("""<h2 id="evasion-techniques">Evasion Techniques</h2>""")
            print "\nEVASION TECHNIQUES\n------------"
            self.doTest( evasionTechniques.EvasionTechniques(self._target).getPayloads() )

        if self.config.get('TESTS', 'shellCodes') == '1':
            self.writeReport("""<h2 id="shellcodes">ShellCodes</h2>""")
            print "\nSHELLCODES\n------------"
            self.doTest( shellCodes.ShellCodes(self._target).getPayloads() )

        if self.config.get('TESTS', 'denialOfService') == '1':
            self.writeReport("""<h2 id="denialOfService">Denial of Service</h2>""")
            print "\nDENIAL OF SERVICE\n------------"
            self.doTest( denialOfService.DenialOfService(self._target).getPayloads() )

        # Finalize report
        self.finalizeReport()

        # Done!
        print "\n\n-----------------------"
        print "DONE. Check the report."
        print "-----------------------\n"

    def getAlertsFile(self, idstype):
        """Get the alerts file (FTP) from a remote Snort or Suricata server
        and save it to /tmp/pytbull.tmp"""
        # FTP Connection
        ftp = FTP(self._target)
        ftp.login(config.get('CREDENTIALS','ftpuser'),config.get('CREDENTIALS','ftppasswd'))
        # Get file
        f = open(self.tmpreport, "w")
        if idstype == "snort":
            alertsFile = self.config.get('PATHS', 'snortalertsfile')
        else:
            alertsFile = self.config.get('PATHS', 'suricataalertsfile')
        ftp.retrbinary("RETR %s" % alertsFile, f.write)
        #Close file and FTP connection
        f.close()
        ftp.quit()

    def getOffset(self, report):
        """Get initial offset (Number of lines in alert file)"""
        f = open(report, "r")
        offset = len(f.readlines())
        f.close()
        return offset

    def getAlertsFromOffset(self, report, offset):
        f = open(report, "r")
        c = f.readlines()
        return ''.join(c[offset:])

    def initializeReport(self):
        """Open a report (HTML file) and initialize it with HTML headers"""
        self.finalReport = open(self.config.get('PATHS', 'report'), 'w')
        self.writeReport( "<html><head><title>Detection Report</title></head><body>" )
        self.writeReport("""<table><tr><td style="width:500px;">
            <pre style="font: 10px/5px monospace;">
                                           @@@@@@
                        @@@@@@@@          @@@@@@@@@@@
                    @@@@@    @@@@          @@@@    @@@@
                  @@@@@@   @@  @            @@@@@   @@@@@@
                @@@@@@@   @@  @             @@@@@@@@   @@@@@
               @@@   @   @@@@@@@             @@@@@@@@@   @@@@@
              @@@   @   @@@@@@@@              @@@@@@@@@@  @@@@@
             @@@  @@   @  @@@@@             @@ @@@@@@@@@@ @@@@@
            @@   @@  @@  @@@@@@@@@       @@@@@@ @@@@@@@@@@@@ @@@
            @@   @  @@  @@@@@@@@@@@@@@@@@@@@@  @@@    @@@@@@ @@@@
            @@   @  @   @@@@@@@   @@  @@@@@@@          @@@@@@@@@@@
           @@@   @@@@   @    @@    @    @@@@@@           @@@@ @@@@@
           @@@    @@  @@      @  @@@    @@@@@              @@  @@@@
          @@   @  @@@@         @@@      @  @                   @@ @@
          @@@ @@@@@@@            @     @@                          @@
          @  @@                  @    @@@                     @@@@  @
          @  @                   @@@  @@                    @@@@@@@@@
          @      @                  @@@      @@@            @@@@@@@@@@
          @      @            @      @@  @      @@         @@@@@@@@@@
         @   @   @           @@             @    @      @@ @@@@@@@@@
         @  @   @           @@        @                  @@@@@@@@@@@
         @@@  @@           @@                              @@@@@@@@@
              @            @              @  @            @@@@@@@@@@
             @                             @ @           @@@@@@@@@@@
             @                 @@@   @     @ @       @@  @@@@@@@@@@@
                              @@@@@  @     @ @ @@   @@@@@@@ @@@@@@@@@
                            @@@@@              @@    @@@@@@   @@@@@@@
                            @@@@@     @       @ @    @@@@@@@@@ @@@@@@
                           @@@@@@@@   @         @ @@@@@@@@@@@@@@@@@@
                          @@@@@@@@@   @          @@@@   @     @@@@@@
            @         @@@@@@@@@@@@@@ @@        @ @@@   @  @@@@@@@@@@
            @    @   @@@@  @@@@@@@@@@@@               @        @@@@@
            @     @@@@@@   @@ @@@@@@@@@               @ @@  @   @@@@
            @      @@@@@ @@@@  @@@@@@@@@                 @@@    @@@@
            @   @@@@@@@@ @@@@@@@@@@@@@@@@                  @   @@@@@
            @  @@@@@@@@@@  @@@@@@@@@  @@@                      @@@ @
           @ @@@    @@@@@       @@@   @@@       @       @@@   @@@   @
           @           @@@      @     @@         @      @@@@@@@@    @
           @            @@@@@@@@     @@           @@    @@@@@@@     @@
           @       @@              @@@                  @@@@         @
           @        @             @@                   @@@@          @
           @         @           @                     @@@           @
           @          @         @                      @@@           @@
           @          @                                @@@           @@
          @           @@                                @@@          @@
          @            @@    @                           @@@         @
          @              @   @                            @@         @
          @               @ @                              @@        @
                           @                               @@@       @
           @                                                @@       @
          @                                 @@@@@@@          @@     @@
          @                              @@@@@@    @@         @     @
          @                             @@    @      @        @     @
          @                            @@     @     @@@       @    @
          @                             @  @  @@  @@@@@           @@
          @                             @@    @@  @  @@        @ @@
          @                              @   @@  @@ @@@        @ @@
         @                                @@@@@   @@@@         @  @
         @                                 @@@@    @           @  @
        @                                   @@@@@@@@           @  @@
        @           @                         @@               @   @
       @            @                                          @   @@
                    @@                         @               @   @@@
      @              @                         @               @     @
      @              @                         @              @       @
     @               @                         @              @       @@
     @               @                        @@@             @        @
                     @                   @@@@@@@@@@          @         @@
    @                @@                  @   @@@@@@         @           @
                      @@                @@   @             @@
  @@                   @@               @@   @ @@@@@      @@             @
  @                     @@       @@@@@@  @@@@@@@@@@  @@   @              @
 @                        @@@@@@@@@@        @   @   @@@@@@                @
 @                                  @@@  @@@   @@ @@     @                @
@                                    @        @   @      @                 @
@                                            @   @       @                 @
@                                           @   @        @                  @
                                                         @
                                                        @
                                             @@        @
                                            @         @
                                           @         @
                                          @@        @@
            </pre></td>""")
        self.writeReport( """<td><h1>Pytbull Detection Report</h1>""" )
        self.writeReport( "<p>Remote Host: %s</p>" % self._target )
        self.writeReport("""
            <ul>
            <li><a href="#client-side-attacks">Client Side Attacks</a></li>
            <li><a href="#test-rules">Test Rules</a></li>
            <li><a href="#bad-traffic">Bad Traffic</a></li>
            <li><a href="#fragmented-packets">Fragmented Packets</a></li>
            <li><a href="#multiple-failed-logins">Multiple Failed Logins</a></li>
            <li><a href="#evasion-techniques">Evasion Techniques</a></li>
            <li><a href="#shellcodes">ShellCodes</a></li>
            <li><a href="#denialOfService">Denial of Service</a></li>
            </ul>
            <div style="font-size:9pt;margin-top:150px;">(C) This report has been generated by <a href="http://code.google.com/p/pytbull/">pytbull</a>, Sebastien Damaye, aldeid.com</div>
            </td></tr></table>
            <hr />
        """)

    def writeReport(self, content):
        """ Add content to HTML report """
        self.finalReport.write( content )

    def finalizeReport(self):
        """ Write end of report and close file """
        self.writeReport("""<hr /><div style="font-size:9pt;">(C) This report has been generated by <a href="http://code.google.com/p/pytbull/">pytbull</a>, Sebastien Damaye, aldeid.com</div>""")
        self.writeReport( "</body></html>" )
        self.finalReport.close()

if __name__ == '__main__':

    banner = """
                                 _   _           _ _
                     _ __  _   _| |_| |__  _   _| | |
                    | '_ \| | | | __| '_ \| | | | | |
                    | |_) | |_| | |_| |_) | |_| | | |
                    | .__/ \__, |\__|_.__/ \__,_|_|_|
                    |_|    |___/
                       Sebastien Damaye, aldeid.com"""
    usg = "sudo ./%prog -t <target> -i <snort|suricata> [--version]"
    config = ConfigParser.RawConfigParser()
    config.read('config.cfg')
    ver = banner + "\n                                Version " + config.get('VERSION', 'version') + '\n'

    parser = OptionParser(usage=usg, version=ver)
    parser.add_option("-t", "--target", dest="target",
        help="host to connect to (e.g. 192.168.100.48)")
    parser.add_option("-i", "--ids", dest="type",
        help="IDS type (snort|suricata)")

    (options, args) = parser.parse_args(sys.argv)

    if not options.target:
        parser.error("Host missing. Use -t <target>.")
    if not options.type:
        parser.error("IDS type missing. Use -i <snort|suricata>.")
    if options.type!= "snort" and options.type!="suricata":
        parser.error("Invalid IDS type. Use -i <snort|suricata>")
    # Instantiate Pytbull class
    oPytbull = Pytbull(banner, options.target, options.type)
    # Do all tests
    oPytbull.doAllTests()
    # Destruct object
    del oPytbull

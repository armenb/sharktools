#!/usr/bin/env python26
#
# Unit tests for lists. This example shows how subclassing can be used in
# order to re-use test code wth different test objects. Comments in this
# module explain some points about typical usage. See the documentation for
# more information, including the documentation strings in the unittest module.
# 
# $Id: listtests.py,v 1.3 2001/03/12 11:52:56 purcell Exp $

import sys

#sys.path.append('./yunit-1.4.1')

import unittest
#from UserList import UserList

sys.path.append('../src')
import pyshark
from pyshark import PySharkError

class PySharkArgumentChecks(unittest.TestCase):
    def setUp(self):
        self.filename = "capture1.pcap"

    def testPySharkFilenameDoesntExist1(self):
        """This should fail because the file doesn't exist"""
        try:
            pkts = pyshark.iter("thisfiledoesntexist.pcap",
                                ['frame.number', 'eth.type'],
                                '')
            self.fail("Bad Filename did not raise PySharkError")
        except PySharkError:
            pass

    def testPySharkFilenameDoesntExist3(self):
        """This should fail because the filename is an empty string"""
        try:
            pkts = pyshark.iter("",
                                ['frame.number', 'eth.type'],
                                '')
            self.fail("Bad Filename did not raise PySharkError")
        except PySharkError:
            pass

    def testPySharkBadFilename1(self):
        """This should fail because the first argument is a number"""
        try:
            pkts = pyshark.iter(34,
                                ['frame.number', 'eth.type'],
                                '')
            self.fail("Bad Filename did not raise TypeError")
        except TypeError:
            pass
            
    def testPySharkBadFilename2(self):
        """This should fail because the filename is None"""
        try:
            pkts = pyshark.iter(None,
                                ['frame.number', 'eth.type'],
                                '')
            self.fail("Bad Filename did not raise TypeError")
        except TypeError:
            pass

    def testPySharkBadFieldNames1(self):
        """This should fail because the second argument is not a list"""
        try:
            pkts = pyshark.iter(self.filename,
                                3,
                                '')
            self.fail("Bad Field Names did not raise TypeError")
        except TypeError:
            pass

    def testPySharkBadFieldNames2(self):
        """This shoudl fail because one of the list items in the
        second argument is not a string"""
        try:
            pkts = pyshark.iter(self.filename,
                                ['frame.number', 4, 'eth.type'],
                                '')
            self.fail("Bad Field Names did not raise TypeError")
        except TypeError:
            pass

    def testPySharkBadDisplayFilter(self):
        try:
            pkts = pyshark.iter(self.filename,
                                ['frame.number', 'eth.type'],
                                55)
            self.fail("Bad Display Filter did not raise TypeError")
        except TypeError:
            pass

    def testPySharkBadDecodeAs1(self):
        try:
            pkts = pyshark.iter(self.filename,
                                ['frame.number', 'eth.type'],
                                '',
                                'rtcp.port==80,ftp')
            self.fail("Bad Decode As string did not raise TypeError")
        except PySharkError:
            pass

    def testPySharkBadDecodeAs2(self):
        try:
            pkts = pyshark.iter(self.filename,
                                ['frame.number', 'eth.type'],
                                '',
                                '')
            self.fail("Bad Decode As string did not raise TypeError")
        except PySharkError:
            pass

    def testPySharkBadDecodeAs3(self):
        try:
            pkts = pyshark.iter(self.filename,
                                ['frame.number', 'eth.type'],
                                '',
                                None)
            self.fail("Bad Decode As string did not raise TypeError")
        except PySharkError:
            pass

    def testPySharkBadDecodeAs3(self):
        pkts = pyshark.iter(self.filename,
                            ['frame.number', 'eth.type'],
                            '',
                            'tcp.port==80,ftp')
        del pkts
        
    def tearDown(self):
        pass

class PySharkParsingChecks(unittest.TestCase):
    def setUp(self):
        self.filename = "capture1.pcap"

    def testPySharkIterator(self):
        """capture1.pcap has 100 packets in it; 74 are udp packets
        """
        pkts = pyshark.iter(self.filename,
                            ['frame.number', 'eth.trailer', 'udp.srcport'],
                            '')
        count = 0
        udpcount = 0 
        for pkt in pkts:
            count += 1
            if("udp.srcport" in pkt and pkt["udp.srcport"] not in [None, []]):
                #print pkt
                udpcount += 1
        self.failUnless(count == 100)
        self.failUnless(udpcount == 74)

    def testPySharkIterator2(self):
        pkts = pyshark.iter(self.filename,
                            ['frame.number', 'eth.type'],
                            '')
        count = 0
        for pkt in pkts:
            count += 1
        self.failUnless(count == 100)
        
    def testPySharkDisplayFilter(self):
        """There are 74 UDP packets in the capture"""
        pkts = pyshark.iter(self.filename,
                            ['frame.number', 'eth.type'],
                            'udp')
        count = 0
        for pkt in pkts:
            count += 1
        #print pkts.next()
        #print "count =", count
        self.failUnless(count == 74)

    def testPySharkIteratorWildcard1(self):
        pkts = pyshark.iter(self.filename,
                            ['*'],
                            '')
        count = 0
        num_keys = len(pkts.next().keys())
        self.failUnless(num_keys == 55)

    def testPySharkIteratorWildcard2(self):
        pkts = pyshark.iter(self.filename,
                            ['*', 'eth.type'],
                            '')
        count = 0
        num_keys = len(pkts.next().keys())
        self.failUnless(num_keys == 55)

    def testPySharkIteratorWildcard3(self):
        pkts = pyshark.iter(self.filename,
                            ['ip.*', 'eth.type'],
                            '')
        count = 0
        num_keys = len(pkts.next().keys())
        self.failUnless(num_keys == 25)

    def tearDown(self):
        pass

def suite():
    suite = unittest.makeSuite()
    #suite.addtest(PySharkTestCase("testPySharkBadFilename"))
    #suite.addtest(PySharkTestCase("testPySharkOpen"))
    return suite


if __name__ == '__main__':
    # When this module is executed from the command-line, run all its tests
    unittest.main()

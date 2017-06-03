import socket
import re
import sys
import tld
import whoispy_parser

OK = '\033[92m'
FAIL = '\033[91m'
ENDC = '\033[0m'

class Query:
    def __init__(self, domainName):
        self._domainName = domainName
        self._sockMsg = ""
        self._tldName = ""
        self._whoisAddr = ""
        self._detailTuple = {}
        
        regex = re.compile('.+\..+')
        match = regex.search(self._domainName)
        if not match:
            # Invalid domain
            self._display_fail("Invalil domain")
            return

        # Divice TLD
        regex = re.compile('\..+')
        match = regex.search(self._domainName)
        if match:
            self._tldName = match.group()
        else:
            self._display_fail("Not found TLD")
            return
        
        # Get TLD List
        tldDict = tld.get_tldDict()
        if not (self._tldName in tldDict):
            self._display_fail("Not Found TLD whois server")
            return

        self._whoisAddr = tldDict.get( self._tldName ) 
        self._sockMsg = self._get_sockMsg( self._whoisAddr , self._domainName, 43)
    
    # check whether possible to acquire domain
    def get_vacant_bool(self):
        return whoispy_parser.parse(self._sockMsg, self._whoisAddr)
        
    # Get Raw whois data
    def get_rawData(self):
        return self._sockMsg
    
    # Get raw data method
    def _get_sockMsg(self, server, msg, port=43):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( ( server, port) )
        sendStr = msg + "\r\n"
        sock.send(bytes(sendStr, 'utf-8'))
        buf = ""
        while True:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            buf += str(data)
        return buf
    
    # Display method
    def _display_fail(self, msg):
        sys.stdout.write( FAIL )
        sys.stdout.write("%s\n" % msg)
        sys.stdout.write( ENDC )
        
    def _display_safe(self, msg):
        sys.stdout.write( OK )
        sys.stdout.write("%s\n" % msg)
        sys.stdout.write( ENDC )

import socket
import re
import sys
import tld
import can_get

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
        self._errorCheck = 1
        
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
        self._errorCheck = 0
    
    # check whether possible to acquire domain
    def get_vacant_bool(self):
        return can_get.check(self._sockMsg, self._whoisAddr)
        
        '''
        if self._errorCheck == 1:
            self._display_fail("Failed to get WHOIS DATA")
            return -1
            
            regex = re.compile("No match for \"%s\"\." % self._domain.upper())
            match = regex.search(self._sockMsg)
            if match:
                self._display_safe("Yes can Get")
                return 1
                
            self._display_fail("No can Get")
            return 0
        '''
        
    # Get Raw whois data
    def get_rawData(self):
        return self._sockMsg

    '''
    def get_detail(self):
        if self._errorCheck == 1:
            return self._detailTuple
            
        for match in re.finditer(".+:.*", self._sockMsg, re.MULTILINE):
            row_str = match.group()
            option_index = row_str.split(':')[0]
            option_value = row_str.split(':')[1]
            self._detailTuple.update( {option_index : option_value} )
        
        return self._detailTuple
    '''
    
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

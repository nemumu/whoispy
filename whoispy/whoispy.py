import socket
import re
import sys
import whoisSrvDict
import parser_branch

OK = '\033[92m'
FAIL = '\033[91m'
ENDC = '\033[0m'

class Query:
    def __init__(self, domainName):
        self._domainName = domainName
        self._rawMsg = ""
        self._tldName = ""
        self._whoisSrvAddr = ""

        regex = re.compile('.+\..+')
        match = regex.search(self._domainName)
        if not match:
            # Invalid domain
            self._display_fail("Invalil domain format")
            return None

        # Divice TLD
        regex = re.compile('\..+')
        match = regex.search(self._domainName)
        if match:
            self._tldName = match.group()
        else:
            self._display_fail("Can not parse TLD")
            return None
        
        # Get TLD List
        if not (self._tldName in whoisSrvDict.get_whoisSrvDict()):
            self._display_fail("Not Found TLD whois server")
            return None

        self._whoisSrvAddr = whoisSrvDict.get_whoisSrvDict().get(self._tldName)
        self._rawMsg = self._get_rawMsg(self._whoisSrvAddr , self._domainName, 43)
        return parser_branch.parse(self._rawMsg, self._whoisSrvAddr)
        
    # Get Raw whois data
    def get_rawData(self):
        return self._rawMsg
    
    # Get raw data method
    def _get_rawMsg(self, server, msg, port=43):
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

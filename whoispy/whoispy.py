import re
import sys
import whoisSrvDict
import whoispy_sock
import parser_branch

OK = '\033[92m'
FAIL = '\033[91m'
ENDC = '\033[0m'

def query(domainName):
    rawMsg = ""
    tldName = ""
    whoisSrvAddr = ""

    regex = re.compile('.+\..+')
    match = regex.search(domainName)
    if not match:
        # Invalid domain
        _display_fail("Invalid domain format")
        return None

    # Divice TLD
    regex = re.compile('\..+')
    match = regex.search(domainName)
    if match:
        tldName = match.group()
    else:
        _display_fail("Can not parse TLD")
        return None
    
    # Get TLD List
    if not (tldName in whoisSrvDict.get_whoisSrvDict()):
        _display_fail("Not Found TLD whois server")
        return None

    whoisSrvAddr = whoisSrvDict.get_whoisSrvDict().get(tldName)
    rawMsg = whoispy_sock.get_rawMsg(whoisSrvAddr , domainName, 43)
    return parser_branch.get_parser(rawMsg, whoisSrvAddr)

# Display method
def _display_fail(msg):
    sys.stdout.write( FAIL )
    sys.stdout.write("%s\n" % msg)
    sys.stdout.write( ENDC )
    
def _display_safe(msg):
    sys.stdout.write( OK )
    sys.stdout.write("%s\n" % msg)
    sys.stdout.write( ENDC )

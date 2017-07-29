import re
import whoispy_sock
import parser_general

def get_parser(rawMsg):
    # Parse domain name
    queryDomain = getLine_inHeadStr('Domain Name', rawMsg)
    if queryDomain is None:
        print('Can not parse [Domain Name]')
        return None

    # Parse WHOIS server
    whoisSrvDomain = getLine_inHeadStr('Registrar WHOIS Server', rawMsg)
    if whoisSrvDomain is None:
        print('Can not parse [Whois Server]')
        return None

    registrarWhoisAnswer = whoispy_sock.get_rawMsg(whoisSrvDomain, queryDomain, 43)
    
    return parser_general.get_parser(registrarWhoisAnswer)
   
def getLine_inHeadStr(headStr, rawMsg):
    regex = re.compile(headStr + ':.+?\\\\n')
    match = regex.search(rawMsg)

    if match:
        matchStr = match.group(0)
        matchStr = matchStr.replace(headStr + ': ', '')
        matchStr = matchStr.replace('\\n', '')
        matchStr = matchStr.replace('\\r', '')

        return matchStr
    return None

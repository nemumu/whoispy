import re
import whoispy_sock
import parser_whoisEnomCom
import parser_whoisUniregistrarCom

def get_parser(rawMsg):
    # Parse domain name
    queryDomain = getLine_inHeadStr('Domain Name', rawMsg)
    if queryDomain is None:
        print('Can not parse [Domain Name]')
        return None

    # Parse WHOIS server
    whoisSrvDomain = getLine_inHeadStr('Whois Server', rawMsg)
    if whoisSrvDomain is None:
        print('Can not parse [Whois Server]')
        return None

    registrarWhoisAnswer = whoispy_sock.get_rawMsg(whoisSrvDomain, queryDomain, 43)
    
    # Branch flow for each WHOIS server
    if whoisSrvDomain == "whois.enom.com":
        return parser_whoisEnomCom.get_parser(registrarWhoisAnswer)
    elif whoisSrvDomain == "whois.uniregistrar.com":
        return parser_whoisUniregistrarCom.get_parser(registrarWhoisAnswer)
    return None

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
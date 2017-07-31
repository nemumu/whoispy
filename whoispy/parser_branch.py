import parser_general
import parser_whoisVerisignGrsCom

def get_parser(rawMsg, whoisSrvAddr):
    if whoisSrvAddr == "whois.verisign-grs.com":
        return parser_whoisVerisignGrsCom.get_parser(rawMsg)
    elif whoisSrvAddr == "whois.afilias.info":
        return parser_general.get_parser(rawMsg)
    else:
        return None

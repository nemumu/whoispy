import parser_whoisVerisignGrsCom

def get_parser(rawMsg, whoisSrvAddr):
    if whoisSrvAddr == "whois.verisign-grs.com":
        return parser_whoisVerisignGrsCom.get_parser(rawMsg)
    else:
        return None

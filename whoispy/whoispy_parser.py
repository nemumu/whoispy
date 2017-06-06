import re

def parse(raw_data, tld_addr):
    if tld_addr == "whois.aero":
        return aero_parser(raw_data)
    elif tld_addr == "whois.iana.org":
        return arpa_parser(raw_data)
    elif tld_addr == "whois.nic.asia":
        return asia_parser(raw_data)
    elif tld_addr == "whois.biz":
        return biz_parser(raw_data)
    elif tld_addr == "whois.cat":
        return cat_parser(raw_data)
    elif tld_addr == "whois.verisign-grs.com":
        return com_parser(raw_data)
    else:
        return -1

def aero_parser(raw_data):
    return regex_support(raw_data, "Access ")

def arpa_parser(raw_data):
    return regex_support(raw_data, "% This query returned 1 objects.")

def asia_parser(raw_data):
    return regex_support(raw_data, "DotAsia ")

def biz_parser(raw_data):
    return regex_support(raw_data, "Domain ")

def cat_parser(raw_data):
    return regex_support(raw_data, "Domain ID:")

def com_parser(raw_data):
    return ~regex_support(raw_data, "No match for") + 2

def regex_support(raw_data, regex_word):
    regex = re.compile(regex_word)
    match = regex.search(raw_data)

    if match:
        return 0
    return 1

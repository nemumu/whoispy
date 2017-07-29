from parser_base import *

'''
This parser is supporting .com and .net

# Warning
whois.godaddy.com is limited access count by IP addr
'''

class get_parser(parser_base):
    def __init__(self, rawMsg):
        # Delete ('|")b('|") str (Parse interrupter ?)
        rawMsg = re.sub(r"(\'|\")b(\'|\")", '', rawMsg)

        self.rawMsg = rawMsg
    def domainName(self):
        return self.getLine_inHeadStr(['Domain Name'])
    def registryDomainID(self):
        return self.getLine_inHeadStr(['Registry Domain ID'])
    def registrarWHOISServer(self):
        return self.getLine_inHeadStr(['Registrar WHOIS Server'])
    def registrarURL(self):
        return self.getLine_inHeadStr(['Registrar URL'])
    def updatedDate(self):
        updatedDateStr = self.getLine_inHeadStr(['Updated Date', 'Update Date'])
        if updatedDateStr is None:
            return None
        return self.getDateFromDateStr(updatedDateStr)
    def creationDate(self):
        creationDateStr = self.getLine_inHeadStr(['Creation Date'])
        if creationDateStr is None:
            return None
        return self.getDateFromDateStr(creationDateStr)
    def registrarRegistrationExpirationDate(self):
        expireDateStr =  self.getLine_inHeadStr(['Registrar Registration Expiration Date'])
        if expireDateStr is None:
            return None
        return self.getDateFromDateStr(expireDateStr)
    def registrar(self):
        return self.getLine_inHeadStr(['Registrar'])
    def registrarIANAID(self):
        return self.getLine_inHeadStr(['Registrar IANA ID'])
    def domainStatus(self):
        return self.getLine_inHeadStr(['Domain Status'])
    def registryRegistrantID(self):
        return self.getLine_inHeadStr(['Registry Registrant ID'])
    def registrantName(self):
        return self.getLine_inHeadStr(['Registrant Name'])
    def registrantOrganization(self):
        return self.getLine_inHeadStr(['Registrant Organization'])
    def registrantStreet(self):
        return self.getLine_inHeadStr(['Registrant Street'])
    def registrantCity(self):
        return self.getLine_inHeadStr(['Registrant City'])
    def registrantStateProvince(self):
        return self.getLine_inHeadStr(['Registrant State/Province'])
    def registrantPostalCode(self):
        return self.getLine_inHeadStr(['Registrant Postal Code'])
    def registrantCountry(self):
        return self.getLine_inHeadStr(['Registrant Country'])
    def registrantPhone(self):
        return self.getLine_inHeadStr(['Registrant Phone'])
    def registrantPhoneExt(self):
        return self.getLine_inHeadStr(['Registrant Phone Ext'])
    def registrantFax(self):
        return self.getLine_inHeadStr(['Registrant Fax'])
    def registrantFaxExt(self):
        return self.getLine_inHeadStr(['Registrant Fax Ext'])
    def registrantEmail(self):
        return self.getLine_inHeadStr(['Registrant Email'])
    def registryAdminID(self):
        return self.getLine_inHeadStr(['Registry Admin ID'])
    def adminName(self):
        return self.getLine_inHeadStr(['Admin Name'])
    def adminOrganization(self):
        return self.getLine_inHeadStr(['Admin Organization'])
    def adminStreet(self):
        return self.getLine_inHeadStr(['Admin Street'])
    def adminCity(self):
        return self.getLine_inHeadStr(['Admin City'])
    def adminStateProvince(self):
        return self.getLine_inHeadStr(['Admin State/Province'])
    def adminPostalCode(self):
        return self.getLine_inHeadStr(['Admin Postal Code'])
    def adminCountry(self):
        return self.getLine_inHeadStr(['Admin Country'])
    def adminPhone(self):
        return self.getLine_inHeadStr(['Admin Phone'])
    def adminPhoneExt(self):
        return self.getLine_inHeadStr(['Admin Phone Ext'])
    def adminFax(self):
        return self.getLine_inHeadStr(['Admin Fax'])
    def adminFaxExt(self):
        return self.getLine_inHeadStr(['Admin Fax Ext'])
    def adminEmail(self):
        return self.getLine_inHeadStr(['Admin Email'])
    def registryTechID(self):
        return self.getLine_inHeadStr(['Registry Tech ID'])
    def techName(self):
        return self.getLine_inHeadStr(['Tech Name'])
    def techOrganization(self):
        return self.getLine_inHeadStr(['Tech Organization'])
    def techStreet(self):
        return self.getLine_inHeadStr(['Tech Street'])
    def techCity(self):
        return self.getLine_inHeadStr(['Tech City'])
    def techStateProvince(self):
        return self.getLine_inHeadStr(['Tech State/Province'])
    def techPostalCode(self):
        return self.getLine_inHeadStr(['Tech Postal Code'])
    def techCountry(self):
        return self.getLine_inHeadStr(['Tech Country'])
    def techPhone(self):
        return self.getLine_inHeadStr(['Tech Phone'])
    def techPhoneExt(self):
        return self.getLine_inHeadStr(['Tech Phone Ext'])
    def techFax(self):
        return self.getLine_inHeadStr(['Tech Fax'])
    def techFaxExt(self):
        return self.getLine_inHeadStr(['Tech Fax Ext'])
    def techEmail(self):
        return self.getLine_inHeadStr(['Tech Email'])
    def nameServer(self):
        return self.getLine_inHeadStr(['Name Server'])
    def DNSSEC(self):
        return self.getLine_inHeadStr(['DNSSEC'])
    def registrarAbuseContactEmail(self):
        return self.getLine_inHeadStr(['Registrar Abuse Contact Email'])
    def registrarAbuseContactPhone(self):
        return self.getLine_inHeadStr(['Registrar Abuse Contact Phone'])
    def urlOfTheICANNWHOISDataProblemReportingSystem(self):
        return self.getLine_inHeadStr(['URL of the ICANN WHOIS Data Problem Reporting System'])

    def getDateFromDateStr(self, dateStr):
        regex = re.compile('\d+-\d+-\d+-?T\d+:\d+:\d+')
        match = regex.search(dateStr)
        if match is not None:
            matchDateStr = match.group(0)
            matchDateStr = matchDateStr.replace('-T', 'T')
            retDate = datetime.strptime(matchDateStr, '%Y-%m-%dT%H:%M:%S')
            return retDate
        return None
        

    def getLine_inHeadStr(self, headStrs):
        for headStr in headStrs:
            regex = re.compile(headStr + ':.*?\\\\n')
            match = regex.search(self.rawMsg)

            if match is not None:
                matchStr = match.group(0)
                matchStr = matchStr.replace(headStr + ':', '')
                matchStr = re.sub(r'^ ', '', matchStr)
                matchStr = matchStr.replace('\\n', '')
                matchStr = matchStr.replace('\\r', '')

                return matchStr
        return None

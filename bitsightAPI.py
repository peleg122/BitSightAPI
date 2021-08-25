import datetime
import json
import os
import time
import requests
import jsonpickle

# Global Variables:
# Used for Url Requests :
Time_Period = 5 * 60  # 5 min in seconds
Requests = 2000  # number of requests

# Today's Date subtracting 3 Months (31days in a month):
last_3month = datetime.date.today() - datetime.timedelta(days=93)  # looks like: YYYY-MM-DD
date = datetime.datetime.today().strftime('%Y-%m-%d')  # Current date : YYYY-MM-DD

# Api Key To work with...
#api_key = r"Please-Enter-API-Key-Here"
# Creates Directory for each Scanning day
#os.chdir(r"C:\...")
#if not os.path.exists(date):
#    os.makedirs(date)
#    print("Directory Created!")
#else:
#    print("Directory Already Exists!")

# Functions:
def api_key_check(apikey):
    url = 'https://api.bitsighttech.com/'
    response = requests.get(url, auth=(apikey, ""))
    if response.status_code == 401 and str(response.json()["detail"]) == "Invalid token":
        api_key = input("Invalid Api key Please Insert Valid Api key\n")
        api_key_check(api_key)
    else:
        print("Api Key is Valid.")


def urltojson(url, apikey):
    # Limit of Requests is : 5000 requests per 5 min ( if light traffic)
    #                                 or
    #                        100  requests per 5 min ( if heavy traffic)
    time.sleep(Time_Period / Requests)  # Rate Limit of 5 min / 80 requests = 3.75 sec to wait each request
    response = requests.get(url, auth=(apikey, ""))
    if response.status_code == 200:
        return response.json()
    else:  # most of the time will be triggered by response code : 403 (Too Many Requests sent)
        return urltojson(url, apikey)  # in case of response code other than 200 try again and wait some more


def get_companies():  # Gets all Companies as Json Objects and make Company Objects out of the json

    companies_list = []
    try:
        url = f"https://api.bitsighttech.com/ratings/v1/companies/"
        json_companies = urltojson(url, api_key)
        i = 1
        size = len(json_companies["companies"])
        for company in json_companies["companies"]:
            comp = Company(company["name"], company["guid"], company["rating"])
            print(f"({i} | {size}) - ", comp.Name, comp.Score)
            i = i + 1
            companies_list.append(comp)
    except requests.exceptions.RequestException as e:
        print(str(e.response))
    return companies_list


# Classes:

class Company:
    Name = None
    Guid = None
    Score = None
    Diligence = None
    Assets = None

    def __init__(self, name, guid, rating):
        self.Name = name
        self.Guid = guid
        self.Diligence = Diligence(self)
        self.Score = rating
        self.Assets = self.get_assets()

    # gets all the assets of a company ip/domain name and a list of the resolved ip address in an object form

    def get_assets(self):
        assets = []
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Guid}/assets?&limit=1000000"
            json_obj = urltojson(url, api_key)
            if str(json_obj["links"]["next"]) == "None" and int(json_obj["count"]) > 0:
                for line in json_obj["results"]:
                    name = line["asset"]
                    asset = Asset(name, line["ip_addresses"])
                    assets.append(asset)
            else:
                while str(json_obj["links"]["next"]) != "None":
                    for line in json_obj["results"]:
                        name = line["asset"]
                        asset = Asset(name, line["ip_addresses"])
                        assets.append(asset)
                    nexturl = str(json_obj["links"]["next"])
                    if nexturl != "None":
                        json_obj = urltojson(nexturl, api_key)
                if str(json_obj["links"]["next"]) == "None" and int(json_obj["count"]) > 0:
                    for line in json_obj["results"]:
                        name = line["asset"]
                        asset = Asset(name, line["ip_addresses"])
                        assets.append(asset)
            return assets
        except requests.exceptions.RequestException as e:
            print(e)
            return None


class Asset:  # object that represents the assets of a company ( ip/domain name and a list of resolved addresses)
    AssetName = None
    AssetAddress = []

    def __init__(self, asset_name, address):
        self.AssetName = asset_name
        self.AssetAddress = address


class Diligence:  # object to hold all Diligence lists by category of the company for easy access
    Company = None
    CompromisedSystems = []
    Spf = []
    Dkim = []
    SSLConfiguration = []
    SSLCertificates = []
    OpenPorts = []
    WebApplicationHeaders = []
    PatchingCadence = []
    InsecureSystems = []
    ServerSoftware = []
    DesktopSoftware = []
    DnsSec = []
    UserBehavior = []

    def __init__(self, company):  # TODO: Finish Implementation -> copy paste from spf
        self.Company = company
        self.CompromisedSystems = self.get_compromised_systems()
        self.Spf = self.get_spf_records()
        self.Dkim = self.get_dkim()
        self.SSLConfiguration = self.get_ssl_configuration()
        self.SSLCertificates = self.get_ssl_certificates()
        self.OpenPorts = self.get_open_ports()
        self.WebApplicationHeaders = self.get_web_application_headers()
        self.PatchingCadence = self.get_patching_cadence()
        self.InsecureSystems = self.get_insecure_systems()
        self.ServerSoftware = self.get_server_software()
        self.DesktopSoftware = self.get_desktop_software()
        self.DnsSec = self.get_dnssec()
        self.UserBehavior = self.get_user_behavior()

    def get_botnet_infection(self):
        botnet = []
        risk_vector = "botnet_infections"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    _type = line["risk_vector_label"]
                    asset_name = line["evidence_key"]
                    location = line["details"]["geo_ip_location"]
                    details = line["details"]["infection"]["family"]
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    days = str(line["duration"]).split()[0]
                    obj = CompromisedSystems(_type, asset_name, location, first_seen, last_seen, days, details)
                    botnet.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return botnet

    def get_potentially_exploited(self):
        potentially_exploited = []
        risk_vector = "potentially_exploited"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    _type = line["risk_vector_label"]
                    asset_name = line["evidence_key"]
                    location = line["details"]["geo_ip_location"]
                    details = line["details"]["infection"]["family"]
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    days = str(line["duration"]).split()[0]
                    obj = CompromisedSystems(_type, asset_name, location, first_seen, last_seen, days, details)
                    potentially_exploited.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return potentially_exploited

    def get_compromised_systems(self):
        compromisedsystems = []
        compromisedsystems.extend(self.get_botnet_infection())  # Adds all Botnet objects into compromised
        compromisedsystems.extend(self.get_potentially_exploited())
        return compromisedsystems

    def get_spf_records(self):
        spf = []
        risk_vector = "spf"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = Spf(first_seen, last_seen, asset_name, grade, details)
                    spf.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return spf

    def get_dkim(self):
        dkim = []
        risk_vector = "dkim"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = Dkim(first_seen, last_seen, asset_name, grade, details)
                    dkim.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return dkim

    def get_ssl_configuration(self):
        sslConfig = []
        risk_vector = "ssl_configurations"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = SSLConfiguration(first_seen, last_seen, asset_name, grade, details)
                    sslConfig.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return sslConfig

    def get_ssl_certificates(self):
        sslCert = []
        risk_vector = "ssl_certificates"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = SSLCertificates(first_seen, last_seen, asset_name, grade, details)
                    sslCert.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return sslCert

    def get_open_ports(self):
        open_port = []
        risk_vector = "open_ports"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    portnumber = line["details"]["dest_port"]
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = OpenPorts(portnumber, first_seen, last_seen, asset_name, grade, details)
                    open_port.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return open_port

    def get_web_application_headers(self):
        web = []
        risk_vector = "application_security"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = WebApplicationHeaders(first_seen, last_seen, asset_name, grade, details)
                    web.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return web

    def get_patching_cadence(self):
        patchingcadence = []
        risk_vector = "patching_cadence"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    if line["details"]["diligence_annotations"]["is_remediated"] == False:
                        asset_name = line["evidence_key"]
                        remediated = line["details"]["diligence_annotations"]["is_remediated"]
                        details = []
                        for message in line["details"]["remediations"]:
                            detail = message["message"]
                            details.append(detail)
                        first_seen = line["first_seen"]
                        last_seen = line["last_seen"]
                        obj = PatchingCadence(first_seen, last_seen, asset_name, remediated, details)
                        patchingcadence.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return patchingcadence

    def get_insecure_systems(self):
        insecureSys = []
        risk_vector = "insecure_systems"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = InsecureSystems(first_seen, last_seen, asset_name, grade, details)
                    insecureSys.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return insecureSys

    def get_server_software(self):
        serversoftware = []
        risk_vector = "server_software"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = str(line["evidence_key"])
                    asset_name = asset_name + "["
                    for port in line["details"]["port_list"]:
                        asset_name = asset_name + "" + str(port) + ", "
                    asset_name = asset_name[:-2] + "]"
                    grade = line["details"]["grade"]
                    _type = line["details"]["diligence_annotations"]["server"]
                    vesion = line["details"]["diligence_annotations"]["version"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = ServerSoftware(first_seen, last_seen, asset_name, _type, vesion, grade, details)
                    serversoftware.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return serversoftware

    def get_desktop_software(self):
        desktopsoftware = []
        risk_vector = "desktop_software"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = ""
                    for asset in line["assets"]:
                        asset_name = asset["asset"]
                    grade = line["details"]["grade"]
                    os = line["details"]["operating_system_family"]
                    browser = line["details"]["user_agent_family"] + " " + line["details"]["user_agent_version"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = DesktopSoftware(first_seen, last_seen, asset_name, os, browser, grade, details)
                    desktopsoftware.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return desktopsoftware

    def get_dnssec(self):
        dnssec = []
        risk_vector = "dnssec"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&grade=BAD" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    grade = line["details"]["grade"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    obj = DnsSec(first_seen, last_seen, asset_name, grade, details)
                    dnssec.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return dnssec

    def get_user_behavior(self):
        userbehavior = []
        risk_vector = "file_sharing"
        try:
            url = f"https://api.bitsighttech.com/ratings/v1/companies/{self.Company.Guid}/findings?" \
                  f"risk_vector={risk_vector}" \
                  f"&affects_rating=true" \
                  f"&last_seen_gt={last_3month}" \
                  f"&limit=1000000"  # limit 1 million records for minimum request number
            r = urltojson(url, api_key)
            if int(r["count"]) > 0:
                for line in r["results"]:
                    asset_name = line["evidence_key"]
                    category = line["details"]["category"]
                    details = []
                    for message in line["details"]["remediations"]:
                        detail = message["message"]
                        details.append(detail)
                    first_seen = line["first_seen"]
                    last_seen = line["last_seen"]
                    days = str(line["duration"]).split()[0]
                    obj = UserBehavior(category, asset_name, first_seen, last_seen, days, "no")
                    userbehavior.append(obj)
        except requests.exceptions.RequestException as e:
            print(e.response.text)
        return userbehavior


class CompromisedSystems(Diligence):
    Type = None
    IpAddressOrDomain = None
    Location = None
    Start = None
    End = None
    Days = None
    Details = None

    def __init__(self, _type, ip, location, start, end, days, details):
        self.Type = str(_type)
        self.IpAddressOrDomain = str(ip)
        self.Location = str(location)
        self.Start = str(start)
        self.End = str(end)
        self.Days = str(days)
        self.Details = str(details)


class Spf(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details




class Dkim(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details


class SSLConfiguration(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details


class SSLCertificates(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details


class OpenPorts(Diligence):
    PortNumber = None
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, portnum, first, last, ip, grade, details):
        self.PortNumber = portnum
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details


class WebApplicationHeaders(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details


class PatchingCadence(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Remediated = None
    Details = None

    def __init__(self, first, last, ip, remediated, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Remediated = remediated
        self.Details = details


class InsecureSystems(Diligence):  # only if not remediated
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details


class ServerSoftware(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Type = None
    Version = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, _type, version, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Type = _type
        self.Version = version
        self.Grade = grade
        self.Details = details


class DesktopSoftware(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Os = None
    Browser = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, os, browser, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Os = os
        self.Browser = browser
        self.Grade = grade
        self.Details = details


class DnsSec(Diligence):
    FirstSeen = None
    LastSeen = None
    Host = None
    Grade = None
    Details = None

    def __init__(self, first, last, ip, grade, details):
        self.FirstSeen = first
        self.LastSeen = last
        self.Host = ip
        self.Grade = grade
        self.Details = details


class UserBehavior(Diligence):
    FileSharingCategory = None
    Host = None
    Start = None
    End = None
    Days = None
    Whitelisted = None

    def __init__(self, filesharecategory, host, start, end, days, whitelisted):
        self.FileSharingCategory = filesharecategory
        self.Host = host
        self.Start = start
        self.End = end
        self.Days = days
        self.Whitelisted = whitelisted


#  main:


def main():
    api_key_check(api_key)
    comp = get_companies()
    for company in comp:
        name = date+"/"+str(company.Name).replace("\"", "")+".json"
        with open(name, 'w') as f:  # strip all special characters
            obj = jsonpickle.encode(company)
            f.write(obj)
            f.close()
    print("file Created!")
    # to get assets ip address if not found any in resolve will produce empty list
    # for asset in comp[0].Assets:
    #     print(asset.AssetName, ", ",asset.AssetAddress)


if __name__ == "__main__":
    main()

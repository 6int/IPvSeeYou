#!/usr/bin/env python3
import os
import sys
import json
import argparse
import ipaddress
import requests
import BSSIDApple_pb2
import simplekml
from urllib3.exceptions import InsecureRequestWarning

#suppress certificate warnings for hitting Apple's location services API
#endpoint
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def isMAC(s):
    '''
    @brief: Checks if string s is a valid MAC address
    @param: s -- string, colon-separated MAC address in aa:bb:cc:dd:ee:ff form
    @return: True if valid, False else
    '''
    if len(s.split(':')) != 6:
        return False
    for x in s.split(':'):
        if len(x) != 2:
            return False
        try:
            i = int(x,16)
            if i < 0 or i > 255:
                return False
        except ValueError:
            return False

    return True

def isEUI64(addr):
    '''
    @params: addr -- full 32-hex digit address
    @returns: True if an EUI64 address, False if not
    '''
    if not addr or "*" in addr:
        return False
    try:
        addr.split(':')
    except IndexError:
        return False

    hextets = addr.split(':')

    if hextets[-3].endswith('ff') and hextets[-2].startswith('fe'):
        return True
    else:
        return False

def checkArgs(args):
    '''
    @brief: Checks arguments for errors/format
    @param: args -- Argparse args object
    @return: None
    '''

    #Validate MAC/MAC file/EUI-64 IPv6/EUI-64 IPv6 file
    if args.mac and not isMAC(args.mac):
        print(f"[-] Error: {args.mac} is not a valid MAC address (e.g. " +\
        "00:11:22:33:44:55)")
        sys.exit(1)
    elif args.mac_file and not os.path.exists(args.mac_file):
        print(f"[-] Error: {args.mac_file} does not exist")
        sys.exit(2)
    elif args.eui and not isEUI64(args.eui):
        print(f"[-] Error: {args.eui} is not an EUI-64 IPv6 address")
        sys.exit(3)
    elif args.eui_file and not os.path.exists(args.eui_file):
        print(f"[-] Error: {args.eui_file} does not exist")
        sys.exit(4)

    if not args.offset_file:
        print(f"[-] Error: Offset file must be specified")
        sys.exit(5)

    if args.wigle and (not args.api_user or not args.api_pass):
        print(f"[-] Error: -w/--wigle requires -U/--api-user USERNAME and "+\
                "-P/--api-pass PASS where USERNAME and PASS are the user's "+\
                "WiGLE API authentication parameters")
        sys.exit(6)

def getOUI(mac):
    '''
    @brief: returns OUI from a MAC address
    @param: mac: MAC address in xx:xx:xx:xx:xx (colon-separated)
    format
    @return: OUI
    '''
    return ':'.join(mac.split(':')[:3])
        

def getOffsets(fname):
    '''
    @brief: reads file of OUI offsets, returns OUI-keyed dict of these offsets
    @param: fname: string filename parameter
    @returns: ouiDict: dictionary keyed by OUI, each OUI maps to the WAN-BSSID
    offset integer
    '''
    ouiDict = {}
    with open(fname) as f:
        for line in f:
            l = line.strip().split()
            oui = l[0]
            offset = int(l[1])
            ouiDict[oui] = offset
    return ouiDict

def macToInt(mac):
    '''
    @brief: converts a MAC into an integer
    @param: mac: a MAC address in colon-separated format
    @returns: macInt, that MAC address as an integer
    '''
    translation_table = dict.fromkeys(map(ord, ':.- '), None)

    macInt = int(mac.translate(translation_table), 16)

    return macInt

def intToMAC(n):
    '''
    @brief intToMac converts an integer into a MAC address
    @param: n: integer to convert into a MAC address
    @returns: macStr: the converted MAC address
    '''
    if n > (2**48 - 1):
        print(f"{n} is too large to fit into a 48-bit MAC address")
    macHex = "{:012x}".format(n)
    macStr = ":".join(macHex[i:i+2] for i in range(0, len(macHex), 2))
    return macStr


def getPredictedBSSID(mac, ouiDict):
    '''
    @brief: returns the predicted BSSID for an EUI-64-derived MAC given the MAC
    and a dictionary of OUI->(WAN-BSSID offset) mappings
    @param: mac: the EUI-64-derived MAC address
    @param: ouiDict: a dictionary keyed by OUI that maps to each OUI's WAN-BSSID
    offset value
    @returns: the predicted BSSID
    '''
    oui = getOUI(mac)

    if not oui in ouiDict:
        print(f"Error: {oui} has no WAN-BSSID inferences; can't "+\
                f"geolocate {mac}")
        return

    offset = ouiDict[oui]

    macInt = macToInt(mac)

    return intToMAC(macInt + offset)

def delocalize(mac):
    '''
    @param:  mac: MAC address string of the form (xy:xx:xx:xx:xx:xx) where the
    y position has the local bit on
    @returns: delocalized mac address string
    '''
    first_byte = mac.split(':')[0]
    first_nybble = first_byte[0]
    second_nybble = first_byte[1]

    #if this is global already, return
    if not (int(second_nybble,16) >> 1) & 1:
        return mac

    second_nybble = hex(int(second_nybble,16) ^ 0x2)[2:]
    if second_nybble ==2:
        sys.exit(1)
    first_byte = first_nybble + second_nybble

    return first_byte + ':' + ':'.join(mac.split(':')[1:])

def getMAC(addr):
    '''
    @params: addr -- full 32-hex digit EUI-64 address
    @returns: de-localized MAC address (unless explicit deloc=False in call)
    '''
    lower64 = addr.split(':')[4:]
    one_two = lower64[0][:2] + ':' + lower64[0][2:]
    three = lower64[1][:2]
    four = lower64[2][2:]
    five_six = lower64[3][:2] + ':' + lower64[3][2:]

    return delocalize(':'.join([one_two,three,four,five_six]))

def geolocateApple(bssid):
    '''
    @brief: Attempts to geolocate a BSSID using the Apple location services API
    @param: bssid: the BSSID to attempt to geolocate
    @returns: (lat,lon) tuple of floats

    @notes: much of this code borrowed from iSniff-GPS, who borrowed it from 
    Mostly taken from paper by François-Xavier Aguessy and Côme Demoustier
    http://fxaguessy.fr/rapport-pfe-interception-ssl-analyse-donnees-localisation-smartphones/
    '''

    data_bssid = f"\x12\x13\n\x11{bssid}\x18\x00\x20\01"
    headers = {'Content-Type':'application/x-www-form-urlencoded',
                'Accept':'*/*', 
                "Accept-Charset": "utf-8",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language":"en-us", 
                'User-Agent':'locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0'
                }  
    data = "\x00\x01\x00\x05en_US\x00\x13com.apple.locationd\x00\x0a"+\
           "8.1.12B411\x00\x00\x00\x01\x00\x00\x00" + \
           chr(len(data_bssid)) + data_bssid;

    r = requests.post('https://gs-loc.apple.com/clls/wloc',headers=headers,data=data,verify=False) # CN of cert on this hostname is sometimes *.ls.apple.com / ls.apple.com, so have to disable SSL verify

    bssidResponse = BSSIDApple_pb2.BSSIDResp()
    bssidResponse.ParseFromString(r.content[10:])

    for wifi in bssidResponse.wifi:
        #Skip any BSSIDs Apple returns that aren't the one we requested
        if wifi.bssid != bssid:
            continue
        lat = wifi.location.lat * pow(10,-8) 
        lon = wifi.location.lon * pow(10,-8)

        return lat, lon

    return -180.0, -180.0

def geolocateMylnikov(bssid):
    '''
    @brief: Attempts to geolocate BSSID using the api.mylnikov.org API.
    @param: bssid: a string BSSID to attempt to geolocate
    @returns: lat, lon, float tuple representing the BSSID's geolocation
    according to the API, or -180.0,-180.0 if not found
    '''
    lat, lon = -180.0, -180.0

    session = requests.Session()
    url = f"https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&"+\
          f"bssid={bssid}"
    try:
        r = session.get(url)
        resp = json.loads(r.text)

        if resp['result'] != 200:
            print(f"[-] Failure geolocating {bssid}")
        else:
            #we got a successful geolocation, so return it
            lat = resp["lat"]
            lon = resp["lon"]

    except Exception as e:
        print(f"[-] Exception {e} querying mylnikov")

    return lat, lon

def geolocateWiGLE(bssid, apiUser, apiPass):
    '''
    @brief: Attempts to geolocate BSSID using WiGLE's API. Requires a valid,
    active API key apiKey
    @param: bssid: a string BSSID to attempt to geolocate
    @param: apiKey: a valid WiGLE API key
    @returns: lat, lon, float tuple representing the BSSID's geolocation
    according to WiGLE, or -180.0,-180.0 if not found
    '''

    lat, lon = -180.0, -180.0

    session = requests.Session()
    session.auth = (apiUser, apiPass)

    url = f"https://api.wigle.net/api/v2/network/search?netid={bssid}"
    try:
        r = session.get(url)
        resp = json.loads(r.text)

        if resp['success'] != True or 'results' not in resp or not resp['results']:
            print(f"[-] Failure geolocating {bssid}")
        else:
            #we got a successful geolocation, so return it
            results = resp['results']
            for item in results:
                resBssid = item['netid'].lower()
                if bssid != resBssid:
                    continue
                lat = item['trilat']
                lon = item['trilong']
                break 

    except Exception as e:
        print(f"[-] Exception {e} querying WiGLE")

    return lat, lon

def geolocate(bssid, args):
    '''
    @brief: Decides which geolocation engine to use and passes the required
    parameters off to that function
    @param: bssid: string BSSID to attempt to geolocate
    @param: args: argparse argument object
    @returns: Lat/lon from geolocation (unable to geolocate returns 
    -180.0,-180.0)
    '''

    lat, lon = -180.0, -180.0
    if args.apple:
        lat, lon = geolocateApple(bssid)
    elif args.wigle:
        lat, lon = geolocateWiGLE(bssid, args.api_user, args.api_pass)
    elif args.mylnikov:
        lat, lon = geolocateMylnikov(bssid)

    return lat, lon

def validateIP(ip):
    '''
    @brief: Checks whether an IP address parameter is valid
    @param: ip: string to verify is a legit IPv6 address
    @returns: bool: True if ip is a valid IPv6 address, False else
    '''
    try:
        ipaddress.IPv6Address(ip)
    except ipaddress.AddressValueError as e:
        print(f"[-] Error: {ip} is an invalid IPv6 address: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error validating IP address: {e}")
        return False

    return True


def printLocations(locations):
    '''
    @brief: Prints the lookup results in a friendly manner
    @param: locations: dictionary keyed by EUI-64-derived MAC address
    @return: None
    '''

    print("#EUI-64-Derived MAC\tBSSID\tlat,lon")
    for euiMAC in locations:
        res = locations[euiMAC]
        BSSID = res[0]
        lat = res[1]
        lon = res[2]
        print(f"{euiMAC}\t{BSSID}\t{lat},{lon}")

    return None

def writeKML(locations, fname):
    '''
    @brief: Writes the KML output file if user wanted one written
    @param: locations: dictionary keyed by EUI-64-derived MAC address
    @return: None
    '''

    kml = simplekml.Kml()

    for euiMAC in locations:
        res = locations[euiMAC]
        BSSID = res[0]
        lat = res[1]
        lon = res[2]

        #skip the default invalid coordinates we return if we can't find a
        #predicted BSSID
        if lat == -180 and lon == -180:
            continue

        point = kml.newpoint(name=BSSID, description=f"EUI-64-Derived MAC: {euiMAC}",
                coords=[(lon, lat)])

    kml.save(fname)

    return None

def main(args):

    locations = {}
    ouiDict = getOffsets(args.offset_file)

    #Single MAC geolocation requested
    if args.mac:
        predictedBSSID = getPredictedBSSID(args.mac, ouiDict)
        lat, lon = geolocate(predictedBSSID, args)
        locations[args.mac] = (predictedBSSID, lat, lon)

    #File of EUI-64 MAC geolocations requested
    elif args.mac_file:

        with open(args.mac_file) as f:
            for line in f:
                mac = line.strip()
                if not isMAC(mac):
                    print(f"[-] {mac} is not a valid MAC address")
                    continue

                predictedBSSID = getPredictedBSSID(mac, ouiDict)
                lat, lon = geolocate(predictedBSSID, args)
                locations[mac] = (predictedBSSID, lat, lon)

    #Single EUI-64 IPv6 address to geolocate requested
    elif args.eui:

        if not validateIP(args.eui):
            sys.exit(6)

        mac = getMAC(ipaddress.IPv6Address(args.eui).exploded)
        predictedBSSID = getPredictedBSSID(mac, ouiDict)
        lat, lon = geolocate(predictedBSSID, args)
        locations[mac] = (predictedBSSID, lat, lon)

    #File of EUI-64 IPv6 address geolocations requested
    elif args.eui_file:

        with open(args.eui_file) as f:
            for line in f:
                ip = line.strip()

                if not validateIP(ip):
                    continue
            
                if not isEUI64(ip):
                    print(f"[-] {ip} is not a valid EUI-64 IPv6 address")
                    continue

                mac = getMAC(ipaddress.IPv6Address(ip).exploded)

                predictedBSSID = getPredictedBSSID(mac, ouiDict)
                lat, lon = geolocate(predictedBSSID, args)
                locations[mac] = (predictedBSSID, lat, lon)

    printLocations(locations)

    if args.kml:
        writeKML(locations, args.kml)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    inputType = parser.add_mutually_exclusive_group(required=True)
    inputType.add_argument("-M", "--mac-file", help="File of MAC addresses "+\
            "from EUI-64 IPv6 addresses to bulk lookup")
    inputType.add_argument("-m", "--mac", help="Single MAC address from "+\
            "EUI-64 IPv6 address to attempt to geolocate")
    inputType.add_argument("-e", "--eui", help="Single EUI-64 IPv6 address" +\
            " to extract MAC from and attempt to geolocate")
    inputType.add_argument("-E", "--eui-file", help="File of EUI-64 IPv6 " +\
            "addresses to extract MAC from and attempt to geolocate")
    lookupType = parser.add_mutually_exclusive_group(required=True)
    lookupType.add_argument("-a", "--apple", help="Use Apple's location " +\
            "services API to geolocate BSSID", action="store_true")
    lookupType.add_argument("-w", "--wigle", help="Use WiGLE's API to " +\
            "geolocate BSSID (requires -U API_USER and -P API_PASS)", 
            action="store_true")
    lookupType.add_argument("-y", "--mylnikov", help="Use api.mylnikov.org "+\
            "API to geolocate BSSID", action="store_true")
    parser.add_argument("-o", "--offset-file", help="File containing " + \
            "inferred OUI offsets (default ./offsets.txt)", default="offsets.txt")
    parser.add_argument("-k", "--kml", help="Output KML filename")
    parser.add_argument("-U", "--api-user", help="WiGLE API username (required for -w)")
    parser.add_argument("-P", "--api-pass", help="WiGLE API password (required for -w)")
    args = parser.parse_args()

    checkArgs(args)

    main(args)
    

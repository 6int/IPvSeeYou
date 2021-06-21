# IPvSeeYou Geolocation Lookup Tool

## Overview

`IPvSeeYou.py` is a tool to assist with geolocating EUI-64 IPv6 hosts. It 

1. takes as input an EUI-64-derived MAC address, 
1. uses a previously-generated WAN MAC address to BSSID offset table to predict
   the BSSID for the EUI-64-derived MAC address, 
1. queries a geolocation API for the predicted BSSID, and 
1. prints the results (and optionally outputs to KML.)

## Requirements

`IPvSeeYou.py` is written in and has been tested only using Python3. Installing
the packages from the `requirements.txt` file using:

```
pip3 install -r requirements.txt
```

will ensure you have the required dependencies.

## Usage

`IPvSeeYou.py` is written in Python3 and uses `argparse`, so you can always get
help by passing the `-h` flag:

```
user@host % ./IPvSeeYou.py -h
usage: IPvSeeYou.py [-h] (-M MAC_FILE | -m MAC | -e EUI | -E EUI_FILE) (-a | -w) [-o OFFSET_FILE]
                    [-k KML] [-U API_USER] [-P API_PASS]

optional arguments:
  -h, --help            show this help message and exit
  -M MAC_FILE, --mac-file MAC_FILE
                        File of MAC addresses from EUI-64 IPv6 addresses to bulk lookup
  -m MAC, --mac MAC     Single MAC address from EUI-64 IPv6 address to attempt to geolocate
  -e EUI, --eui EUI     Single EUI-64 IPv6 address to extract MAC from and attempt to geolocate
  -E EUI_FILE, --eui-file EUI_FILE
                        File of EUI-64 IPv6 addresses to extract MAC from and attempt to geolocate
  -a, --apple           Use Apple's location services API to geolocate BSSID
  -w, --wigle           Use WiGLE's API to geolocate BSSID (requires -U API_USER and -P API_PASS)
  -o OFFSET_FILE, --offset-file OFFSET_FILE
                        File containing inferred OUI offsets (default ./offsets.txt)
  -k KML, --kml KML     Output KML filename
  -U API_USER, --api-user API_USER
                        WiGLE API username (required for -w)
  -P API_PASS, --api-pass API_PASS
                        WiGLE API password (required for -w)
```

The first set of mutually exclusive arguments indicates how the program should
expect EUI-64-derived MAC addresses.

1. `-e EUI` indicates that the user is specifying a single EUI-64 IPv6 address
   to attempt to geolocate, as in `-e 2001::0211:22ff:fe33:4455`
1. `-E EUI_FILE` indicates that the user is specifying a file that contains one
   or more EUI-64 IPv6 addresses, each separated by a newline, as in 
    `-E euis.txt`
1. `-m MAC` indicates that the user is specifying a single MAC address (that
   presumably they derived from an EUI-64 IPv6 address), as in `-m
00:11:22:33:44:55`
1. `-M MAC_FILE` indicates that they user is specifying a file containing one or
   more MAC addresses, each separated by a newline, as in `-M macs.txt`

The second set of mutually exclusive arguments indicates how the program should
look up the predicted BSSID (if one is found) for the EUI-64 derived MAC
addresses.

1. `-a/--apple` will use Apple's location services API. `IPvSeeYou.py` uses
   logic derived from hubert3's [iSniff-GPS](https://github.com/hubert3/iSniff-GPS)
1. `-w/--wigle` will use WiGLE's API to query for the predicted BSSID. This
   requires a WiGLE API username and password to be specified using
`-U/--api-user` and `-P/--api-pass`.

`-o/--offset-file OFFSET_FILE` is an optional argument to specify OUI and their WAN MAC to
BSSID offsets, each on a new line. For example:

```
00:11:22 -3
00:77:88 2
```

indicates that the OUI `00:11:22` has a WAN MAC to BSSID offset of -3. By
default, a file called `./offsets.txt` is used and need not be specified if it
exists.

`-k/--kml KML` is an optional argument that will generate a KML output file with
a point for each geolocated EUI-64-derived MAC address. 

### Examples

MAC addresses, username/password and geolocations in this section are for
example purposes only, and will not provide an actual geolocation or
authentication to WiGLE.

To specify a single EUI-64 IPv6 address to geolocate using Apple's location
services API and output to a KML file called `output.kml`, we:

```
./IPvSeeYou.py -e 2001:0:1:2:0200:11ff:fe22:3344 -k output.kml -a

#EUI-64-Derived MAC	BSSID	lat,lon
00:00:11:22:33:44	00:00:11:22:33:46	12.34,56.78 
```

To specify a file containing EUI-64-derived MAC addresses to geolocate using the
WiGLE API, with WiGLE API username `` and password ``, we:

```
./IPvSeeYou.py -M fileOfMacs.txt -w -U abcdefabcdefabcdefabcdef -P 1234567890abcdef
#EUI-64-Derived MAC	BSSID	lat,lon
00:00:11:22:33:44	00:00:11:22:33:46	12.34,56.78 
f8:00:11:22:33:44	f8:00:11:22:33:40	23.45,-12.34
```

## Credits

Much of the code that interacts with Apple's Location Services was borrowed from
@hubert3's excellent [`iSniff-GPS`](https://github.com/hubert3/iSniff-GPS),
presented at Black Hat USA 2012.

#!/usr/bin/env python3
# netsec-toolkit — network security toolkit
# https://github.com/feelyounear/netsec-toolkit
#
# requires: requests, dnspython
#   pip install -r requirements.txt

import os
import sys
import time

from modules.utils import cls, RS, R, DR, W, G, Y, C, GR, B, err
from modules.network import (
    port_scanner, ping_sweep, traceroute,
    dns_lookup, ssl_checker, network_scanner,
)
from modules.osint import (
    whois_lookup, ip_geolocation, subdomain_finder,
    email_header, username_lookup, dorking_engine,
)
from modules.exploit import (
    hash_identifier, hash_cracker, jwt_decoder,
    sqli_tester, lfi_tester, dir_bruteforcer,
    header_analyzer, revshell_gen,
)


def banner():
    cls()
    print(f"""{DR}{B}
 ███╗   ██╗███████╗████████╗███████╗███████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝
 ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██║
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║
 ██║ ╚████║███████╗   ██║   ███████║███████╗╚██████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝{RS}
{R}─────────────────────────────────────────────────────{RS}
{GR}                  network security toolkit{RS}
{GR}                         by {R}Arre{RS}
{R}─────────────────────────────────────────────────────{RS}
""")


def menu():
    banner()
    print(f"  {DR}┌─[ {W}NETWORK{DR} ]──────────────────────────────────┐{RS}")
    print(f"  {DR}│{RS}  {R}[01]{RS} Port Scanner          {R}[02]{RS} Ping Sweep       {DR}│{RS}")
    print(f"  {DR}│{RS}  {R}[03]{RS} Traceroute            {R}[04]{RS} DNS Lookup       {DR}│{RS}")
    print(f"  {DR}│{RS}  {R}[05]{RS} SSL Checker           {R}[06]{RS} Network Scanner  {DR}│{RS}")
    print(f"  {DR}└────────────────────────────────────────────────┘{RS}")
    print()
    print(f"  {DR}┌─[ {W}OSINT{DR} ]─────────────────────────────────────┐{RS}")
    print(f"  {DR}│{RS}  {R}[07]{RS} Whois Lookup          {R}[08]{RS} IP Geolocation   {DR}│{RS}")
    print(f"  {DR}│{RS}  {R}[09]{RS} Subdomain Finder      {R}[10]{RS} Email Header     {DR}│{RS}")
    print(f"  {DR}│{RS}  {R}[11]{RS} Username Lookup       {R}[12]{RS} Dorking Engine   {DR}│{RS}")
    print(f"  {DR}└────────────────────────────────────────────────┘{RS}")
    print()
    print(f"  {DR}┌─[ {W}EXPLOIT UTILS{DR} ]──────────────────────────────┐{RS}")
    print(f"  {DR}│{RS}  {R}[13]{RS} Hash Identifier       {R}[14]{RS} Hash Cracker     {DR}│{RS}")
    print(f"  {DR}│{RS}  {R}[15]{RS} JWT Decoder           {R}[16]{RS} SQLi Tester      {DR}│{RS}")
    print(f"  {DR}│{RS}  {R}[17]{RS} LFI Tester            {R}[18]{RS} Dir Bruteforcer  {DR}│{RS}")
    print(f"  {DR}│{RS}  {R}[19]{RS} Header Analyzer       {R}[20]{RS} Reverse Shell Gen{DR}│{RS}")
    print(f"  {DR}└────────────────────────────────────────────────┘{RS}")
    print()
    print(f"  {GR}[0] Exit{RS}")
    print()
    return input(f"  {DR}[{W}netsec{DR}]{RS} → ").strip()


ROUTES = {
    "1":  port_scanner,    "01": port_scanner,
    "2":  ping_sweep,      "02": ping_sweep,
    "3":  traceroute,      "03": traceroute,
    "4":  dns_lookup,      "04": dns_lookup,
    "5":  ssl_checker,     "05": ssl_checker,
    "6":  network_scanner, "06": network_scanner,
    "7":  whois_lookup,    "07": whois_lookup,
    "8":  ip_geolocation,  "08": ip_geolocation,
    "9":  subdomain_finder,"09": subdomain_finder,
    "10": email_header,
    "11": username_lookup,
    "12": dorking_engine,
    "13": hash_identifier,
    "14": hash_cracker,
    "15": jwt_decoder,
    "16": sqli_tester,
    "17": lfi_tester,
    "18": dir_bruteforcer,
    "19": header_analyzer,
    "20": revshell_gen,
}


def main():
    while True:
        choice = menu()
        if choice in ("0", "00") or choice.lower() in ("exit", "quit", "q"):
            cls()
            sys.exit(0)
        fn = ROUTES.get(choice)
        if fn:
            try:
                fn()
            except KeyboardInterrupt:
                pass
        else:
            err("Invalid option")
            time.sleep(0.4)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cls()
        sys.exit(0)

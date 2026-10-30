#!/usr/bin/env python3
# modules/utils.py — shared helpers and color constants

import os
import socket
import re

# ─── ANSI colors ───────────────────────────────────────────────────────────────
R  = "\033[91m"
DR = "\033[31m"
W  = "\033[97m"
G  = "\033[92m"
Y  = "\033[93m"
C  = "\033[96m"
GR = "\033[90m"
RS = "\033[0m"
B  = "\033[1m"


def cls():
    os.system("cls" if os.name == "nt" else "clear")


def resolve(host):
    host = re.sub(r"^https?://", "", host).split("/")[0]
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"  {R}[!]{RS} Could not resolve '{host}': {e}")
        return None


def get_input(prompt):
    val = input(f"  {DR}>{RS} {prompt}: ").strip()
    if val == "0":
        raise KeyboardInterrupt
    return val


def section(title):
    cls()
    print(f"\033[31m\033[1m")
    print(f" ███╗   ██╗███████╗████████╗███████╗███████╗ ██████╗")
    print(f" ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝")
    print(f" ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██║     ")
    print(f" ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║     ")
    print(f" ██║ ╚████║███████╗   ██║   ███████║███████╗╚██████╗")
    print(f" ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝{RS}")
    print(f"{R}─────────────────────────────────────────────────────{RS}")
    print(f"{GR}                  network security toolkit{RS}")
    print(f"{GR}                         by {R}Arre{RS}")
    print(f"{R}─────────────────────────────────────────────────────{RS}\n")
    print(f"  {DR}┌─[ {W}{title}{DR} ]{'─' * max(1, 44 - len(title))}┐{RS}\n")


def ok(msg):    print(f"  {G}[+]{RS} {msg}")
def info(msg):  print(f"  {C}[*]{RS} {msg}")
def warn(msg):  print(f"  {Y}[!]{RS} {msg}")
def err(msg):   print(f"  {R}[!]{RS} {msg}")
def result(label, val): print(f"  {GR}    {label:<22}{RS}{W}{val}{RS}")


def pause():
    print(f"\n  {GR}[0] Back  |  any key to stay{RS}")
    v = input("  → ").strip()
    if v == "0":
        raise KeyboardInterrupt

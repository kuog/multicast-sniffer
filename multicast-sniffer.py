#!/usr/bin/env python3

from netaddr import EUI, NotRegisteredError
import pyshark
import curses
import argparse
import signal
import os
from subprocess import PIPE, CalledProcessError, Popen
import re
import json

parser = argparse.ArgumentParser(description='WLAN multicast sniffer. Find WLAN clients and ethernet LAN stations '
                                             'behind access point through MAC address diclosure in multicast packets. '
                                             'Press Ctrl+C to exit.')
parser.add_argument('-i', '--iface', help='WLAN interface in monitor mode', required=True, dest='iface')
parser.add_argument('-b', '--bssid', help='Display MACs for the selected BSSID', required=False, dest='bssid')
parser.add_argument('-f', '--file', help='Output file to store found MACs', required=False, dest='file')
parser.add_argument('-c', '--channel', help='Set channel', required=False, dest='channel')
parser.add_argument('-t', '--timeout', help='Set timeout to quit', type=int, required=False, dest='timeout')
parser.add_argument('-j', '--json', help='Output file name in JSON format', required=False, dest='json')
args = parser.parse_args()

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")


def get_current_channel():
    bash_command = 'iwlist ' + args.iface + ' channel'
    out = run_bash(bash_command)
    m = re.match(".*Current Frequency.+\(Channel (?P<ch>\d+)\)", str(out))
    return m.groups('ch')[0]


def run_bash(bash_command):
    try:
        process = Popen(bash_command.split(), stdout=PIPE)
        output, _ = process.communicate()
        if process.returncode != 0:
            print(output)
            exit(1)
        else:
            return output
    except CalledProcessError as e:
        print(e)
        exit(1)


channel = ''


def write_results():
    if args.file is not None:
        with open(args.file, 'w') as fout:
            for bssid, bssid_data in bssids.items():
                fout.write('BSSID=' + bssid + ', SSID=' + bssid_data['essid'] + ', channel ' + bssid_data['ch'] + os.linesep)
                for src_addr, dst_list in bssid_data['src'].items():
                    fout.write('\tSA=' + src_addr + os.linesep)
                    for dst_addr in dst_list:
                        fout.write('\t\tDA=' + dst_addr + os.linesep)


def write_json():
    if args.json is not None:
        with open(args.json, 'w') as jout:
            json.dump(bssids, jout)


bssids = {}
essids = {}


def sigint_handler(signum, frame):
    print('Stop pressing the CTRL+C!')
    write_results()
    write_json()


def sigalrm_handler(signum, frame):
    print('Stopped on timeout')
    write_results()
    write_json()
    exit(0)


signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGALRM, sigalrm_handler)

if args.timeout is not None:
    signal.alarm(args.timeout)


def find_oui(ether):
    try:
        mac = EUI(ether)
        org = mac.oui.registration().org
        ether += "(" + org + ")"
    except NotRegisteredError:
        pass
    return ether


def find_multicast(mac):
    mac = mac.upper()
    is_multicast = False
    if mac == "FF:FF:FF:FF:FF:FF":
        mac += " Broadcast"
        is_multicast = True
    elif mac == "01:00:0C:CC:CC:CC":
        mac += " CDP/VTP/UDLD"
        is_multicast = True
    elif mac == "01:00:0C:CC:CC:CD":
        mac += " Cisco Shared Spanning Tree Protocol Address"
        is_multicast = True
    elif mac == "01:80:C2:00:00:00" or mac == "01:80:C2:00:00:03" or mac == "01:80:C2:00:00:0E":
        mac += " LLDP"
        is_multicast = True
    elif mac == "01:80:C2:00:00:08":
        mac += " STP (for provider bridges) IEEE 802.1ad"
        is_multicast = True
    elif mac == "01:80:C2:00:00:01":
        mac += " Ethernet flow control (Pause frame) IEEE 802.3x"
        is_multicast = True
    elif mac == "01:80:C2:00:00:02":
        mac += " Ethernet OAM Protocol IEEE 802.3ah (A.K.A. 'slow protocols')"
        is_multicast = True
    elif "01:80:C2:00:00:3" in mac:
        mac += " Ethernet CFM Protocol IEEE 802.1ag"
        is_multicast = True
    elif "01:00:5E" in mac:
        mac += " IPv4 Multicast (RFC 1112)"
        is_multicast = True
    elif "33:33:" in mac:
        mac += " IPv6 Multicast (RFC 2464)"
        is_multicast = True
    elif "01:0C:CD:01:" in mac:
        mac += " IEC 61850:8:1 GOOSE Type 1/1A"
        is_multicast = True
    elif "01:0C:CD:02:" in mac:
        mac += " GSSE (IEC 61850 8:1)"
        is_multicast = True
    elif "01:0C:CD:04:" in mac:
        mac += " Multicast sampled values (IEC 61850 8-1)"
        is_multicast = True
    elif mac == "01:1B:19:00:00:00" or mac == "01:80:C2:00:00:0E":
        mac += " Precision Time Protocol (PTP) version 2 over Ethernet (layer:2)"
        is_multicast = True
    return mac, is_multicast


def main():
    global channel
    if args.channel is not None:
        set_channel(args.channel)
    channel = get_current_channel()
    stdscr = prepare_screen()
    cap = pyshark.LiveCapture(interface=args.iface)
    for pkt in cap.sniff_continuously():
        try:
            bssid = pkt.wlan.bssid
            sa = pkt.wlan.sa
            da = pkt.wlan.da
            bssid = find_oui(bssid)
            find_ssid(bssid, pkt)
            if (
                    args.bssid is not None and pkt.wlan.bssid.lower() == args.bssid.lower() and
                    pkt.wlan.bssid != pkt.wlan.sa) or (
                    pkt.wlan.bssid != 'ff:ff:ff:ff:ff:ff' and pkt.wlan.bssid != pkt.wlan.sa):
                sa = find_oui(sa)
                da = find_oui(da)
                da, m = find_multicast(da)
                if m:
                    store_bssid(bssid, sa, da, channel)
                    write_results()
                    write_json()
                print_bssids(stdscr)
        except AttributeError:
            pass
        except Exception as e:
            print(e)
            exit(1)


def store_bssid(bssid, src_addr, dst_addr, ch):
    global bssids
    if bssid not in bssids:
        bssids[bssid] = {'ch': ch, 'essid': get_ssid(bssid), 'src': {src_addr: [dst_addr]}}
    elif src_addr not in bssids[bssid]['src']:
        bssids[bssid]['src'][src_addr] = [dst_addr]
    else:
        dst_list = bssids[bssid]['src'][src_addr]
        if dst_addr not in dst_list:
            dst_list.append(dst_addr)

    if get_ssid(bssid) != bssids[bssid]['essid']:
        bssids[bssid]['essid'] = get_ssid(bssid)


def get_ssid(bssid):
    global essids
    ssid = '<not found>'
    if bssid in essids:
        ssid = essids[bssid]
    return ssid


def find_ssid(bssid, packet):
    if packet.wlan.fc_type_subtype == '8':  # Beacon frame
        if bssid not in essids:
            if len(packet.layers[3].ssid) == 0:
                essids[bssid] = '<hidden>'
            else:
                essids[bssid] = str(packet.layers[3].ssid)


def prepare_screen():
    stdscr = curses.initscr()
    curses.start_color()
    # Don't print what I type on the terminal
    curses.noecho()
    # React to every key press, not just when pressing "enter"
    curses.cbreak()
    # Enable easy key codes (will come back to this)
    stdscr.keypad(True)
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    return stdscr


def set_channel(ch):
    bash_command = 'iwconfig ' + args.iface + ' channel ' + ch
    run_bash(bash_command)


def print_bssids(stdscr):
    global bssids
    stdscr.clear()
    try:
        n = 1
        stdscr.addstr(n, 0, 'Run on ' + args.iface + ', channel ' + channel)
        n += 1
        for bssid, bssid_data in bssids.items():
            stdscr.addstr(n, 0, 'BSSID=' + bssid + ', SSID=' + bssid_data['essid'], curses.color_pair(1))
            n += 1
            for src_addr, dst_list in bssid_data['src'].items():
                stdscr.addstr(n, 10, 'SA=' + src_addr, curses.color_pair(2))
                n += 1
                for dst_addr in dst_list:
                    stdscr.addstr(n, 20, 'DA=' + dst_addr)
                    n += 1
    except curses.error:
        pass
    stdscr.refresh()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import requests

def get_arguments():
    '''
    Collecting arugments from user
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', dest='ip', help='IP/IPs to scan', required=True)

    return parser.parse_args()

def get_mac_producent(mac):
    '''
    Getting MAC producents from api, and returning them.
    '''
    req = requests.get(f'https://api.macvendors.com/{mac}')
    if req.status_code == 200:          # If request return success (find in database) code thne execute this
        return req.text
    else:
        return 'UNKNOWN'


def scan(ip):
    '''
    Scans the network and retrieves MAC addresses of active devices.
    Calls another scanning functions
    '''
    client_list = []

    arp_frame = scapy.ARP(pdst=ip)
    ether_frame = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    frame = ether_frame / arp_frame
    answered_list = scapy.srp(frame, timeout=10, verbose=False)[0]

    for element in answered_list:
        mac = element[1].hwsrc
        client_list.append({'ip': element[1].psrc, 'mac': mac, 'mac_producent': get_mac_producent(mac)})
    return client_list


def print_results(result_list):
    '''
    Printing results of scanning
    '''
    print(f'IP\t\tMAC Address\t\tMAC producent\n{"-"*60}')
    for client in result_list:
        print(f'{client["ip"]}\t{client["mac"]}\t{client["mac_producent"]}')

if __name__ == '__main__':
    options = get_arguments()
    scan_result = scan(options.ip)
    print_results(scan_result)
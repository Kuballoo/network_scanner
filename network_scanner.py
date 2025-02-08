#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def get_arguments():
    '''
    Collecting arugments from user
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', dest='ip', help='IP/IPs to scan', required=True)

    return parser.parse_args()


def scan_mac(ip):
    '''
    Scans the network and retrieves MAC addresses of active devices.
    '''
    client_list = []

    arp_frame = scapy.ARP(pdst=ip)
    ether_frame = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    frame = ether_frame / arp_frame
    answered_list = scapy.srp(frame, timeout=1, verbose=False)[0]

    for element in answered_list:
        client_list.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
    return client_list


def print_results(result_list):
    '''
    Printing results of scanning
    '''
    print(f'IP\t\t\tMAC Address\n{"-"*50}')
    for client in result_list:
        print(f'{client["ip"]}\t\t{client["mac"]}')

if __name__ == '__main__':
    options = get_arguments()
    scan_result = scan_mac(options.ip)
    print_results(scan_result)
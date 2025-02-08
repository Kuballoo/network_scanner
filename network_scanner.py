#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import requests
import ipaddress

def get_arguments():
    '''
    Collecting arugments from user
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', dest='ip', help='IP/IPs to scan', required=True)
    parser.add_argument('-t', '--timeout', dest='timeout', help='Waiting time for response of ARP request', type=float, default=1)
    parser.add_argument('-a', '--accurate', dest='accurate_flag', help='Make more accurate scanning (long waiting time)', action='store_true', default=False)

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


def gen_ips_list(network_ip):
    '''
    Generating list of ips for accurate scanning
    '''
    try:
        network = ipaddress.IPv4Network(network_ip, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def send_arp_request(ip, timeout=1):
    """
    Sends an ARP request to the given IP and returns the response.
    """
    arp_frame = scapy.ARP(pdst=ip)
    ether_frame = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    frame = ether_frame / arp_frame
    answered_list = scapy.srp(frame, timeout=timeout, verbose=False)[0]
    return [
        {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'mac_producent': get_mac_producent(element[1].hwsrc)}
        for element in answered_list
    ]


def accurate_scanning(ip_list, timeout):
    """
    Performs a more detailed scan for a list of IPs.
    """
    client_list = []
    try:
        for index, ip in enumerate(ip_list, 1):
            print(f'\rAccurate scanning in progress: {index}/{len(ip_list)}', end='', flush=True)
            client_list.extend(send_arp_request(ip, timeout))
        print('')
    except KeyboardInterrupt:
        return client_list
        
    return client_list

def scan(ip, timeout):
    """
    Scans a single IP or subnet and retrieves MAC addresses of active devices.
    """
    return send_arp_request(ip, timeout)


def print_results(result_list):
    '''
    Printing results of scanning
    '''
    print(f'IP\t\tMAC Address\t\tMAC producent\n{"-"*60}')
    for client in result_list:
        print(f'{client["ip"]}\t{client["mac"]}\t{client["mac_producent"]}')

if __name__ == '__main__':
    options = get_arguments()
    scan_result = None
    if not options.accurate_flag:
        scan_result = scan(options.ip, options.timeout)
    else:
        scan_result = accurate_scanning(gen_ips_list(options.ip), options.timeout)
    print_results(scan_result)
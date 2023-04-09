from scapy.config import conf
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1
import time
import ipwhois


def is_found(pkt, ip, timeout, requests, whois):
    conf.verb = 0
    start = time.time()
    response = sr1(pkt, timeout=timeout)
    finish = time.time()
    times = round((finish - start) * 1000)
    if not response:
        print(f'{requests} *')
    else:
        ip_res = response.src
        if whois:
            print(f'{requests} {ip_res} {times} ms {get_whois(ip_res)}')
        else:
            print(f'{requests} {ip_res} {times} ms')
        if ip == ip_res:
            return True
    return False


def get_whois(ip):
    try:
        return ipwhois.IPWhois(ip).lookup_rdap()['asn']
    except ipwhois.IPDefinedError:
        return '-'


def icmp(ip, timeout, requests, whois):
    ttl = 1
    while ttl <= requests:
        if ':' in ip:
            pkt = IPv6(dst=ip, hlim=ttl) / ICMPv6EchoRequest()
        else:
            pkt = IP(dst=ip, ttl=ttl) / ICMP()
        if is_found(pkt, ip, timeout, ttl, whois):
            break
        ttl += 1


def tcp(ip, port, timeout, requests, whois):
    ttl = 1
    while ttl <= requests:
        if ':' in ip:
            pkt = IPv6(dst=ip, hlim=ttl) / TCP(dport=port)
        else:
            pkt = IP(dst=ip, ttl=ttl) / TCP(dport=port)
        if is_found(pkt, ip, timeout, ttl, whois):
            break
        ttl += 1


def udp(ip, port, timeout, requests, whois):
    ttl = 1
    while ttl <= requests:
        if ':' in ip:
            pkt = IPv6(dst=ip, hlim=ttl) / UDP(dport=port)
        else:
            pkt = IP(dst=ip, ttl=ttl) / UDP(dport=port)
        if is_found(pkt, ip, timeout, ttl, whois):
            break
        ttl += 1

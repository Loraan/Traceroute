import argparse
from modules import traceroute_algo


def inp():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timeout', dest="timeout", help="Таймаут ожидания ответа", type=int, default=2)
    parser.add_argument('-p', '--port', dest="port", help="Порт (для TCP/UDP)", type=int)
    parser.add_argument('-n', '--hops', dest="requests", help="Максимальное количество запросов", type=int, default=30)
    parser.add_argument('-v', '--verbose', dest="whois", help="Вывод номера автономной системы", action="store_true")
    parser.add_argument('ip', help="IP адрес")
    parser.add_argument('protocol', help="TCP/UDP/ICMP", choices=['tcp', 'udp', 'icmp'])
    return parser


def traceroute():
    arguments = inp().parse_args()
    ip = arguments.ip
    port = arguments.port
    time = arguments.timeout
    requests = arguments.requests
    whois = arguments.whois
    if arguments.protocol == "tcp":
        traceroute_algo.tcp(ip, port, time, requests, whois)
    elif arguments.protocol == "udp":
        traceroute_algo.udp(ip, port, time, requests, whois)
    elif arguments.protocol == "icmp":
        traceroute_algo.icmp(ip, time, requests, whois)


if __name__ == "__main__":
    traceroute()

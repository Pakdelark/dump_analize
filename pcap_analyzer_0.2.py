#usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_analyzer.py
Добавлена детализация по источникам и назначениям (src/dst)
"""

import sys
import argparse
from collections import Counter
from scapy.all import PcapReader, TCP, UDP, IP, IPv6, ARP

def human_perc(part, whole):
    if whole == 0:
        return "0.00%"
    return f"{(part/whole)*100:6.2f}%"


def analyze_pcap(path, max_packets=None):
    ip_counts = Counter()
    ip_src_counts = Counter()
    ip_dst_counts = Counter()

    port_counts = Counter()
    port_src_counts = Counter()
    port_dst_counts = Counter()

    l3_counts = Counter()
    l4_counts = Counter()
    tcp_flag_counts = Counter()

    total_packets = 0
    total_ip_mentions = 0
    total_port_mentions = 0
    total_tcp_packets = 0

    def record_tcp_flags(tcp_pkt):
        flags_str = str(tcp_pkt.flags)
        if 'S' in flags_str:
            tcp_flag_counts['SYN'] += 1
        if 'A' in flags_str:
            tcp_flag_counts['ACK'] += 1
        if 'F' in flags_str:
            tcp_flag_counts['FIN'] += 1
        if 'R' in flags_str:
            tcp_flag_counts['RST'] += 1
        if 'P' in flags_str:
            tcp_flag_counts['PSH'] += 1
        if 'U' in flags_str:
            tcp_flag_counts['URG'] += 1
        if 'E' in flags_str:
            tcp_flag_counts['ECE'] += 1
        if 'C' in flags_str:
            tcp_flag_counts['CWR'] += 1
        if ('S' in flags_str) and ('A' in flags_str):
            tcp_flag_counts['SYN-ACK'] += 1

    # ---- Основной цикл обработки pcap ----
    try:
        with PcapReader(path) as pcap:
            for pkt in pcap:
                total_packets += 1
                if max_packets and total_packets >= max_packets:
                    break

                # IPv4
                if IP in pkt:
                    l3_counts['IPv4'] += 1
                    ip = pkt[IP]
                    ip_counts[ip.src] += 1
                    ip_counts[ip.dst] += 1
                    ip_src_counts[ip.src] += 1
                    ip_dst_counts[ip.dst] += 1
                    total_ip_mentions += 2

                    if TCP in pkt:
                        l4_counts['TCP'] += 1
                        tcp = pkt[TCP]
                        total_tcp_packets += 1
                        port_counts[tcp.sport] += 1
                        port_counts[tcp.dport] += 1
                        port_src_counts[tcp.sport] += 1
                        port_dst_counts[tcp.dport] += 1
                        total_port_mentions += 2
                        record_tcp_flags(tcp)

                    elif UDP in pkt:
                        l4_counts['UDP'] += 1
                        udp = pkt[UDP]
                        port_counts[udp.sport] += 1
                        port_counts[udp.dport] += 1
                        port_src_counts[udp.sport] += 1
                        port_dst_counts[udp.dport] += 1
                        total_port_mentions += 2
                    else:
                        proto = ip.proto
                        if proto == 1:
                            l4_counts['ICMP'] += 1
                        else:
                            l4_counts['OTHER'] += 1

                # IPv6
                elif IPv6 in pkt:
                    l3_counts['IPv6'] += 1
                    ip6 = pkt[IPv6]
                    ip_counts[ip6.src] += 1
                    ip_counts[ip6.dst] += 1
                    ip_src_counts[ip6.src] += 1
                    ip_dst_counts[ip6.dst] += 1
                    total_ip_mentions += 2

                    if TCP in pkt:
                        l4_counts['TCP'] += 1
                        tcp = pkt[TCP]
                        total_tcp_packets += 1
                        port_counts[tcp.sport] += 1
                        port_counts[tcp.dport] += 1
                        port_src_counts[tcp.sport] += 1
                        port_dst_counts[tcp.dport] += 1
                        total_port_mentions += 2
                        record_tcp_flags(tcp)

                    elif UDP in pkt:
                        l4_counts['UDP'] += 1
                        udp = pkt[UDP]
                        port_counts[udp.sport] += 1
                        port_counts[udp.dport] += 1
                        port_src_counts[udp.sport] += 1
                        port_dst_counts[udp.dport] += 1
                        total_port_mentions += 2
                    else:
                        l4_counts['OTHER'] += 1

                # ARP
                elif ARP in pkt:
                    l3_counts['ARP'] += 1
                    arp = pkt[ARP]
                    if hasattr(arp, 'psrc') and arp.psrc:
                        ip_counts[arp.psrc] += 1
                        ip_src_counts[arp.psrc] += 1
                        total_ip_mentions += 1
                    if hasattr(arp, 'pdst') and arp.pdst:
                        ip_counts[arp.pdst] += 1
                        ip_dst_counts[arp.pdst] += 1
                        total_ip_mentions += 1

                else:
                    l3_counts['OTHER'] += 1

    except FileNotFoundError:
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)
        sys.exit(3)

    # Возврат результатов
    return {
        'total_packets': total_packets,
        'l3_counts': dict(l3_counts),
        'l4_counts': dict(l4_counts),
        'ip_counts': ip_counts,
        'ip_src_counts': ip_src_counts,
        'ip_dst_counts': ip_dst_counts,
        'port_counts': port_counts,
        'port_src_counts': port_src_counts,
        'port_dst_counts': port_dst_counts,
        'tcp_flag_counts': dict(tcp_flag_counts),
        'total_ip_mentions': total_ip_mentions,
        'total_port_mentions': total_port_mentions,
        'total_tcp_packets': total_tcp_packets
    }


def pretty_print(results, top_n=20):
    tp = results
    print("=" * 60)
    print(f"Total packets processed: {tp['total_packets']}")
    print("-" * 60)

    print("L3 protocol distribution:")
    total_l3 = sum(tp['l3_counts'].values())
    for k, v in sorted(tp['l3_counts'].items(), key=lambda x: -x[1]):
        print(f"  {k:8s}: {v:8d}   {human_perc(v, total_l3)}")
    print("-" * 60)

    print("L4 protocol distribution:")
    total_l4 = sum(tp['l4_counts'].values())
    for k, v in sorted(tp['l4_counts'].items(), key=lambda x: -x[1]):
        print(f"  {k:8s}: {v:8d}   {human_perc(v, total_l4)}")
    print("-" * 60)

    print(f"Top {top_n} IP addresses (src+dst):")
    total_ip = tp['total_ip_mentions'] or 1
    for i, (ip, cnt) in enumerate(tp['ip_counts'].most_common(top_n), 1):
        src = tp['ip_src_counts'].get(ip, 0)
        dst = tp['ip_dst_counts'].get(ip, 0)
        print(f"{i:2d}. {ip:40s} total:{cnt:8d}  src:{src:8d}  dst:{dst:8d}  {human_perc(cnt, total_ip)}")
    print("-" * 60)

    print(f"Top {top_n} ports (TCP+UDP):")
    total_ports = tp['total_port_mentions'] or 1
    for i, (port, cnt) in enumerate(tp['port_counts'].most_common(top_n), 1):
        src = tp['port_src_counts'].get(port, 0)
        dst = tp['port_dst_counts'].get(port, 0)
        print(f"{i:2d}. {str(port):6s} total:{cnt:8d}  src:{src:8d}  dst:{dst:8d}  {human_perc(cnt, total_ports)}")
    print("-" * 60)

    print("TCP flags:")
    total_tcp = tp['total_tcp_packets'] or 1
    for f, cnt in tp['tcp_flag_counts'].items():
        print(f"  {f:7s}: {cnt:8d}   {human_perc(cnt, total_tcp)}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Анализ pcap: топ адресов, порты, протоколы, TCP флаги + src/dst")
    parser.add_argument("pcap", help="путь до pcap файла")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--max", type=int, default=None)
    args = parser.parse_args()

    results = analyze_pcap(args.pcap, args.max)
    pretty_print(results, args.top)


if __name__ == "__main__":
    main()

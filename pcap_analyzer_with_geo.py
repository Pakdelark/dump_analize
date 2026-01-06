#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Accurate and fast pcap analysis:
- IPv4 / IPv6
- TCP / UDP / ICMP / ICMPv6
- Top IP src/dst with GEO
- port taking into account the protocol
- TCP flags
- init/resp and port
"""

import sys
import argparse
from collections import Counter
from scapy.all import PcapReader, TCP, UDP, IP, IPv6, ARP
from pathlib import Path

# attempting to import the geoip2 library
try:
    import geoip2.database
except ImportError:
    geoip2 = None

# launch geoIP if the GeoLite2-Country.mmdb file is in the directory
def init_geoip():   
    base_dir = Path(__file__).resolve().parent
    db_path = base_dir / "GeoLite2-Country.mmdb"

    if not geoip2:
        return None

    if not db_path.is_file():
        return None

    try:
        return geoip2.database.Reader(db_path)
    except Exception:
        return None
# if the country is not found, returns dashes
def geo_country(reader, ip):    
    if not reader:
        return "-------"

    try:
        r = reader.country(ip)
        return r.country.name or "-------"   # or use r.country.iso_code [US]
    except Exception:
        return "-------"

# initialize persent format
def human_perc(part, whole):
    return f"{(part / whole * 100):6.2f}%" if whole else "0.00%"

# packet and content counter
def analyze_pcap(path, max_packets=None):   
    # Counters
    l3_counts = Counter()
    l4_counts = Counter()

    ip_counts = Counter()
    ip_src_counts = Counter()
    ip_dst_counts = Counter()

    port_counts = Counter()          # ('TCP', 443)
    port_src_counts = Counter()
    port_dst_counts = Counter()

    ip_flows = Counter()      # (src_ip, dst_ip)
    ip_port_flows = Counter() # (src_ip, proto, dst_port)

    tcp_flag_combo = Counter()

    total_packets = 0
    total_ip_endpoints = 0
    total_port_endpoints = 0
    total_tcp_packets = 0

    try:
        with PcapReader(path) as pcap:
            for pkt in pcap:
                total_packets += 1
                if max_packets and total_packets > max_packets:
                    break

                # ---------- IPv4 ----------
                if IP in pkt:
                    l3_counts['IPv4'] += 1
                    ip = pkt[IP]

                    ip_counts[ip.src] += 1
                    ip_counts[ip.dst] += 1
                    ip_src_counts[ip.src] += 1
                    ip_dst_counts[ip.dst] += 1
                    ip_flows[(ip.src, ip.dst)] += 1
                    total_ip_endpoints += 2

                    proto = ip.proto

                    if TCP in pkt:
                        l4_counts['TCP'] += 1
                        tcp = pkt[TCP]
                        total_tcp_packets += 1

                        key_s = ('TCP', tcp.sport)
                        key_d = ('TCP', tcp.dport)

                        port_counts[key_s] += 1
                        port_counts[key_d] += 1
                        port_src_counts[key_s] += 1
                        port_dst_counts[key_d] += 1
                        ip_port_flows[(ip.src, 'TCP', tcp.dport)] += 1
                        total_port_endpoints += 2

                        tcp_flag_combo[str(tcp.sprintf("%TCP.flags%"))] += 1

                    elif UDP in pkt:
                        l4_counts['UDP'] += 1
                        udp = pkt[UDP]

                        key_s = ('UDP', udp.sport)
                        key_d = ('UDP', udp.dport)

                        port_counts[key_s] += 1
                        port_counts[key_d] += 1
                        port_src_counts[key_s] += 1
                        port_dst_counts[key_d] += 1
                        ip_port_flows[(ip.src, 'UDP', udp.dport)] += 1
                        total_port_endpoints += 2

                    elif proto == 1:
                        l4_counts['ICMP'] += 1
                    else:
                        l4_counts[f'IP_PROTO_{proto}'] += 1

                # ---------- IPv6 ----------
                elif IPv6 in pkt:
                    l3_counts['IPv6'] += 1
                    ip6 = pkt[IPv6]

                    ip_counts[ip6.src] += 1
                    ip_counts[ip6.dst] += 1
                    ip_src_counts[ip6.src] += 1
                    ip_dst_counts[ip6.dst] += 1
                    ip_flows[(ip6.src, ip6.dst)] += 1
                    total_ip_endpoints += 2

                    if TCP in pkt:
                        l4_counts['TCP'] += 1
                        tcp = pkt[TCP]
                        total_tcp_packets += 1

                        key_s = ('TCP', tcp.sport)
                        key_d = ('TCP', tcp.dport)

                        port_counts[key_s] += 1
                        port_counts[key_d] += 1
                        port_src_counts[key_s] += 1
                        port_dst_counts[key_d] += 1
                        ip_port_flows[(ip6.src, 'TCP', tcp.dport)] += 1
                        total_port_endpoints += 2

                        tcp_flag_combo[str(tcp.sprintf("%TCP.flags%"))] += 1

                    elif UDP in pkt:
                        l4_counts['UDP'] += 1
                        udp = pkt[UDP]

                        key_s = ('UDP', udp.sport)
                        key_d = ('UDP', udp.dport)

                        port_counts[key_s] += 1
                        port_counts[key_d] += 1
                        port_src_counts[key_s] += 1
                        port_dst_counts[key_d] += 1
                        ip_port_flows[(ip6.src, 'UDP', udp.dport)] += 1
                        total_port_endpoints += 2

                    elif ip6.nh == 58:
                        l4_counts['ICMPv6'] += 1
                    else:
                        l4_counts[f'IP6_NH_{ip6.nh}'] += 1

                # ---------- ARP ----------
                elif ARP in pkt:
                    l3_counts['ARP'] += 1

                else:
                    l3_counts['OTHER'] += 1

    # input error handling
    except FileNotFoundError:   
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)
        sys.exit(3)

    return {
        'total_packets': total_packets,
        'l3_counts': l3_counts,
        'l4_counts': l4_counts,
        'ip_counts': ip_counts,
        'ip_src_counts': ip_src_counts,
        'ip_dst_counts': ip_dst_counts,
        'port_counts': port_counts,
        'port_src_counts': port_src_counts,
        'port_dst_counts': port_dst_counts,
        'tcp_flag_combo': tcp_flag_combo,
        'total_ip_endpoints': total_ip_endpoints,
        'total_port_endpoints': total_port_endpoints,
        'total_tcp_packets': total_tcp_packets,
        'ip_flows': ip_flows,
        'ip_port_flows': ip_port_flows,
    }
# defining the connection initiator
def split_initiators_responders(src_counter, dst_counter, top_n=10):  
    roles = []
    for key in set(src_counter) | set(dst_counter):
        src = src_counter.get(key, 0)
        dst = dst_counter.get(key, 0)
        delta = src - dst
        roles.append((key, src, dst, delta))

    initiators = sorted(
        [r for r in roles if r[3] > 0],
        key=lambda x: x[3],
        reverse=True
    )[:top_n]

    responders = sorted(
        [r for r in roles if r[3] < 0],
        key=lambda x: abs(x[3]),
        reverse=True
    )[:top_n]

    return initiators, responders

# global output 
def pretty_print(tp, top_n=10):

    print("=" * 60)
    print(f"Total packets processed: {tp['total_packets']}")
    print("-" * 60)

    print("L3 protocol distribution:")
    total = sum(tp['l3_counts'].values())
    for k, v in tp['l3_counts'].most_common():
        print(f"  {k:12s}: {v:8d} {human_perc(v, total)}")

    print("-" * 60)
    print("L4 protocol distribution:")
    total = sum(tp['l4_counts'].values())
    for k, v in tp['l4_counts'].most_common():
        print(f"  {k:12s}: {v:8d} {human_perc(v, total)}")

    print("-" * 60)
    geo = init_geoip()  # attempt to initialize the GEO function
    
    # top ip adresses
    print(f"Top {top_n} IP addresses:")
    total = tp['total_ip_endpoints']
    for i, (ip, cnt) in enumerate(tp['ip_counts'].most_common(top_n), 1):
        country = geo_country(geo, ip)  # GEO
        print(f"{i:2d}. {ip:20s} {country:15s} "
              f"src:{tp['ip_src_counts'][ip]:7d} "
              f"dst:{tp['ip_dst_counts'][ip]:7d} "
              f"{human_perc(cnt, total)}")
    # top ports
    print("-" * 60)
    print(f"Top {top_n} ports:")
    total = tp['total_port_endpoints']
    for i, ((proto, port), cnt) in enumerate(tp['port_counts'].most_common(top_n), 1):
        print(f"{i:2d}. {proto}:{port:<6} total:{cnt:7d} "
              f"src:{tp['port_src_counts'][(proto, port)]:7d} "
              f"dst:{tp['port_dst_counts'][(proto, port)]:7d} "
              f"{human_perc(cnt, total)}")

    # TCP - flags
    print("-" * 60)
    print("TCP flag combinations:")
    total = tp['total_tcp_packets']
    for flags, cnt in tp['tcp_flag_combo'].most_common():
        print(f"  {flags:8s}: {cnt:7d} {human_perc(cnt, total)}")

    print("=" * 60)

    # initiators 

    print("TOP IP INITIATORS (src ≫ dst) WITH TARGETS")

    initiators, responders = split_initiators_responders(
        tp['ip_src_counts'], tp['ip_dst_counts'], top_n
    )

    for i, (src_ip, src_cnt, dst_cnt, delta) in enumerate(initiators, 1):

        country = geo_country(geo, src_ip)
        print(f"\n{i:2d}. {src_ip} {country} src:{src_cnt} dst:{dst_cnt} Δ:{delta:+}")

        # Куда этот IP слал пакеты
        targets = Counter(
            {dst: c for (s, dst), c in tp['ip_flows'].items() if s == src_ip}
        )

        for dst_ip, cnt in targets.most_common(3):
            print(f"      → {dst_ip:<40} packets:{cnt}")

        # На какие порты этот IP слал трафик
        ports = Counter(
            {(proto, port): c
             for (s, proto, port), c in tp['ip_port_flows'].items()
             if s == src_ip}
        )

        for (proto, port), cnt in ports.most_common(5):
            print(f"      → {proto}:{port:<6} packets:{cnt}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="PCAP analyzer (correct & fast)")
    parser.add_argument("pcap", help="path to pcap file")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--max", type=int)
    args = parser.parse_args()

    res = analyze_pcap(args.pcap, args.max)
    pretty_print(res, args.top)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PCAP Attack Analyzer
Быстрый анализ атак:
- кто → кому
- кто → на какой порт
- initiators / responders
"""

import sys
import argparse
from collections import Counter
from scapy.all import PcapReader, TCP, UDP, IP, IPv6, ARP


# ---------- helpers ----------

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


# ---------- core analysis ----------

def analyze_pcap(path, max_packets=None):
    ip_src = Counter()
    ip_dst = Counter()

    port_src = Counter()      # (proto, port)
    port_dst = Counter()

    ip_flows = Counter()      # (src_ip, dst_ip)
    ip_port_flows = Counter() # (src_ip, proto, dst_port)

    try:
        with PcapReader(path) as pcap:
            for i, pkt in enumerate(pcap, 1):
                if max_packets and i > max_packets:
                    break

                # ---------- IPv4 ----------
                if IP in pkt:
                    ip = pkt[IP]
                    src, dst = ip.src, ip.dst

                    ip_src[src] += 1
                    ip_dst[dst] += 1
                    ip_flows[(src, dst)] += 1

                    if TCP in pkt:
                        tcp = pkt[TCP]
                        port_src[('TCP', tcp.sport)] += 1
                        port_dst[('TCP', tcp.dport)] += 1
                        ip_port_flows[(src, 'TCP', tcp.dport)] += 1

                    elif UDP in pkt:
                        udp = pkt[UDP]
                        port_src[('UDP', udp.sport)] += 1
                        port_dst[('UDP', udp.dport)] += 1
                        ip_port_flows[(src, 'UDP', udp.dport)] += 1

                # ---------- IPv6 ----------
                elif IPv6 in pkt:
                    ip6 = pkt[IPv6]
                    src, dst = ip6.src, ip6.dst

                    ip_src[src] += 1
                    ip_dst[dst] += 1
                    ip_flows[(src, dst)] += 1

                    if TCP in pkt:
                        tcp = pkt[TCP]
                        port_src[('TCP', tcp.sport)] += 1
                        port_dst[('TCP', tcp.dport)] += 1
                        ip_port_flows[(src, 'TCP', tcp.dport)] += 1

                    elif UDP in pkt:
                        udp = pkt[UDP]
                        port_src[('UDP', udp.sport)] += 1
                        port_dst[('UDP', udp.dport)] += 1
                        ip_port_flows[(src, 'UDP', udp.dport)] += 1

                elif ARP in pkt:
                    continue

    except FileNotFoundError:
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)
        sys.exit(3)

    return {
        'ip_src': ip_src,
        'ip_dst': ip_dst,
        'port_src': port_src,
        'port_dst': port_dst,
        'ip_flows': ip_flows,
        'ip_port_flows': ip_port_flows,
    }


# ---------- output ----------

def pretty_print(tp, top_n=10):
    print("=" * 70)
    print("TOP IP INITIATORS (src ≫ dst) WITH TARGETS")

    initiators, responders = split_initiators_responders(
        tp['ip_src'], tp['ip_dst'], top_n
    )

    for i, (src_ip, src, dst, delta) in enumerate(initiators, 1):
        print(f"\n{i:2d}. {src_ip}  src:{src} dst:{dst} Δ:{delta:+}")

        targets = Counter(
            {d: c for (s, d), c in tp['ip_flows'].items() if s == src_ip}
        )

        for d, c in targets.most_common(3):
            print(f"      → {d:<40} packets:{c}")

        ports = Counter(
            {(proto, port): c
             for (s, proto, port), c in tp['ip_port_flows'].items()
             if s == src_ip}
        )

        for (proto, port), c in ports.most_common(5):
            print(f"      → {proto}:{port:<6} packets:{c}")

    print("\n" + "=" * 70)
    print("TOP IP RESPONDERS (dst ≫ src)")

    for i, (ip, src, dst, delta) in enumerate(responders, 1):
        print(f"{i:2d}. {ip:<40} src:{src} dst:{dst} Δ:{delta:+}")

    print("\n" + "=" * 70)
    print("TOP PORT INITIATORS (clients)")

    p_init, p_resp = split_initiators_responders(
        tp['port_src'], tp['port_dst'], top_n
    )

    for i, ((proto, port), src, dst, delta) in enumerate(p_init, 1):
        print(f"{i:2d}. {proto}:{port:<6} src:{src} dst:{dst} Δ:{delta:+}")

    print("\n" + "=" * 70)
    print("TOP PORT RESPONDERS (servers)")

    for i, ((proto, port), src, dst, delta) in enumerate(p_resp, 1):
        print(f"{i:2d}. {proto}:{port:<6} src:{src} dst:{dst} Δ:{delta:+}")

    print("=" * 70)


# ---------- entry ----------

def main():
    parser = argparse.ArgumentParser(description="PCAP attack-oriented analyzer")
    parser.add_argument("pcap", help="path to pcap file")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--max", type=int)
    args = parser.parse_args()

    data = analyze_pcap(args.pcap, args.max)
    pretty_print(data, args.top)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Accurate and fast pcap analysis:
- IPv4 / IPv6
- TCP / UDP / ICMP / ICMPv6
- TLS
- Top IP src/dst with GEO
- port taking into account the protocol
- TCP flags
- VPN
- SNI
- init/resp and port
"""

import sys
import re
import argparse
from collections import Counter, defaultdict 
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

# Indentificate TLS version inside packet Client Hello
def detect_tls_version(pkt):
    if not pkt.haslayer(TCP):
        return None
    
    payload = bytes(pkt[TCP].payload)
    if len(payload) < 12:
        return None
    
    # 0x16 - Handshake record, 0x03 - TLS-pref
    if payload[0] == 0x16 and payload[1] == 0x03:
        if payload[5] == 0x01:  # Client Hello
            hs_version = payload[9:11]
            if hs_version == b'\x03\x01': return "TLS 1.0"
            if hs_version == b'\x03\x02': return "TLS 1.1"
            if hs_version == b'\x03\x03':
                # fast search extended supported_versions (0x002b) for detection TLS 1.3
                if b'\x00\x2b' in payload:
                    return "TLS 1.3"
                return "TLS 1.2"
    return None

# fast extraction of SNI (TLS Client Hello) or HTTP Host
def extract_sni_or_host(pkt):
    if TCP not in pkt:
        return None
    
    try:
        payload = bytes(pkt[TCP].payload)
    except Exception:
        return None

    if not payload:
        return None

    # 1. HTTP Request detection (GET, POST, HEAD, PUT, DELETE, OPTIONS, CONNECT)
    if any(payload.startswith(m) for m in [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT "]):
        try:
            text = payload.decode('utf-8', errors='ignore')
            for line in text.split('\r\n'):
                if line.lower().startswith('host:'):
                    return line.split(':', 1)[1].strip()
        except Exception:
            pass

    # 2. TLS Client Hello detection (0x16 = Handshake, 0x01 = Client Hello)
    if len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01:
        try:
            idx = 43  # Position of Session ID Length
            if idx >= len(payload): return None
            sess_id_len = payload[idx]
            idx += 1 + sess_id_len
            
            if idx + 2 > len(payload): return None
            cipher_len = int.from_bytes(payload[idx:idx+2], byteorder='big')
            idx += 2 + cipher_len
            
            if idx + 1 > len(payload): return None
            comp_len = payload[idx]
            idx += 1 + comp_len
            
            if idx + 2 > len(payload): return None
            ext_len = int.from_bytes(payload[idx:idx+2], byteorder='big')
            idx += 2
            
            end_idx = idx + ext_len
            if end_idx > len(payload): end_idx = len(payload)
            
            while idx + 4 <= end_idx:
                ext_type = int.from_bytes(payload[idx:idx+2], byteorder='big')
                ext_data_len = int.from_bytes(payload[idx+2:idx+4], byteorder='big')
                idx += 4
                
                if ext_type == 0:  # Server Name Indication (SNI)
                    if idx + 2 <= end_idx:
                        _ = int.from_bytes(payload[idx:idx+2], byteorder='big') # list length
                        if idx + 5 <= end_idx and payload[idx+2] == 0:  # Hostname type
                            name_len = int.from_bytes(payload[idx+3:idx+5], byteorder='big')
                            if idx + 5 + name_len <= end_idx:
                                return payload[idx+5:idx+5+name_len].decode('utf-8', errors='ignore')
                idx += ext_data_len
        except Exception:
            pass

    return None

# Heuristic discovery WireGuard, IPsec and OpenVPN 
def detect_vpn_and_ports(pkt):
    # Return cortage: (Protocol_name, port or (None, None).
    if pkt.haslayer(UDP):
        payload = bytes(pkt[UDP].payload)
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        
        # 1. WireGuard (Signature: 1-4 byte type + 3 byte zero)
        if len(payload) >= 4 and payload[1:4] == b'\x00\x00\x00':
            msg_type = payload[0]
            if msg_type in [1, 2, 3, 4]:
                # VPN-port (default 51820)
                active_port = dport if dport != 51820 and sport == 51820 else dport
                return "WireGuard", f"UDP:{active_port}"
        
        # 2. IPsec NAT-Traversal (default 4500)
        if dport == 4500 or sport == 4500:
            if len(payload) >= 4:
                p_name = "IPsec (IKEv2 NAT-T)" if payload[0:4] == b'\x00\x00\x00\x00' else "IPsec (ESP NAT-T)"
                return p_name, f"UDP:{dport if dport == 4500 else sport}"
        
        # 3. OpenVPN UDP (Heuristic by Opcode + classic port)
        if len(payload) > 1:
            opcode = payload[0] >> 3
            if 1 <= opcode <= 10 and (dport == 1194 or sport == 1194):
                return "OpenVPN (UDP)", f"UDP:{dport if dport == 1194 else sport}"

    elif pkt.haslayer(TCP):
        payload = bytes(pkt[TCP].payload)
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        
        # 4. OpenVPN TCP (default port = 1194 and header length)
        if len(payload) >= 2:
            if dport == 1194 or sport == 1194:
                return "OpenVPN (TCP)", f"TCP:{dport if dport == 1194 else sport}"
            # Additional marker for OpenVPN on 'hidden' ports like 443
            elif dport == 443 or sport == 443:
                # We check whether the segment length matches the first two bytes of the TCP payload
                op_len = int.from_bytes(payload[0:2], byteorder='big')
                if op_len == len(payload) - 2 and (payload[2] >> 3) in [1, 2, 7, 8]:
                    return "OpenVPN (TCP-Masked)", f"TCP:{dport if dport == 443 else sport}"

    return None, None

# packet and content counter
def analyze_pcap(path, max_packets=None):   
    # Counters
    l3_counts = Counter()
    l4_counts = Counter()
    tls_counts = Counter()

    ip_counts = Counter()
    ip_src_counts = Counter()
    ip_dst_counts = Counter()

    port_counts = Counter()          # ('TCP', 443)
    port_src_counts = Counter()
    port_dst_counts = Counter()

    ip_flows = Counter()      # (src_ip, dst_ip)
    ip_port_flows = Counter() # (src_ip, proto, dst_port)

    tcp_flag_combo = Counter()
    sni_counts = Counter()    # SNI web-resource counter
    vpn_counts = Counter()    # VPN
    vpn_ports = defaultdict(Counter)    # VPN ports

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

                        # Extracting Web Resources (SNI / HTTP Host) statistic
                        web_res = extract_sni_or_host(pkt)
                        if web_res:
                            sni_counts[web_res] += 1

                        # TLS statustic
                        tls_ver = detect_tls_version(pkt)
                        if tls_ver:
                            tls_counts[tls_ver] += 1

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

                        # VPN statistic
                        vpn_proto, vpn_port_str = detect_vpn_and_ports(pkt)
                        if vpn_proto:
                            vpn_counts[vpn_proto] += 1
                            vpn_ports[vpn_proto][vpn_port_str] += 1

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
        'tls_counts': tls_counts,
        'ip_src_counts': ip_src_counts,
        'ip_dst_counts': ip_dst_counts,
        'port_counts': port_counts,
        'port_src_counts': port_src_counts,
        'port_dst_counts': port_dst_counts,
        'tcp_flag_combo': tcp_flag_combo,
        'sni_counts': sni_counts,
        'vpn_counts': vpn_counts,
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

    # TLS
    print("TLS version distribution:")
    total_tls = sum(tp['tls_counts'].values())
    if total_tls > 0:
        for k, v in tp['tls_counts'].most_common():
            print(f"  {k:12s}: {v:8d} {human_perc(v, total_tls)}")
    else:
        print("  No TLS handshake packets identified.")
    print("-" * 60)
    
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


    # Top 10 Web Resources (SNI / HTTP Host)
    print("-" * 60)
    print(f"Top {top_n} requested web resources (SNI / HTTP Host):")
    total_sni = sum(tp['sni_counts'].values())
    if total_sni > 0:
        for i, (resource, cnt) in enumerate(tp['sni_counts'].most_common(top_n), 1):
            print(f"{i:2d}. {resource:<40} total:{cnt:7d} {human_perc(cnt, total_sni)}")
    else:
        print("  No SNI or HTTP Host entries identified.")

        # VPN 
    print("-" * 60)
    print("VPN protocol distribution & utilized ports:")
    total_all_packets = tp['total_packets']  # База для расчета % во всем трафике
    
    if tp['vpn_counts']:
        for proto, cnt in tp['vpn_counts'].most_common():
            # Считаем точный процент присутствия данного VPN во всем pcap-файле
            global_perc = human_perc(cnt, total_all_packets)
            print(f"  {proto:<35} total:{cnt:7d} {global_perc}")
            
            # Извлекаем и выводим порты, привязанные конкретно к этому протоколу
            ports_counter = tp['vpn_ports'][proto]
            for port_str, p_cnt in ports_counter.most_common(5):
                print(f"      → {port_str:<15} packets:{p_cnt}")
    else:
        print("  No VPN traffic identified.")

    # initiators 
    print("=" * 60)
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

        # Which ports this IP sent traffic to
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

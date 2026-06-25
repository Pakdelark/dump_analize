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
- DNS
- Init/resp adress and port
- ENGINE PERFORMANCE METRICS
"""

import time
import socket
import sys
import dpkt
import argparse
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
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

# presentation and translation
def human_traffic(bytes_count, active_secs_set=None):
	mb = bytes_count / (1024 * 1024)
	
	if active_secs_set:
		duration = len(active_secs_set)  # For how many seconds was data actually being transmitted?
		if duration > 0:
			mbps = (bytes_count * 8) / 1_000_000 / duration
			return f"{mb:8.2f} MB {mbps:6.2f} Mbps"
			
	return f"{mb:8.2f} MB   0.00 Mbps"

# Indentificate TLS version inside packet Client Hello
def detect_tls_version(payload):
	if not payload or len(payload) < 12:
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
def extract_sni_or_host(payload):
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
def detect_vpn_and_ports(proto_type, payload, sport, dport):
	# Return tuple: (Protocol_name, port_str) or (None, None).
	if not payload:
		return None, None

	if proto_type == 'UDP':
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

	elif proto_type == 'TCP':
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
	l3_counts = Counter()
	l4_counts = Counter()
	tls_counts = Counter()
	ip_counts = Counter()
	ip_src_counts = Counter()
	ip_dst_counts = Counter()
	port_counts = Counter()		  
	port_src_counts = Counter()
	port_dst_counts = Counter()
	ip_flows = Counter()	  
	ip_port_flows = Counter() 
	tcp_flag_combo = Counter()
	sni_counts = Counter()	
	vpn_counts = Counter()	
	vpn_ports = defaultdict(Counter)
	dns_query_counts = Counter()

	# Mb and mbps
	l3_bytes = Counter()
	l4_bytes = Counter()
	ip_bytes = Counter()
	port_bytes = Counter()
	dns_bytes = Counter()
	sni_bytes = Counter()

	# dict for recording the time (count mbps)
	ip_active_seconds = defaultdict(set)
	port_active_seconds = defaultdict(set)
	l3_active_seconds = defaultdict(set)
	l4_active_seconds = defaultdict(set)
	dns_active_seconds = defaultdict(set)
	sni_active_seconds = defaultdict(set)

	total_packets = 0
	total_ip_endpoints = 0
	total_port_endpoints = 0
	total_tcp_packets = 0

	# Fast local function-decode
	inet_ntoa = socket.inet_ntoa
	inet_ntop = socket.inet_ntop
	AF_INET6 = socket.AF_INET6

	try:
		with open(path, 'rb') as f:
			cheak_format = f.read(4)  # read firs 4 byte to determine the file format
			f.seek(0)  # reset the file pointer to the beginning of the file after checking
			
			if cheak_format == b'\x0a\x0d\x0d\x0a':
				pcap = dpkt.pcapng.Reader(f)
			else:
				pcap = dpkt.pcap.Reader(f)
			
			# detect tipe LVL (L2) 
			datalink = pcap.datalink()

			# packet time
			first_packet_ts = None
			last_packet_ts = None
			
			for ts, buf in pcap:
				if first_packet_ts is None:
					first_packet_ts = ts
				last_packet_ts = ts
				total_packets += 1
				if max_packets and total_packets > max_packets:
					break

				ip_packet = None
				is_ipv4 = False
				is_ipv6 = False

				# Extract network LVL (L3) depending on the structure and interface
				try:
					if datalink == 1:	  # DLT_EN10MB (Ethernet standart)
						eth = dpkt.ethernet.Ethernet(buf)
						if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
							l3_counts['ARP'] += 1
							continue
						ip_packet = eth.data
					elif datalink == 113:  # DLT_LINUX_SLL (Linux Cooked Capture, interface 'any')
						sll = dpkt.sll.SLL(buf)
						ip_packet = sll.data
					elif datalink == 0:	# DLT_NULL (Loopback / local host)
						if len(buf) >= 4:
							ip_packet = buf[4:]
					elif datalink in (101, 12):  # DLT_RAW / DLT_LOOP (Raw IP without L2)
						ip_packet = buf
					else:
						# Fallback option for accidental encapsulation
						eth = dpkt.ethernet.Ethernet(buf)
						ip_packet = eth.data

					# Forcefully decode raw bytes if dpkt hasn't done so itself
					if isinstance(ip_packet, dpkt.ip.IP):
						is_ipv4 = True
					elif isinstance(ip_packet, dpkt.ip6.IP6):
						is_ipv6 = True
					elif isinstance(ip_packet, bytes) and len(ip_packet) > 0:
						version = ip_packet[0] >> 4
						if version == 4:
							ip_packet = dpkt.ip.IP(ip_packet)
							is_ipv4 = True
						elif version == 6:
							ip_packet = dpkt.ip6.IP6(ip_packet)
							is_ipv6 = True
				except Exception:
					l3_counts['OTHER'] += 1
					continue

				if not (is_ipv4 or is_ipv6):
					l3_counts['OTHER'] += 1
					continue

				# Extracting IP addresses and L4 protocol code
				try:
					if is_ipv4:
						l3_counts['IPv4'] += 1
						src_ip = inet_ntoa(ip_packet.src)
						dst_ip = inet_ntoa(ip_packet.dst)
						proto = ip_packet.p
						l4_payload_raw = ip_packet.data
					else:
						l3_counts['IPv6'] += 1
						src_ip = inet_ntop(AF_INET6, ip_packet.src)
						dst_ip = inet_ntop(AF_INET6, ip_packet.dst)
						proto = ip_packet.nxt
						l4_payload_raw = ip_packet.data
				except Exception:
					continue

				# IP-statistic
				pkt_size = len(buf)  # Packet size in bytes
				ip_counts[src_ip] += 1
				ip_counts[dst_ip] += 1
				ip_src_counts[src_ip] += 1
				ip_dst_counts[dst_ip] += 1
				ip_flows[(src_ip, dst_ip)] += 1
				total_ip_endpoints += 2
				ip_bytes[src_ip] += pkt_size
				ip_bytes[dst_ip] += pkt_size
				l3_bytes['IPv4' if is_ipv4 else 'IPv6'] += pkt_size

				# Select the current second of the packet
				sec_bucket = int(ts)
				
				# Recorded active second for hosts and the L3 protocol
				ip_active_seconds[src_ip].add(sec_bucket)
				ip_active_seconds[dst_ip].add(sec_bucket)
				l3_active_seconds['IPv4' if is_ipv4 else 'IPv6'].add(sec_bucket)

				# ---------- TCP Processing ----------
				if proto == 6:  
					l4_counts['TCP'] += 1
					total_tcp_packets += 1
					
					try:
						# validation TCP
						if isinstance(l4_payload_raw, dpkt.tcp.TCP):
							tcp = l4_payload_raw
						else:
							tcp = dpkt.tcp.TCP(l4_payload_raw)
						
						sport = tcp.sport
						dport = tcp.dport
						payload = tcp.data
					except Exception:
						continue

					key_s = ('TCP', sport)
					key_d = ('TCP', dport)
					port_counts[key_s] += 1
					port_counts[key_d] += 1
					port_src_counts[key_s] += 1
					port_dst_counts[key_d] += 1
					ip_port_flows[(src_ip, 'TCP', dport)] += 1
					total_port_endpoints += 2

					# Byte and active second filling for TCP
					l4_bytes['TCP'] += pkt_size
					port_bytes[key_s] += pkt_size
					port_bytes[key_d] += pkt_size
					l4_active_seconds['TCP'].add(sec_bucket)
					port_active_seconds[key_s].add(sec_bucket)
					port_active_seconds[key_d].add(sec_bucket)

					# TCP flags (FSRPAUEC)
					flags = tcp.flags
					flags_str = ""
					if flags & 0x01: flags_str += "F"  # FIN
					if flags & 0x02: flags_str += "S"  # SYN
					if flags & 0x04: flags_str += "R"  # RST
					if flags & 0x08: flags_str += "P"  # PSH
					if flags & 0x10: flags_str += "A"  # ACK
					if flags & 0x20: flags_str += "U"  # URG
					if flags & 0x40: flags_str += "E"  # ECE
					if flags & 0x80: flags_str += "C"  # CWR
					tcp_flag_combo[flags_str or "."] += 1

					# Analize (Payload) SNI, TLS, VPN - count
					if payload:
						web_res = extract_sni_or_host(payload)
						if web_res: 
							sni_counts[web_res] += 1

						tls_ver = detect_tls_version(payload)
						if tls_ver: tls_counts[tls_ver] += 1
							
						vpn_proto, vpn_port_str = detect_vpn_and_ports('TCP', payload, sport, dport)
						if vpn_proto:
							vpn_counts[vpn_proto] += 1
							vpn_ports[vpn_proto][vpn_port_str] += 1

				# ---------- UDP Processing ----------
				elif proto == 17:  
					l4_counts['UDP'] += 1
					
					try:
						if isinstance(l4_payload_raw, dpkt.udp.UDP):
							udp = l4_payload_raw
						else:
							udp = dpkt.udp.UDP(l4_payload_raw)
						
						sport = udp.sport
						dport = udp.dport
						payload = udp.data
					except Exception:
						continue

					key_s = ('UDP', sport)
					key_d = ('UDP', dport)
					port_counts[key_s] += 1
					port_counts[key_d] += 1
					port_src_counts[key_s] += 1
					port_dst_counts[key_d] += 1
					ip_port_flows[(src_ip, 'UDP', dport)] += 1
					total_port_endpoints += 2

					# Byte and active second filling for UDP
					l4_bytes['UDP'] += pkt_size
					port_bytes[key_s] += pkt_size
					port_bytes[key_d] += pkt_size
					l4_active_seconds['UDP'].add(sec_bucket)
					port_active_seconds[key_s].add(sec_bucket)
					port_active_seconds[key_d].add(sec_bucket)
					if payload:
						# ---------- Deep analize DNS (standart port 53) ----------
						if sport == 53 or dport == 53:
							try:
								dns = dpkt.dns.DNS(payload)
								# cheak (queries) in package
								if dns.qd:
									for q in dns.qd:
										domain = q.name
										if isinstance(domain, bytes):
											domain = domain.decode('utf-8', errors='ignore')
										if domain:
											dns_query_counts[domain] += 1
							except Exception:
								pass # Ignore package, if it wasn't DNS-traffic

						# ---------- Count VPN proto ---------
						vpn_proto, vpn_port_str = detect_vpn_and_ports('UDP', payload, sport, dport)
						if vpn_proto:
							vpn_counts[vpn_proto] += 1
							vpn_ports[vpn_proto][vpn_port_str] += 1

				# ---------- Other L4 protocols ----------
				elif proto == 1:  
					l4_counts['ICMP'] += 1
					# Byte and active second filling for ICMP
					l4_bytes['ICMP'] += pkt_size
					l4_active_seconds['ICMP'].add(sec_bucket)
				elif proto == 58:  
					l4_counts['ICMPv6'] += 1
					# Byte and active second filling for ICMPv6
					l4_bytes['ICMPv6'] += pkt_size
					l4_active_seconds['ICMPv6'].add(sec_bucket)
				else:
					proto_name = f'PROTO_{proto}'
					l4_counts[proto_name] += 1
					# Byte and timestamp filling for other protocols
					l4_bytes[proto_name] += pkt_size
					l4_active_seconds[proto_name].add(sec_bucket)

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
		'vpn_ports': vpn_ports,
		'dns_query_counts': dns_query_counts,
		'total_ip_endpoints': total_ip_endpoints,
		'total_port_endpoints': total_port_endpoints,
		'total_tcp_packets': total_tcp_packets,
		'ip_flows': ip_flows,
		'ip_port_flows': ip_port_flows,
		'ip_bytes': ip_bytes,
		'port_bytes': port_bytes,
		'l3_bytes': l3_bytes,
		'l4_bytes': l4_bytes,
		'ip_active_seconds': ip_active_seconds,
		'port_active_seconds': port_active_seconds,
		'l3_active_seconds': l3_active_seconds,
		'l4_active_seconds': l4_active_seconds,
		'first_packet_ts': first_packet_ts,
		'last_packet_ts': last_packet_ts,
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
		ts_r = tp['l3_active_seconds'].get(k)
		traffic_str = human_traffic(tp['l3_bytes'][k], ts_r)
		print(f"  {k:12s}: {v:8d} {human_perc(v, total)} |{traffic_str}")

	print("-" * 60)
	print("L4 protocol distribution:")
	total = sum(tp['l4_counts'].values())
	for k, v in tp['l4_counts'].most_common():
		ts_r = tp['l4_active_seconds'].get(k)
		traffic_str = human_traffic(tp['l4_bytes'][k], ts_r)
		print(f"  {k:12s}: {v:8d} {human_perc(v, total)} |{traffic_str}")

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
	
	# Top IP adresses
	print(f"Top {top_n} IP addresses:")
	total = tp['total_ip_endpoints']
	for i, (ip, cnt) in enumerate(tp['ip_counts'].most_common(top_n), 1):
		country = geo_country(geo, ip)  # GEO
		ts_r = tp['ip_active_seconds'].get(ip)
		traffic_str = human_traffic(tp['ip_bytes'][ip], ts_r)
		
		print(f"{i:2d}. {ip:18s} {country:16s} "
			  f"src:{tp['ip_src_counts'][ip]:7d} "
			  f"dst:{tp['ip_dst_counts'][ip]:7d} "
			  f"{human_perc(cnt, total)} |{traffic_str}")

	# Top ports
	print("-" * 60)
	print(f"Top {top_n} ports:")
	total = tp['total_port_endpoints']
	for i, ((proto, port), cnt) in enumerate(tp['port_counts'].most_common(top_n), 1):
		key = (proto, port)
		active_secs = tp['port_active_seconds'].get(key)
		traffic_str = human_traffic(tp['port_bytes'][key], active_secs)
		print(f"{i:2d}. {proto}:{port:<6} total:{cnt:7d} "
			  f"src:{tp['port_src_counts'][(proto, port)]:7d} "
			  f"dst:{tp['port_dst_counts'][(proto, port)]:7d} "
			  f"{human_perc(cnt, total)} |{traffic_str}")

	# TCP flags
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

	# DNS
	print("-" * 60)
	print(f"Top {top_n} DNS Queries (Requested Domain Names):")
	total_dns = sum(tp['dns_query_counts'].values())
	if total_dns > 0:
		for i, (domain, cnt) in enumerate(tp['dns_query_counts'].most_common(top_n), 1):
			print(f"{i:2d}. {domain:<40} total:{cnt:7d} {human_perc(cnt, total_dns)}")
	else:
		print("  No DNS query packets identified.")

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
				print(f"	  → {port_str:<15} packets:{p_cnt}")
	else:
		print("  No VPN traffic identified.")

	# Initiators 
	print("=" * 60)
	print("TOP IP INITIATORS (src ≫ dst) WITH TARGETS")

	initiators, responders = split_initiators_responders(
		tp['ip_src_counts'], tp['ip_dst_counts'], top_n
	)

	for i, (src_ip, src_cnt, dst_cnt, delta) in enumerate(initiators, 1):

		country = geo_country(geo, src_ip)
		print(f"\n{i:2d}. {src_ip} {country} src:{src_cnt} dst:{dst_cnt} Δ:{delta:+}")

		# Where was this IP sending packets
		targets = Counter(
			{dst: c for (s, dst), c in tp['ip_flows'].items() if s == src_ip}
		)

		for dst_ip, cnt in targets.most_common(3):
			print(f"	  ↳ {dst_ip:<40} packets:{cnt}")

		# Which ports this IP sent traffic to
		ports = Counter(
			{(proto, port): c
			 for (s, proto, port), c in tp['ip_port_flows'].items()
			 if s == src_ip}
		)

		for (proto, port), cnt in ports.most_common(5):
			print(f"	  → {proto}:{port:<6} packets:{cnt}")

	print("=" * 60)


def main():
	# 1. Time - start of processing
	start_time = time.perf_counter()

	parser = argparse.ArgumentParser(description="PCAP analyzer (correct & fast)")
	parser.add_argument("pcap", help="path to pcap file")
	parser.add_argument("--top", type=int, default=10)  # up/down defaul value
	parser.add_argument("--max", type=int)
	args = parser.parse_args()
	res = analyze_pcap(args.pcap, args.max)

	# 2. Time - end of processing 
	end_time = time.perf_counter()

	pretty_print(res, args.top)

	# Lead time - result
	execution_time = end_time - start_time

	total_packets = res.get('total_packets', 0)
	print("******ENGINE PERFORMANCE METRICS:*******")
	print("  Trace file:", args.pcap)
	print(f"  Total processing time : {execution_time:.4f} seconds")

	if execution_time > 0 and total_packets > 0:
		# Packets Per Second
		pps = total_packets / execution_time
		print(f"  Throughput speed	  : {pps:.2f} packets/sec (PPS)")
	else:
		print("  Throughput speed	  : N/A (Zero packets or instant execution)")
	
	print("-" * 60)
	
	# packet time
	start_ts = res.get('first_packet_ts')
	end_ts = res.get('last_packet_ts')
	
	if start_ts and end_ts:
		start_time = datetime.fromtimestamp(start_ts).strftime('%d-%m-%Y %H:%M:%S.%f')[:-7]
		end_time = datetime.fromtimestamp(end_ts).strftime('%d-%m-%Y %H:%M:%S.%f')[:-7]
		duration = end_ts - start_ts
		print(f"  Capture Start Time : {start_time}")
		print(f"  Capture End Time   : {end_time}")
		print(f"  Total Capture Duration: {duration:.0f} seconds")
	else:
		print("  Capture Time Range : Unknown (No packets or timestamps)")

	print("=" * 60)

if __name__ == "__main__":
	main()

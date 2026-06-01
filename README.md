### About the progect

This is instument for fast analize traffic dump on L3, L4 lvl.

### Required additional python libraries

 - scapy
 - geoip2 

### Launch options

`python3 <name_cript> <dump_file.pcap>`

### Usege GEO-IP

In order for GEO-IP to work, it necessary download database, in the same folder __where__ the script is located.
- free versian download from the officual website *MaxMind* or other sources.

### Format result 

**example**

Total packets processed: 328

L3 protocol distribution:

	IPv4        :      326  99.39%
	ARP         :        2   0.61%


L4 protocol distribution:

	TCP         :      286  87.73%
	UDP         :       40  12.27%


TLS version distribution:

	TLS 1.2     :        4  57.14%
	TLS 1.3     :        3  42.86%

Top 10 IP addresses:

	1. 10.10.100.10        -------         src:    174 dst:    132  46.93%
	2. 31.14.41.239         Romania         src:     89 dst:    121  32.21%
	3. 149.154.167.99       United Kingdom  src:     30 dst:     37  10.28%
	4. 127.0.0.1            -------         src:     10 dst:     10   3.07%
	5. 127.0.0.53           -------         src:     10 dst:     10   3.07%
	6. 10.10.100.11        -------         src:     10 dst:     10   3.07%
	7. 172.64.41.4          -------         src:      1 dst:      2   0.46%
	8. 34.36.137.203        United States   src:      1 dst:      2   0.46%
	9. 34.107.243.93        United States   src:      1 dst:      2   0.46%


Top 10 ports:

	1. TCP:2047   total:   7080 src:   4040 dst:   3040  50.00%	
	2. TCP:50440  total:   3686 src:   1368 dst:   2318  26.03%
	3. TCP:40648  total:    337 src:    146 dst:    191   2.38%	
	4. TCP:40622  total:    127 src:     55 dst:     72   0.90%
	5. TCP:38840  total:    120 src:     57 dst:     63   0.85%
	6. TCP:40624  total:     91 src:     43 dst:     48   0.64%
	7. TCP:50500  total:     85 src:     41 dst:     44   0.60%
	8. TCP:40474  total:     81 src:     39 dst:     42   0.57%
	9. TCP:40660  total:     81 src:     40 dst:     41   0.57%
	10. TCP:40552  total:     79 src:     35 dst:     44   0.56%

TCP flag combinations:

	PA      :    3900  55.08%
	A       :    2934  41.44%
	S       :      62   0.88%
	SA      :      62   0.88%
	FA      :      41   0.58%
	R       :      40   0.56%
	FPA     :      37   0.52%
	RA      :       4   0.06%

Top 10 requested web resources (SNI / HTTP Host)
	
	1. fp.gl.processes.top                      total:      5  71.43%
	2. t.me                                     total:      1  14.29%
	3. telegram.me                              total:      1  14.29%


VPN protocol distribution & utilized ports:

	No VPN traffic identified.


TOP IP INITIATORS (src ≫ dst) WITH TARGETS
	
	1. 10.10.100.10 ------- src:174 dst:132 Δ:+42
      → 31.14.41.239                             packets:121
      → 149.154.167.99                           packets:37
      → 10.10.100.11                            packets:10
      → TCP:443    packets:164
      → UDP:53     packets:10






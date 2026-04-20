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

Total packets processed:
---
L3 protocol distribution:
	* IPv4	:
	* ARP	:
	* IPv6	:
	...
---
L4 protocol distribution:
	* TCP
	* UDP
	...
---
Top 10 IP addresses:
...
---
Top 10 ports:
...
---
TCP flag combinations:
	* PA	:
	* A 	:
	...
---
TOP IP INITIATORS (src ≫ dst) WITH TARGETS
...
---



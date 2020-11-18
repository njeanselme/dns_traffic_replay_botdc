import logging
import struct
import re
import socket
import binascii
import dns
import dns.resolver
import dns.message
import dns.query
import dns.edns
import dns.flags

#########################################################	

logging.basicConfig(handlers = [logging.FileHandler('replay-query.log'), logging.StreamHandler()],level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file = 'dns-query.log'
log_format = 'query' #query, response, capture
dns_server = '52.119.40.100'

#########################################################

def send_dns_query(qip,qname,qtype,dns_server):

	TIMEOUT = 0.4
	PAYLOAD = 512
	
	if ':' in qip:
		qip = socket.inet_pton(socket.AF_INET6, qip)
	else:
		qip = socket.inet_aton(qip)

	options = [dns.edns.GenericOption(65523,qip),						 #qip
	dns.edns.GenericOption(65524,binascii.unhexlify('000000000000')),	 #source mac
	dns.edns.GenericOption(65526,'POC'.encode())] 						 #dns_view
	
	message = dns.message.make_query(qname, qtype, use_edns=True, options = options)
	message.payload = PAYLOAD
	dns.query.udp(message, dns_server, timeout=TIMEOUT)

#########################################################


file=open(log_file, 'r')	
content = file.readlines()
line_number=0

for line in content:
	line_number +=1
	line = line.strip()
	qip = qname = qtype = None
	

#query
#client @0x7f3ea8154d20 192.168.1.101#59001 (videosearch.ubuntu.com): query: videosearch.ubuntu.com IN A + (192.168.1.2)
#client @0x7f3ea8154d20 192.168.1.4#46850 (myboguscompany): query: myboguscompany IN SOA - (192.168.1.2)
#client @0x7f3ea8254b10 ::1#49641 (1.0.0.127.in-addr.arpa): query: 1.0.0.127.in-addr.arpa IN PTR + (2001:db8:a42:cafe:100::2)

	if log_format =='query':
		regex = re.compile(r'^client @0x[0-9a-fA-F]+ ([^#]+)#\d+ \([^)]+\): query: ([^ ]+) [A-Z]+ ([A-Z]+) [+-]+.*$')
		z = re.match(regex, line)
		if z:
			if len(z.groups()) == 3:
				qip = z.groups()[0]
				qname = z.groups()[1]
				qtype = z.groups()[2]
				
#response
#18-Nov-2020 02:23:46.188 client 127.0.0.1#59536: UDP: query: 1.0.0.127.in-addr.arpa IN PTR response: NOERROR +A 1.0.0.127.in-addr.arpa. 3600 IN PTR localhost.;
	
	if log_format =='response':
		regex = re.compile(r'^[^ ]+ [^ ]+ client ([^#]+)#\d+: (UDP|TCP): query: ([^ ]+) [A-Z]+ ([A-Z]+) .*$')
		z = re.match(regex, line)
		if z:
			if len(z.groups()) == 4:
				logging.debug((z.groups()))
				qip = z.groups()[0]
				qname = z.groups()[2]
				qtype = z.groups()[3]
				
#capture

	if log_format =='capture':
		regex = re.compile(r'^$')#todo
		z = re.match(regex, line)
		if z:
			if len(z.groups()) == 4:
				logging.debug((z.groups()))
				qip = z.groups()[0]
				qname = z.groups()[2]
				qtype = z.groups()[3]

		
	if not (qip == None and qname == None and qtype == None):
		send_dns_query(qip,qname,qtype,dns_server)
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
import concurrent.futures
import timeit

#########################################################	

logging.basicConfig(handlers = [logging.FileHandler('replay-query.log'), logging.StreamHandler()],level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file = 'dns-query.log'
log_format = 'query' #query, response, capture
dns_server = '52.119.40.100'
errors = 0
threads = 0

#########################################################

def send_dns_query(qip,qname,qtype,dns_server):
	try:
		TIMEOUT = 0.05
		PAYLOAD = 512
	
		if ':' in qip:
			qip = socket.inet_pton(socket.AF_INET6, qip)
		else:
			qip = socket.inet_aton(qip)

		options = [dns.edns.GenericOption(65523,qip),						 #qip
		#dns.edns.GenericOption(65524,binascii.unhexlify('000000000000')),	 #source mac
		dns.edns.GenericOption(65526,'POC'.encode())] 			 #dns_view
	
		message = dns.message.make_query(qname, qtype, use_edns=True, options = options)
		#message.payload = PAYLOAD
	
		dns.query.udp(message, dns_server, timeout=TIMEOUT)
	except:
		global errors
		errors=+1
	
	global threads
	threads-=1
	
#########################################################

file=open(log_file, 'r')	
content = file.readlines()
line_number=0
starttime = timeit.default_timer()

with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:

	for line in content:
		line_number +=1
		line = line.strip()
		qip = qname = qtype = None
	

#query
#client @0x7f3ea8154d20 192.168.1.101#59001 (videosearch.ubuntu.com): query: videosearch.ubuntu.com IN A + (192.168.1.2)
#client @0x7f3ea8154d20 192.168.1.4#46850 (myboguscompany): query: myboguscompany IN SOA - (192.168.1.2)
#client @0x7f3ea8254b10 ::1#49641 (1.0.0.127.in-addr.arpa): query: 1.0.0.127.in-addr.arpa IN PTR + (2001:db8:a42:cafe:100::2)

#Nov 26 09:20:13  dns1.ls.pd 10.1.2.3 named[17272]: client 10.1.3.4#39747 (1.rhel.pool.ntp.org): view 7: query: 1.rhel.pool.ntp.org IN A + (10.1.2.2)

		if log_format =='query':
			regex = re.compile(r'^client @0x[0-9a-fA-F]+ ([^#]+)#\d+ \([^)]+\): query: ([^ ]+) [A-Z]+ ([A-Z]+) [+-]+.*$')
			z = re.match(regex, line)
			if z:
				if len(z.groups()) == 3:
					qip = z.groups()[0]
					qname = z.groups()[1]
					qtype = z.groups()[2]
					
			else:
				regex2 = re.compile(r'.*named\[\d+\]\: client ([^#]+)#\d+ \([^)]+\): view [^:]+: query: ([^ ]+) [A-Z]+ ([^ ]+) ')
				y = re.match(regex2, line)
				if y:
					if len(y.groups()) == 3:
						qip = y.groups()[0]
						qname = y.groups()[1]
						qtype = y.groups()[2]

				
#response
#18-Nov-2020 02:23:46.188 client 127.0.0.1#59536: UDP: query: 1.0.0.127.in-addr.arpa IN PTR response: NOERROR +A 1.0.0.127.in-addr.arpa. 3600 IN PTR localhost.;
	
		if log_format =='response':
			regex = re.compile(r'^[^ ]+ [^ ]+ client ([^#]+)#\d+: (UDP|TCP): query: ([^ ]+) [A-Z]+ ([A-Z]+) .*$')
			z = re.match(regex, line)
			if z:
				if len(z.groups()) == 4:
				#logging.debug((z.groups()))
					qip = z.groups()[0]
					qname = z.groups()[2]
					qtype = z.groups()[3]
				
#capture
#1606142707,930,Query,,10.1.1.1,12345,,I,wpad.domain.name,IN,A,1,,Y,,,,,,,,,,,,,,

		if log_format =='capture':
			regex = re.compile(r'\d+,\d+,Query,,([^,]+),\d+,,I,([^,]+),[^,]+,([^,]+)')
			z = re.match(regex, line)
			if z:
				if len(z.groups()) == 3:
				#logging.debug((z.groups()))
					qip = z.groups()[0]
					qname = z.groups()[1]
					qtype = z.groups()[2]

		
		if not (qip == None and qname == None and qtype == None):
			executor.submit(send_dns_query(qip,qname,qtype,dns_server))
			threads+=1
			print("\r", end="")
			print("Queries: ",line_number, "/",len(content)," QPS: ",int(line_number/(timeit.default_timer() - starttime)),"Active Threads: ",threads ,"Errors: ",errors, end="")

print("\n")

#!/usr/bin/python3
from scapy.all import *
import random as r # random port numbers
import re
import sys # error checking command arguments
import ipaddress # error checking command IP addressses
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def main():
	ports = False
	if (len(sys.argv) > 4 or len(sys.argv) < 4):
		print("Command line error. There can only be 4 arguments in the command line: sudo python3 <python script> <dest IP> <port range>")
		sys.exit()
	try:
		ipaddress.ip_address(sys.argv[2]) # Checks if command argument is a valid IP
		
	except ValueError:
		print("Command line error. Third argument must only be an IP address. {} is not valid".format(sys.argv[1]))
		sys.exit()
		
	list_of_ports = [] #Accumulate ports to randomize
	
	if re.search("-", sys.argv[3]):
		ports_in_range = sys.argv[3].split("-")
		#Tests if 4th command argument for integer port number is valid input
		try:
			num_of_ports_scanned = int(ports_in_range[1]) - int(ports_in_range[0])
			ports_scanned = int(ports_in_range[0])
		except:
			print("Command line error. Fourth argument must be a valid integer range.")
			sys.exit()
		# Accumulates ports
		for i in range(num_of_ports_scanned+1):
			list_of_ports.append(ports_scanned)
			ports_scanned += 1
		
		
		#print(num_of_ports_scannned)
		#dst_port = int(ports_in_range[0])
		#print(ports_in_range)
		ports = True
		
	else:
		num_of_ports_scanned = 1
		#Test if 4th command argument for integer port number is valid input
		try: 
			dst_port = int(sys.argv[3])
		except:
			print("Command line error. Fourth argument must be a valid integer.")
			sys.exit()
		
	random.shuffle(list_of_ports)
	print(list_of_ports)
	
	if sys.argv[1] == "T":
		if (ports):
			num_of_ports_scanned+=1
		for i in range(num_of_ports_scanned):
			print("Starting TCP Scans...")
			port_src = r.randint(1025,65534)
			ip_dst = sys.argv[2]
			if (ports):
				dst_port = list_of_ports[i]
			#dst_port = list_of_ports[i]
			#print(dst_port)
			ports_scan_rsp = sr1(IP(dst=ip_dst)/TCP(sport=port_src,dport=dst_port,flags="S"),verbose=0,timeout=1)
			if(ports_scan_rsp is None):
				print("Port: [" + str(dst_port) + "]" "\t\tStatus: filtered" "\t\tReason: No response")
				#print ("port filtered (reply is NONE)")
			elif(ports_scan_rsp.haslayer(TCP)):
				if(ports_scan_rsp.getlayer(TCP).flags == 0x12): # RECIEVED SYN-ACK PACKET (PORT OPENED)
					send_rst = sr(IP(dst=ip_dst)/TCP(sport=port_src,dport=dst_port,flags="R"),verbose=0,timeout=1)
					print("Port: [" + str(dst_port) + "]" "\t\tStatus: opened" "\t\tReason: Received TCP SYN-ACK")
			elif(ports_scan_rsp.getlayer(TCP).flags == 0x14): # RECIEVED RST PACKET (PORT CLOSED)
				print("Port: [" + str(dst_port) + "]" "\t\tStatus: closed" "\t\tReason: Received TCP RST")
				#print("port closed (RST recieved)")
			elif(ports_scan_rsp.haslayer(ICMP)):
				if(int(ports_scan_rsp.getlayer(ICMP).type)==3): # RECIEVED DST PORT UNREACHABLE MESSAGE
					print("Port: [" + str(dst_port) + "]" "\t\tStatus: filtered" "\t\tReason: Received ICMP Port Unreachable")
					#print("port filtered (DST port unreachable)")
		
		
	elif sys.argv[1] == "U":
		if (ports):
			num_of_ports_scanned+=1
		for i in range(num_of_ports_scanned):
			print("Starting UDP Scans...")
			port_src = r.randint(1025,65534)
			ip_dst = sys.argv[2]
			if (ports):
				dst_port = list_of_ports[i]
			#Send UDP packet; set timeout to 5 for latency host unreachable responses
			scanning_rsp = sr1(IP(dst=ip_dst)/UDP(sport=port_src, dport=dst_port), timeout=1, verbose=0) 
			if (scanning_rsp is None):
				print("Port: [" + str(dst_port) + "]" "\t\tStatus: Opened|Filtered" "\t\tReason: No Response")
			elif scanning_rsp.haslayer(ICMP) and scanning_rsp.code == 3: #ICMP port unreachable
				print("Port: [" + str(dst_port) + "]" "\t\tStatus: Closed" "\t\tReason: Received ICMP Port Unreachable")
			elif scanning_rsp.haslayer(UDP):
				print("Port: [" + str(dst_port) + "]" "\t\tStatus: Opened")
			if (ports):
				dst_port += 1
	else:
		print("Invalid transport layer protocol. The third argument must be 'T' or 'U'")
		
main()

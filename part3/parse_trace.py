import collections
import dpkt

websites = []
tcp_conns = {}
syn_packets = 0

def is_syn(packet):
    return "Flags [S]" in packet

def is_tcp(packet):
    return "proto TCP" in packet

def get_ip_port(address):
    address_split = address.split(".")
    if len(address_split) == 5:
        return ".".join(address_split[:4]), address_split[4]
    return address, "-1"
   
def get_ack(packet):
    ack_start = packet.find("ack ") + 4
    return packet[ack_start:packet.find(",", ack_start)]

def get_seqno(packet):
    seqno_start = packet.find("seq ") + 4
    v1 = packet.find(":", seqno_start)
    v2 = packet.find(",", seqno_start)
    if v1 > 0 and v1 < v2:
        return packet[v1+1:v2]
    return str(int(packet[seqno_start:v2]) + 1)

def analyze_packet(packet, syn_map, syn_flood):
    if packet[:2] != "IP":
        return
    packet_split = packet[packet.find("src_dst") + 13:].split(" ")
    src_ip, src_port = get_ip_port(packet_split[0])

    dest_ip, dest_port = get_ip_port(packet_split[2][:-1])  

    if dest_port == "80" and src_ip == "10.30.22.101" and dest_ip not in websites:
        websites.append(dest_ip)

    if is_syn(packet):
        if src_ip not in syn_map:
            syn_map[src_ip] = set()
        syn_map[src_ip].add((dest_ip, dest_port))

        if src_ip not in syn_flood:
            syn_flood[src_ip] = collections.defaultdict(lambda: 0)
        syn_flood[src_ip][dest_ip] += 1

    if is_tcp(packet):
        if src_ip == '10.30.22.101' and "seq " in packet:
            trip = (dest_ip, dest_port, src_port)
            if trip not in tcp_conns:
                tcp_conns[trip] = []
            seqno = get_seqno(packet)
            if (seqno, True) in tcp_conns[trip]:
                print " found a weird one!!", packet
            else:
                tcp_conns[trip].append((seqno, False))
        if dest_ip == '10.30.22.101' and "ack " in packet:
            trip = (src_ip, src_port, dest_port)
            seqno = get_ack(packet)
            if trip in tcp_conns:
                if (seqno, False) in tcp_conns[trip]:
                    tcp_conns[trip].remove((seqno, False))
                    tcp_conns[trip].append((seqno, True))

def read_packets(file):
    f = open(file)
    curr_packet = ""
    packets = []
    for line in iter(f):
        if line[:2] == "IP" or line[:2] == "ARP":
            packets.append(curr_packet)
            curr_packet = ""
        else:
            curr_packet += ", src_dst: "
        curr_packet += line
    f.close()
    return packets

packets = read_packets('trace.txt')
syn_map = {} # src_ip -> set of (dest_ip, dest_port)
syn_flood = {} # src_ip -> (dest_ip->count)
print(len(packets))
for packet in packets:
    analyze_packet(packet, syn_map, syn_flood)
#print websites
for src_ip in syn_map:
    print("{}: {}".format(src_ip, len(syn_map[src_ip])))

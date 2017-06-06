import dpkt

websites = []

def get_ip_port(address):
    address_split = address.split(".")
    if len(address_split) == 5:
        return ".".join(address_split[:4]), address_split[4][:-1]
    return address, "-1"
    

def analyze_packet(packet):
    if packet[:2] != "IP":
        return
    packet_split = packet[packet.find("src_dst") + 13:].split(" ")
    src_ip, src_port = get_ip_port(packet_split[0])

    dest_ip, dest_port = get_ip_port(packet_split[2])  

    if dest_port == "80" and src_ip == "10.30.22.101" and dest_ip not in websites:
        websites.append(dest_ip)

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
for packet in packets:
    analyze_packet(packet)
print websites

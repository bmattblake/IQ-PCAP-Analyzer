import os
import sys
from argparse import ArgumentParser
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP

'''YOU MAY NEED TO INSTALL THE DEVLOPER VERSION OF SCAPY FOR THIS PRGRAM TO WORK'''

class PktDirection:
    undefined = 0
    client_to_server = 1
    server_to_client = 2

def validate_ip(ip_address):
    octets = ip_address.split(".")
    if len(octets) != 4:
        # String is not an ip address if there are not 4 octets
        return False
    for num in octets:
        if not num.isdigit():
            # String is not an ip address if there are non-digits in it
            return False
        n = int(num)
        if n < 0 or n > 255:
            # String is not an ip address if an octet is less than 0 or greater than 255
            return False
    return True

def validate_port(port):
    if not port.isdigit():
        # String is not a port number if it contains non-digits
        return False
    p = int(port)
    if p < 0 or p > 65535:
        # Port numbers are not less than 0 or higher than 65,535
        return False
    return True

def parse_pcap(file_name):
    print(f"Parsing {file_name}...")
    global pkt_list 
    pkt_list = rdpcap(file_name)
    global pkt_count
    pkt_count = len(pkt_list)

    if args.connection != None:
        track_connection(file_name)
        return
    
    intr_pkt_count = 0
    for pkt in pkt_list:
        if "type" not in pkt.fields:
            # LLC frames will have "len" instead of "type". These are not important.
            continue
        
        if pkt.type != 0x0800:
            # Ignore non-IPv4 packets
            continue
        
        ip_hdr = pkt[IP]
        if ip_hdr.proto != 6 and args.t:
            # Ignore non-TCP packets
            continue
    
        intr_pkt_count += 1
        
    print(f"{file_name} contains {pkt_count} packets ({intr_pkt_count} intersting)")
    
def track_connection(file_name):
    client, server = args.connection[0], args.connection[1]
    (client_ip, client_port) = client.split(":")
    (server_ip, server_port) = server.split(":")
    
    # Check if user input contains valid ip addresses and port numbers
    if not validate_ip(client_ip):
        print(f"\"{client_ip}\" is not a valid ip addresss.")
        sys.exit(1)
    if not validate_ip(server_ip):
        print(f"\"{server_ip}\" is not a valid ip addresss.")
        sys.exit(1)
    if not validate_port(client_port):
        print(f"\"{client_port}\" is not a valid port number.")
        sys.exit(1)
    if not validate_port(server_port):
        print(f"\"{server_port}\" is not a valid port number.")
        sys.exit(1) 
    
    serv_seq_offset = None
    clnt_seq_offset = None
    count = 0
    conn_pkt_count = 0
    print(f"TCP session between {client_ip} and {server_ip}:")
    print("------------------------------------------------------------------------------------------------------------------------------")
    for pkt in pkt_list:
        count += 1
        ip_hdr = pkt[IP]
        if ip_hdr.proto != 6:
            # Ignore non-TCP packets
            continue
        
        direction = PktDirection.undefined
        
        # Filter out packets that do not match the user's input.
        tcp_hdr = ip_hdr[TCP]
        if ip_hdr.src == client_ip:
            if tcp_hdr.sport != int(client_port):
                continue
            if ip_hdr.dst != server_ip:
                continue
            if tcp_hdr.dport != int(server_port):
                continue
            direction = PktDirection.client_to_server
        elif ip_hdr.src == server_ip: 
            if tcp_hdr.sport != int(server_port):
                continue
            if ip_hdr.dst != client_ip:
                continue
            if tcp_hdr.dport != int(client_port):
                continue
            direction = PktDirection.server_to_client
        else:
            continue
        
        conn_pkt_count += 1
        if conn_pkt_count == 1:
            first_pkt = pkt
            first_pkt_time = datetime.fromtimestamp(int(first_pkt.time))
            first_pkt_num = int(count)
        
        last_pkt = pkt
        last_pkt_time = datetime.fromtimestamp(int(last_pkt.time))
        last_pkt_num = int(count)
        conn_pkt_count += 1
        
        # Calculate packet metadata
        tcp_payload_len = ip_hdr.len - (ip_hdr.ihl * 4) - (tcp_hdr.dataofs * 4)
        if direction == PktDirection.client_to_server:
                if clnt_seq_offset is None:
                    clnt_seq_offset = tcp_hdr.seq
                relative_offset_seq = tcp_hdr.seq - clnt_seq_offset
        else:
            assert direction == PktDirection.server_to_client
            if serv_seq_offset == None:
                serv_seq_offset = tcp_hdr.seq
            relative_offset_seq = tcp_hdr.seq - serv_seq_offset

        # If  TCP header has "A" as an attribute, it must carry an ack number.
        if "A" not in str(tcp_hdr.flags):
            relative_offset_ack = 0
        else:
            if direction == PktDirection.client_to_server:
                serv_seq_offset = tcp_hdr.seq
                relative_offset_ack = tcp_hdr.ack - serv_seq_offset
            else:
                relative_offset_ack = tcp_hdr.ack - clnt_seq_offset
        
        # Print resuls.
        fmt = "{num:>6s}  {time:<20s} {client_ip:<15s}  {arrow}  {server_ip:>15s}  flag={flag:<3s}  seq={seq:<9d}  \
        ack={ack:<9d}  len={len:<6d}"
        if direction == PktDirection.client_to_server:
            arr = "-->"
        else:
            arr = "<--"
        print(fmt.format(arrow = arr,
                         num = f"{last_pkt_num}",
                         time = str(last_pkt_time),
                         client_ip = client_ip,
                         server_ip = server_ip,
                         flag = str(tcp_hdr.flags),
                         seq = relative_offset_seq,
                         ack = relative_offset_ack,
                         len = tcp_payload_len))
        
    # Print summary.
    if conn_pkt_count != 0:
        perc = round(conn_pkt_count / pkt_count, 4)
        print(f"\n{conn_pkt_count}/{pkt_count} ({perc}%) packets in this session between {client_ip} and {server_ip}:")
        print(f"First packet in connection: Packet #{first_pkt_num} {first_pkt_time}" )
        print(f"Final packet in connection: Packet #{last_pkt_num} {last_pkt_time}" )
    else:
        print(f"TCP Connection between {args.connection[0]} and {args.connection[1]} not found.")
        print("Ensure that the IP addresses and port numbers provided are correct.")
    
if __name__ == "__main__":
    parser = ArgumentParser(description = "PCAP reader")
    parser.add_argument("pcap", metavar = "pycap.py [PCAP FILE NAME]",
                        help = "Specify the pcap file to analyze")
    parser.add_argument("-c", "--connection", nargs = 2,
                        metavar = "[IP ADDRESS]:[PORT]",
                        help = "Track a connection between two devices.")
    parser.add_argument("-t", help = "Only include TCP packets", action = "store_true")
    parser.add_argument("-u", help = "Only include UDP packets", action = "store_true")
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print(f"\"{file_name}\" does not exist")
        sys.exit(-1)
    file_ext = file_name.split(".")[-1]
    if file_ext != "pcap":
        print(f"\"{file_name}\" is an unsupported file type.")
        sys.exit(-1)

    parse_pcap(file_name)
    sys.exit(0)

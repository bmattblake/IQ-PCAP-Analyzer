import sys
import time
from protocols import Protocol
from pktdirection import PktDirection
from datetime import datetime
from scapy.all import rdpcap
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
from scapy.packet import Raw



class PcapHandler:
    
    def __init__(self) -> None:
        pass
    
    def add_arguments(self, args):
        self.validate_args(args)
        self.args = args
    
    def loadbar(self, iteration, total, prefix="", suffix="", decimals=2, legnth=100, fill=">"):
        percent = round(iteration/float(total), decimals)
        filled_length = int(legnth * iteration // total)
        bar = fill * filled_length + "-" * (legnth - filled_length)
        print(f"\r{prefix} |{bar}| {percent}% {suffix}", end="\r")
        if iteration == total:
            print()
    
    def validate_args(self, args):
       if args.t and args.u:
            print("Argumnets: \n" +
                  "Only include TCP packets (-t)\n" + 
                  "Only include UDP packets (-u)\n" +
                  "Cannot be true at the same time."
                  )
            sys.exit(-1)
            

    def validate_ip(self, ip_address):
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

    def validate_port(self, port):
        if not port.isdigit():
            # String is not a port number if it contains non-digits
            return False
        p = int(port)
        if p < 0 or p > 65535:
            # Port numbers are not less than 0 or higher than 65,535
            return False
        return True

    def parse_pcap(self, file_name):
        pkt_dict = {
            "ARP": [],
            "IPv4": {"TCP": dict(),
                     "UDP": dict(),
                     "ICMP": []}
        }
        print(f"Parsing {file_name}...")
        
        self.pkt_list = rdpcap(file_name)
        self.pkt_count = len(self.pkt_list)

        if self.args.connection != None:
            self.track_connection(file_name)
            return
        
        
        intr_pkt_count = 0
        count = 0
        frag_pkts = 0
        for pkt in self.pkt_list:
            
            if "type" not in pkt.fields:
                # LLC frames will have "len" instead of "type". These are not important.
                continue
            
            if pkt.type != Protocol.IPv4:
                # Ignore non-IPv4 packets
                if pkt.type == Protocol.ARP and self.args.a:          
                    pkt_dict["ARP"].append(pkt)
                    intr_pkt_count += 1
                elif pkt.type == Protocol.IPv6:
                    pass
                continue
            
            ip_hdr = pkt[IP]
            if ip_hdr.proto != Protocol.TCP and self.args.t:
                # Ignore non-TCP packets if "-t" flag is used
                continue
            
            if ip_hdr.proto != Protocol.ICMP and self.args.u:
                # Ignore non-UDP packets if "-u" flag is used
                continue 
        
            
            tcp_protos_observed = set()
            if ip_hdr.proto == Protocol.TCP:
                tcp_hdr = ip_hdr[TCP]
                sprotcol = Protocol().get_protocol(tcp_hdr.sport)
                dprotcol = Protocol().get_protocol(tcp_hdr.dport)
                
                if tcp_hdr.haslayer(HTTP):
                
                    if type(tcp_hdr[HTTP].payload) == Raw:
                        # if payload is raw, then this packe tis a segment. 
                        # It will be reonstructed later, so no need to count the segments.
                        continue
                    if sprotcol != None:
                        if sprotcol not in pkt_dict["IPv4"]["TCP"].keys():
                            pkt_dict["IPv4"]["TCP"][sprotcol] = []
                        pkt_dict["IPv4"]["TCP"][sprotcol].append(tcp_hdr)
                    elif dprotcol != None:
                        if dprotcol not in pkt_dict["IPv4"]["TCP"].keys():
                            pkt_dict["IPv4"]["TCP"][dprotcol] = []
                        pkt_dict["IPv4"]["TCP"][dprotcol].append(tcp_hdr)
                    
                        
            if ip_hdr.proto == Protocol.ICMP:
                try:
                    icmp_hdr = ip_hdr[ICMP]
                    pkt_dict["IPv4"]["ICMP"].append(icmp_hdr)
                except IndexError: # IndexError is raised when packet is fragmented
                    frag_pkts += 1
            
                
            intr_pkt_count += 1
            count += 1
            #loadbar(count, pkt_count, prefix="Progress:", suffix="Complete",)
        
        # Print results
        if frag_pkts > 0:
            print(f"{file_name} contains {self.pkt_count} packets ({frag_pkts} fragmented)")
        else:        
            print(f"{file_name} contains {self.pkt_count} packets ({intr_pkt_count} intersting)")
        
        
        # print breakdown (Layer 2)
        ARP_count = len(pkt_dict['ARP'])
        if ARP_count > 0:
            print(f"{ARP_count} ARP ethernet frames")
        
        # print breakdown (Layer 4)
        for proto in pkt_dict["IPv4"].items():
            proto = proto[0]
            if len(pkt_dict["IPv4"][proto]) > 0:
                print(f"{len(pkt_dict['IPv4'][proto])} {proto} packets")
         
        # print breakdown (Layer 7)
        for proto in pkt_dict["IPv4"]["TCP"].items():
            proto = proto[0]
            if len(pkt_dict["IPv4"]["TCP"][proto]) > 0:
                print(f"{len(pkt_dict['IPv4']['TCP'][proto])} {proto} packets")
            
    def track_connection(self, file_name):
        client, server = self.args.connection[0], self.args.connection[1]
        (client_ip, client_port) = client.split(":")
        (server_ip, server_port) = server.split(":")
        
        # Check if user input contains valid ip addresses and port numbers
        if not self.validate_ip(client_ip):
            print(f"\"{client_ip}\" is not a valid ip addresss.")
            sys.exit(1)
        if not self.validate_ip(server_ip):
            print(f"\"{server_ip}\" is not a valid ip addresss.")
            sys.exit(1)
        if not self.validate_port(client_port):
            print(f"\"{client_port}\" is not a valid port number.")
            sys.exit(1)
        if not self.validate_port(server_port):
            print(f"\"{server_port}\" is not a valid port number.")
            sys.exit(1) 
        
        serv_seq_offset = None
        clnt_seq_offset = None
        count = 0
        conn_pkt_count = 0
        print(f"TCP session between {client_ip} and {server_ip}:")
        print("------------------------------------------------------------------------------------------------------------------------------")
        for pkt in self.pkt_list:
            if pkt.type == Protocol.ARP:
                continue
            
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
            perc = round(conn_pkt_count / self.pkt_count, 4)
            print(f"\n{conn_pkt_count}/{self.pkt_count} ({perc}%) packets in this session between {client_ip} and {server_ip}:")
            print(f"First packet in connection: Packet #{first_pkt_num} {first_pkt_time}" )
            print(f"Final packet in connection: Packet #{last_pkt_num} {last_pkt_time}" )
        else:
            print(f"TCP Connection between {self.args.connection[0]} and {self.args.connection[1]} not found.")
            print("Ensure that the IP addresses and port numbers provided are correct.")
        
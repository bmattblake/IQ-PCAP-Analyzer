import os
import sys
from pcaphandler import PcapHandler
from argparse import ArgumentParser


'''YOU MAY NEED TO INSTALL THE DEVLOPER VERSION OF SCAPY FOR THIS PRGRAM TO WORK'''

if __name__ == "__main__":
    parser = ArgumentParser(description = "PCAP reader")
    parser.add_argument("pcap", metavar="iqpcap.py [path/to/pcap/file]",
                        help="Specify the cap/pcap file to analyze")
    parser.add_argument("-c", "--connection", nargs = 2,
                        metavar="[IP ADDRESS]:[PORT]",
                        help="Track a connection between two devices.")
    parser.add_argument("-t", help="Only include TCP packets", action="store_true")
    parser.add_argument("-u", help="Only include UDP packets", action="store_true")
    parser.add_argument("-a", help="Include ARP ethernet frames", action="store_true")
    
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print(f"\"{file_name}\" does not exist")
        sys.exit(-1)
    file_ext = file_name.split(".")[-1]
    if file_ext not in ["pcap", "cap"]:
        print(f"\"{file_name}\" is an unsupported file type. Only .cap and .pcap files are supported")
        sys.exit(-1)

    handler = PcapHandler()
    handler.add_arguments(args)
    handler.parse_pcap(file_name)
    sys.exit(0)

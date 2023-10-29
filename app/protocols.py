class Protocol:
    
    # Layer 2
    ARP = 0x0806
    
    # Layer 3
    IPv4 = 0x0800
    IPv6 = 0x86dd
    ICMP = 1
    
    # Layer 4
    TCP = 6
    UDP = 17
    # Layer 7
    HTTP = 80
    HTTPS = 443  
      
    def get_protocol(self, port_mubner):
        tcp_ports = {
                    1: "TCP Port Service Multiplexer",
                    7: "Echo",
                    9: "Discard",
                    13: "Daytime", # Responds with the current time of day
                    17: "QOTD", # Quote of the Day
                    19: "Character Generator",
                    20: "FTP - Data",
                    21: "FTP - Control",
                    22: "SSH", # Secure Shell
                    23: "Telnet",
                    25: "SMTP", # Simple Mail Transfer Protocol
                    37: "Time",
                    42: "WINS", # Name Server
                    43: "WHOIS",
                    53: "DNS", # Domain Name System
                    67: "DHCP", # Dynamic Host Configuration Protocol
                    68: "DHCP - Client",
                    69: "TFTP", # Trivial File Transfer Protocol 
                    70: "Gopher",
                    79: "Finger",
                    80: "HTTP", # Hypertext Transfer Protocol
                    88: "Kerberos",
                    110: "POP3", # Post Office Protocol version 3
                    111: "ONC RPC (Sun RPC)",
                    113: "Ident", # Authentication Service
                    119: "NNTP", # Network News Transfer Protocol
                    123: "NTP", # Network Time Protocol
                    137: "NetBIOS Name Service",
                    138: "NetBIOS Datagram Service",
                    139: "NetBIOS Session Service",
                    143: "IMAP", # Internet Message Access Protocol
                    161: "SNMP", # Simple Network Management Protocol
                    179: "BGP", # Border Gateway Protocol
                    194: "IRC", # Internet Relay Chat
                    389: "LDAP", # Lightweight Directory Access Protocol
                    443: "HTTPS", # HTTP Secure
                    445: "Microsoft-DS", # Microsoft Directory Services (AD)
                    514: "Syslog",
                    515: "LPD", # Line Printer Daemon 
                    543: "Kerberos Login",
                    554: "RTSP", # Real Time Streaming Protocol
                    587: "SMTP Submission",
                    636: "LDAPS", # LDAP over TLS/SSL
                    993: "IMAPS", # IMAP over TLS/SSL
                    995: "POP3S", # POP3 over TLS/SSL
                    1080: "Socks Proxy",
                    3306: "MySQL Database",
                    3389: "RDP", # Remote Desktop Protocol 
                    5432: "PostgreSQL Database",
                    6660: "IRC", # Internet Relay Chat (IRC) - Unreal IRCd
                    6661: "IRC", # Internet Relay Chat (IRC) - Unreal IRCd,
                    6881: "BitTorrent",
                }
        
        try:
            return tcp_ports[port_mubner]
        except KeyError:
            return None

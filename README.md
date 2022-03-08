# Pcap-File-Analyzer

Note that this program is in its very early stages.

**Description:**

This is a basic command-line tool that has the ability to analyze pcap files.

It can track a specified connection within a pcap file based on the client and server ip address and port number

---

**Syntax:**

```python pycap.py [FILE_NAME].pcap -c [CLIENT_IP]:[PORT] [SERVER_IP]:[PORT]```

**Sample Output:**
```
$ python pycap.py sample.pcap -c 192.168.0.4:3905 192.168.0.1:443
Parsing sample.pcap...
TCP session between 192.168.0.4 and 192.168.0.1:
------------------------------------------------------------------------------------------------------------------------------
   328  2022-03-08 11:45:44  192.168.0.4      -->      192.168.0.1  flag=S    seq=0                  ack=0          len=0
   333  2022-03-08 11:45:44  192.168.0.4      <--      192.168.0.1  flag=SA   seq=0                  ack=1          len=0
   339  2022-03-08 11:45:44  192.168.0.4      -->      192.168.0.1  flag=A    seq=1                  ack=1763305691  len=0
   340  2022-03-08 11:45:44  192.168.0.4      -->      192.168.0.1  flag=PA   seq=1                  ack=1763305691  len=517
   342  2022-03-08 11:45:44  192.168.0.4      <--      192.168.0.1  flag=A    seq=1763305691          ack=518        len=0
   464  2022-03-08 11:45:44  192.168.0.4      <--      192.168.0.1  flag=PA   seq=1763305691          ack=518        len=152
   468  2022-03-08 11:45:44  192.168.0.4      -->      192.168.0.1  flag=PA   seq=518                ack=1763305326  len=7
   472  2022-03-08 11:45:44  192.168.0.4      -->      192.168.0.1  flag=FA   seq=525                ack=1763305319  len=0
   483  2022-03-08 11:45:44  192.168.0.4      <--      192.168.0.1  flag=A    seq=1763305319          ack=525        len=0
   517  2022-03-08 11:45:45  192.168.0.4      <--      192.168.0.1  flag=A    seq=1763305319          ack=526        len=0
   720  2022-03-08 11:45:45  192.168.0.4      <--      192.168.0.1  flag=FA   seq=1763305319          ack=526        len=0
   723  2022-03-08 11:45:45  192.168.0.4      -->      192.168.0.1  flag=A    seq=526                ack=1763305319  len=0

24/2169 (0.0111%) packets sent between client and server:
First packet in connection: Packet #328 2022-03-08 11:45:44
Final packet in connection: Packet #723 2022-03-08 11:45:45
```

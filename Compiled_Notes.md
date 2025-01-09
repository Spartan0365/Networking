# Networking
Notes for the Networking Course

http://networking-ctfd-1.server.vta:8000/login
https://net.cybbh.io/public/networking/latest/index.html
https://miro.com/app/board/o9J_klSqCSY=/?share_link_id=16133753693

#START 
=================

#TAGS:
====================================================================================================================================================================================

Network Access:
#header# , #ARP Types# , #Traceroute# #Firewalking# , #SSH#, #SSH Files# , #tcpdump# , #TTL# in ipv4(6) , #TCP DF (Don't Fragment) bit# , #TCP source port# , #Filter for UDP and TCP Packets# ,
#TCP Flags Examples FOR BPFs# , #Wireshark BPFs# , #Specific IP ID# , #P0F Signature Database#, 

Socket Programming:
#Python#, #Python String#, #Python Integer#, #Python Built In Functions# , #Python Built-In Methods#, #Python How Imports Work#, #Network Programming with Python3#, #The socket.socket Function#
#Hex Encoding and Decoding#, #Python Hex Encoding#, #Base64 Encoding and Decoding#, #Python Base64 Encoding#, #Stream Socket Sender Demo#
#Getting a Message to a remote team Utilizing a specific host (BLUE_DMZ_HOST-1) using STREAM SOCKET#
#Getting a Message to a remote team utilizing the specified host (INTERNET_HOST) using DATAGRAM SOCKET#
#Modify ipraw.py #, #modify tcpraw.py#

Network Discovery:
#Passive External Discovery# -  #Ways to Look up DNS information#, 
#Active External Discovery# - #Ping# , #NMAP Defaults#, #NMAP syntax examples# , #Traceroute - Firewalking# , #Netcat - Horizontal Scanning# , #Netcat - Vertical Scanning#
                              #TCP SCAN SCRIPT# , #UDP SCAN SCRIPT# , #BANNER GRABBING# , #CURL and WGET interface with webservers#
#Passive Internal Discovery# - #Packet Sniffers# , #IP Configuration# , #DNS configuration# , #ARP Cache# , #Network connections# , #Services File# , #OS Information# , #Running Processes# , #Command path# , #Routing Table#
                                #File search# , #SSH Config#
#Active Internal Discovery# - #ARP Scanning# , #Ping Scanning# , #DEV TCP Banner Grab# , #DEV TCP Scanning#  , 
#Network Forensics - Mapping#
#CTFs Network Reconnaissance:#

 File Transfer And Redirection
#Trivial File Transfer Protocol# , #File Transfer Protocol# , #File Transfer Protocol Secure# , #Secure File Transfer Protocol# , #Secure Copy Protocol# , #SCP Syntax# , #SCP Syntax w/ alternate SSHD# , #SCP Syntax through a tunnel# , 
#Dynamic Port forward#

SSH Tunneling and Covert Channels
    #6 in 4# ,  #4 to 6# , #Teredo Tunneling# ,   #ISATAP# , #How to Detect Covert Channels# , #Detecting Covert Channels with ICMP# , #Detecting Covert Channels with HTTP#
    #Secure Shell (SSH Tunneling)# ,  #SSH First Connect# , #SSH Re-Connect# , #SSH Host key Changed# , #SSH Key Change Fix# , #SSH Port Forwarding# , 
    #Local Port Forwarding# , #Local Port Forward to localhost of server# , #Local Port Forward to remote target via server# , #Forward through Tunnel# , 
    #Dynamic Port Forwarding# , #SSH Dynamic Port Forwarding 1-Step# ,#SSH Dynamic Port Forwarding 2-Step# , #Remote Port Forwarding# ,  #Remote Port Forwarding from localhost of client# , 
    #Remote Port Forwarding to remote target via client# , #Bridging Local and Remote Port Forwarding#


=================

RED float info : 10.50.26.58 , Your Network Number is 1 (Given by Instructor) , Credentials: net1_studentX:passwordX , X is your student number : ssh net1_student1@10.50.26.58 (password is: password1)
BLUE Float info - ssh student@10.50.30.41 -X (connect through remmina) 
            Command: ssh student@10.50.30.41 -X   (password: password)
            
Red Boundry Router , Hostname: unk, IP: 172.16.120.1, Ports: 22, Username: vyos, Password: password

DAY 1
==================================================================

A 'float' must be used to get to the private net. This 'float' is not inside the network. Once inside the network, you won't be using the float anymore. 
Float info - ssh student@10.50.30.41 -X (connect through remmina)

==================
= Network Access =
==================


====================
= Network Layer FG =
====================


============================
= Transport to Application =
============================


==================================
=========     Day 2    ===========
==================================

TCP Dump Examples for BPFs from Challenges:
==========================

Filtering for #TCP Flags Examples FOR BPFs#
    "tcp[13] = 20 || tcp[13] = 17" (this will filter for all packets with the ACK/RST or ACK/FIN flags set).
    sudo tcpdump -n "tcp[13] = 20 || tcp[13] = 17" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l
    "tcp[13]=2" (this will filer for initial packets from a client trying to initiate a connection)
    "tcp[13]=18" (this will filter for response packets from a server listening on an open TCP port)
    "tcp[13]=4" (this will filter for packets from a server with closed tcp ports. The reset (4) bit indicates the port was not open.)
    "tcp[2:2]<1024||udp[2:2]<1024" (this will filter for all tcp and udp packets sent to the well known ports)
    "tcp[0:2]=80||tcp[2:2]=80" (this will filter for all http traffic)
    "tcp[0:2]=23||tcp[2:2]=23" (this will filter for all telnet traffic)
    "ether[12:2]=0x0806" (this will filter for all ARP traffic--remember, ARP is filtered for through the ethernet header)"
    "ip[6] & 128 != 0" or "ip[6] & 128 = 128" (this will filter to capture if the "evil bit" is set, the IP header is used here)
    "ip[9]=0x10" (This will filter for the chaos protocol, which can be found filtered through the ipv4 (ip) filter).
    "ip[1]>>2=37" (this will filter for packets with the DSCP field of 37. The '>>2' is necessary as it indicates the 2 bit shift to the right, which is required for the DSCP field).
    "(ip[9]=0x01 || ip[9]=0x11) && ip[8]=1" (This will will look for potential traceroutes betweeen linux and windows systems (and others), AND a TTL of 1 (which is the beginning of each             traceroute, otherwise it would give us much more results for each recorded (incremeneted) Time to live value)) 
    "tcp[13]&32=0&&tcp[18:2]!=0" (this will filter for all packets where the urg value is not set (32) and the urg pointer HAS a value (!=0))
    "ip[16:4]=0x0a0a0a0a && tcp[13]=0" (this will first filter for the IP address 10.10.10.10 (in hex, it is 0x0a0a0a0a) and where all tcp flags are null (basically, no TCP flags), which is         0, and the reason why it is tcp[13]=0"
    "ether[12:4] & 0xffff0fff = 0x81000001 && ether[16:4] & 0xffff0fff = 0x8100000a" (this will filter for #VLAN Hopping#. The 0xffff0fff isn't too important to understand, it essentially           identifies the area you're searching through, though. the 0x81000001 indicates the position of the VLAN (VLAN '1'), and that's why there's a 1 at the end of it. Likewise for the               0x8100000a, which is VLAN 10 (represented by the 'a' in hex). This essentially filters for hopping between these two VLANs).
    
Write Shark filters for BPFs. #Wireshark BPFs#
    Capture filters - used to specify which packets should be saved to disk while capturing.
    Display filters - allow you to change the view of what packets are displayed of those that are captured.

use filter: (example)
  host 172.16.82.106 && (tcp0:2]==80 or tcp 2:2]=80)

Filter for #Specific IP ID#
    'ip[4:2] == 213' (will filter for the specific ip id)
    sudo tcpdump -n " ip[4:2] == 213" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

Filter for #VLAN TAG#
    "ether[12:2]==0x8100" (filters for specific VLAN TAG)
    sudo tcpdump -n "ether[12:2]==0x8100" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

Wireshark can use most primitives and/or BPFs.

Useful Wireshark menu:
  Protocol Hierarchy

To decrypt traffic in Wireshark
  Menu → Edit → Preference → Protocols → SSL

How to filter for for ports across TCP and UDP
  Example:
    "tcp[2:2]=53 || tcp[0:2]=53 || udp[2:2]=53 || udp[0:2]=53" (this one will filter for DNS for both UDP and TCP).
    sudo tcpdump -n "tcp[2:2]=53 || tcp[0:2]=53 || udp[2:2]=53 || udp[0:2]=53" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l


P0F Signature Database #P0F Signature Database#, used for passive fingerprinting. Basically looking for handshakes/exchanges. (this is not part of wireshark or tcpdump)
  Learn as much as you can about P0f because it will be on the final exam, could be 5 questions. 
  less /etc/p0f/p0f.fp
  p0f -h
  p0f -i eth0
  p0f -r capture.pcap
  p0f -r wget.pcap -o /var/log/p0f.log
  cat /var/log/p0f.log | grep {expression}



Socket Programming
======================
======  Day 3  =======
======================

The point of this lesson is to understand TCP Stream, UDP Datagram, and RAW sockets and their vital role as elements for cyber security professionals due to their rolel in network communication protocols. TCP enables reliable, connection-oriented data transmission. UDP Datagram provides lightweight, connectionless communication. RAW sockets provide low-level access to network interfaces. Mastering these allows professionals to analyze network traffic, detect anomalies and develop robust security measures to safeguard against a wide range of cyber threats to enhance the overall resilience of organizational networks. 

Socket Types
  Stream Sockets - Connection oriented and sequenced; methods for connection establishment and tear-down. Used with TCP, SCTP, and Bluetooth.
  Datagram Sockets - Connectionless; designed for quickly sending and receiving data. Used with UDP.
  RAW Sockets - Direct sending and receiving of IP packets without automatic protocol-specific formatting.

User Space vs. Kernel Space Sockets
   User Space Sockets
      Stream Sockets
      Datagram Sockets
   Kernel Space Sockets
      RAW Sockets

Socket Creation and Privilege Level
  User Space Sockets - The most common sockets that do not require elevated privileges to perform actions on behalf of user applications.
  Kernel Space Sockets - Attempts to access hardware directly on behalf of a user application to either prevent encapsulation/decapsulation or to create packets from scratch, which requires elevated privileges.

Userspace applications/sockets:
    Using tcpdump or wireshark to read a file
    Using nmap with no switches
    Using netcat to connect to a listener
    Using netcat to create a listener above the well known port range (1024+)
    Using /dev/tcp or /dev/udp to transmit data

Kernel Space Applications/Sockets
    Using tcpdump or wireshark to capture packets on the wire
    Using nmap for OS identification or to set specific flags when scanning
    Using netcat to create a listener in the well known port range (0 - 1023)

Kernel Space Applications/Sockets
    Using Scapy to craft or modify a packet for transmission
    Using Python to craft or modify RAW Sockets for transmission
    Network devices using routing protocols such as OSPF
    Any Traffic without Transport Header (ICMP)

Understanding Python Terminology #Python#
    Libraries (Standard Python Library) ; (prebuilt storage locations to grab modules from, and these modules have functions)
        Modules (_import module)
            Functions (module.function)
            Exceptions (try:)
            Constants (AF_INET)
            Objects ()
            List [] vs Tuple ()

#Python String# String (example):
    my_string = "Hello World"
    Bytes-like-object
      message = b"Hello World"

#Python Integer# Integer (examples):
    int = 1234
    float = 3.14
    hex = 0x45

#Python Built In Functions#  (Examples):
    int()
    len() (number of characters in an object)
    str()
    sum()
    print() (prints to screen)

#Python Built-In Methods# (Examples):
    my_string.upper()
    my_string.lower()
    my_string.split()
    my_list.append()
    my_list.insert()

#Python How Imports Work#
  -Be careful not to import a module over one you have already imported. 
    import {module}
    import {module} as {name}
    from {module} import * (imports everything from the provided module)
    from {module} import {function}
    from {module} import {function} as {name}


Python3 Libraries and References
  Socket
  Struct (example struct.pack is used to combine various pieces of your raw socket packet into network order.)
  Sys
  Errors
  Exceptions

#Network Programming with Python3#
  Network sockets primarily use the Python3 Socket library and socket.socket function. Example:
  
    import socket
  s = socket.socket(socket.FAMILY, socket.TYPE, socket.PROTOCOL)


#The socket.socket Function#
  Inside the socket.socket. function, you have these arguments, in order:
    socket.socket( *family*, *type*, *proto* )

  family: AF_INET*, AF_INET6, AF_UNIX
  type: SOCK_STREAM*, SOCK_DGRAM, SOCK_RAW
  proto: 0*, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_IP, IPPROTO_ICMP, IPPROTO_RAW


#Stream Socket Sender Demo#
    #!/usr/bin/python3
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ip_addr = '127.0.0.1'
    port = 1111
    s.connect((ip_addr, port))
    message = b"Message"
    s.send(message)
    data, conn = s.recvfrom(1024)
    print(data.decode('utf-8'))
    s.close()

chmod +x new.py  (what I named the file), this makes it executable. 
  ss -ntlp - this will open up all listening sockets
  ss -udp
  nc -lvp 1111

open up a terminator console and type ls, 
then ./new.py


#Datagram Socket Sender Demo#
#!/usr/bin/python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
ip_addr = '127.0.0.1'
port = 2222
message = b"Message"
s.sendto(message, (ip_addr, port))
data, addr = s.recvfrom(1024)
print(data.decode())

chmod +x udp.py 

Raw IPV4 Sockets
  RAW Socket scripts must include the IP header and the next headers.
  Requires guidance from the "Request for Comments" (RFC) to follow header structure properly.
    RFCs contain technical and organizational documents about the Internet, including specifications and policy documents.
  See RFC 791, Section 3 - Specification for details on how to construct an IPv4 header.

Raw Socket Use Case
  Testing specific defense mechanisms - such as triggering and IDS for an effect, or filtering
  Avoiding defense mechanisms
  Obfuscating data during transfer
  Manually crafting a packet with the chosen data in header fields

Encoding and Decoding
  Encoding
    The process of taking bits and converting them using a specified cipher.
  Decoding
    Reverse of the conversion process used by the specified cipher for encoding.
  Common encoding schemes
    UTF-8, Base64, Hex

Encoding vs Encryption
  Encoding - converts data into a different format
  Encryption - scrambles data to make it unreadable without a secret key

#Hex Encoding and Decoding#
  Encode text to Hex:
    echo "Message" | xxd
    or
    xxd file.txt file-encoded.txt
  Decode file from Hex:
    xxd -r file-encoded.txt file-decoded.txt

#Python Hex Encoding#:
  import binascii

  message = b'Message'
  hidden_msg = binascii.hexlify(message)

#Base64 Encoding and Decoding#: (We'll likely see the answers encoded during class, expect different padding at the end of it, which looks like one or two equal signs '==')
  Encode text to base64:
    echo "Message" | base64
    or 
    base64 file.txt > file-encoded.txt  (new file into old file)
  Decode file from Base64:
    base64 -d file-encoded.txt > file-decoded.txt (old file into new file)
  
#Python Base64 Encoding#
  import base64
  message = b'Message'
  hidden_msg = base64.b64encode(message)


Raw IPV4 and TCP Socket Demos #RAW IPV$ and TCP SOCKET DEMO#
#!/usr/bin/python3
#For building the socket
import socket

#For system level commands
import sys

#For establishing the packet structure (Used later on), this will allow direct access to the methods and functions in the struct module
from struct import *

#Create a raw socket.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()

packet = ''
packet = ''

src_ip = "127.0.0.1"
dst_ip = "127.0.0.1"

# Lets add the IPv4 header information
ip_ver_ihl = 69  # This is putting the decimal conversion of 0x45 for Version and Internet Header Length
ip_tos = 0           # This combines the DSCP and ECN feilds
ip_len = 0           # The kernel will fill in the actually length of the packet
ip_id = 12345        # This sets the IP Identification for the packet
ip_frag = 0          # This sets fragmentation to off
ip_ttl = 64          # This determines the TTL of the packet when leaving the machine
ip_proto = 16        # This sets the IP protocol to 16 (Chaos). If this was 6 (TCP) or 17 (UDP) additional headers would be required
ip_check = 0         # The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number
src_ip = "127.0.0.1"
dst_ip = "127.0.0.1"

#Lets add the IPv4 header information
ip_ver_ihl = 69  # This is putting the decimal conversion of 0x45 for Version and Internet Header Length
ip_tos = 0           # This combines the DSCP and ECN feilds
ip_len = 0           # The kernel will fill in the actually length of the packet
ip_id = 12345        # This sets the IP Identification for the packet
ip_frag = 0          # This sets fragmentation to off
ip_ttl = 64          # This determines the TTL of the packet when leaving the machine
ip_proto = 16        # This sets the IP protocol to 16 (Chaos). If this was 6 (TCP) or 17 (UDP) additional headers would be required
ip_check = 0         # The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip)  # inet_aton(string) will convert an IP address to a 32 bit binary number


#Getting a Message to a remote team Utilizing a specific host (BLUE_DMZ_HOST-1) using STREAM SOCKET#

coded information: 867-5309 Jenny
port number = 5309
BLUE-DMZ-HOST-1: 172.16.1.15
Message: Jenny
>vi message.py

    #!/usr/bin/python3
    import socket
    import os
    port = 5309
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ip_addr = '172.16.1.15'
    s.connect((ip_addr, port))
    message = b"Message"
    s.send(message)
    data, conn = s.recvfrom(1024)
    print(data.decode('utf-8'))
    s.close()

#Getting a Message to a remote team utilizing the specified host (INTERNET_HOST) using DATAGRAM SOCKET#

  Port = 10000
  Message = Disturbed
  INTERNET_HOST = PROVIDED FLOAT IP (10.50.30.41)
  > vi dgram.py
  
  #!/usr/bin/python3
  import socket
  import os
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
  ip_addr = '127.0.0.1'
  port = 10000
  message = b"Disturbed"
  s.sendto(message, (ip_addr, port))
  data, addr = s.recvfrom(1024)
  print(data.decode())
  
#Modify ipraw.py #

Source IP: 10.10.0.40
Target IP: 172.16.1.15
DSCP: 24 (to change this you need to account for the ECN field as well, picuture below
                    DSCP       | ECN
                    0 0 0 0 0 0| 0 0
                    0 1 1 0 0 0| 0 0  <----
The bits were orignially shifted two to the right, to equal 24, but since DSCP and ECN are part of the same field, this must be accounted for by shifting it left)                    
IP ID: 1984
Protocol: CHAOS

use below to listen:
nc -lvp 1111

#modify tcpraw.py#

Source IP: 10.10.0.40
Target IP: 172.16.1.15
IP ID: 2020
TCP Src port: 54321
TCP Dst port: 1234
SEQ Number: 90210
ACK Number: 30905
TCP flag: SYN

use below to listen: 
nc -lvp 1111




Service and Network Discovery
    ==================
    ====   Day 4  ====
==========================


#NMAP syntax examples#:
  nmap -sV -p 22,53,110,143,4564 198.116.0-255.1-127 (Launches host enumeration and a TCP scan at the first half of each of the 255 possible eight-bit subnets in the 198.116.0.0/16 address space. This tests whether the systems run                                                           SSH, DNS, POP3, or IMAP on their standard ports, or anything on port 4564. For any of these ports found open, version detection is used to determine what application is running.)
  nmap -sS -p 22,80,443 192.168.1.0/24 (this scans all IP addresses within the 192.168.1.0 network with a /24 subnet mask)
  nmap -sn 192.168.1.1-100  (this scans all IP addresses from 192.168.1.1 to 192.168.1.100 for active hosts)
  nmap -O 192.168.1.0/24 (this attempts to identify the operating systems running on hosts within the network) 
  Remember: you can combine these options in many ways to enchance your scan to get the results you need at one time. 
  Helpful Site: https://nmap.org/book/man-examples.html

#Traceroute - Firewalking#
    traceroute 172.16.82.106
    traceroute 172.16.82.106 -p 123
    sudo traceroute 172.16.82.106 -I
    sudo traceroute 172.16.82.106 -T
    sudo traceroute 172.16.82.106 -T -p 443


Netcat - Scanning
      nc [Options] [Target IP] [Target Port(s)]
      -z : Port scanning mode i.e. zero I/O mode
      -v : Be verbose [use twice -vv to be more verbose]
      -n : do not resolve ip addresses
      -w1 : Set time out value to 1
      -u : To switch to UDP
  
#Netcat - Horizontal Scanning#
    Range of IPs for specific ports:
      --TCP--
    for i in {1..254}; do nc -nvzw1 172.16.82.$i 20-23 80 2>&1 & done | grep -E 'succ|open'
         or 
      --UDP--
    for i in {1..254}; do nc -nuvzw1 172.16.82.$i 1000-2000 2>&1 & done | grep -E 'succ|open'

#Netcat - Vertical Scanning#
    Range of ports on specific IP
      --TCP--
    nc -nzvw1 172.16.82.106 21-23 80 2>&1 | grep -E 'succ|open'   (this is looking for 'successor' or 'open' )
        or
      --UDP--
    nc -nuzvw1 172.16.82.106 1000-2000 2>&1 | grep -E 'succ|open' (this is looking for 'successor' or 'open' )

--------------------------------------------------------------------
Netcat - TCP Scan Script   #TCP SCAN SCRIPT#
    #!/bin/bash
    echo "Enter network address (e.g. 192.168.0): "
    read net
    echo "Enter starting host range (e.g. 1): "  
    read start
    echo "Enter ending host range (e.g. 254): "
    read end
    echo "Enter ports space-delimited (e.g. 21-23 80): "
    read ports
    for ((i=$start; $i<=$end; i++))
    do
        nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
    done
    (When you run this script, it will prompt you to input any required info,--
     and remember, while conducting these scans, you can still conduct passive external reconnaissance.
     Don't waste your time!)
-----------------------------------------------------------------------
Netcat - UDP Scan Script #UDP SCAN SCRIPT#
    #!/bin/bash
    echo "Enter network address (e.g. 192.168.0): "
    read net
    echo "Enter starting host range (e.g. 1): "
    read start
    echo "Enter ending host range (e.g. 254): "
    read end
    echo "Enter ports space-delimited (e.g. 21-23 80): "
    read ports
    for ((i=$start; $i<=$end; i++))
    do
        nc -nuvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
    done
------------------------------------------------------------------------

Netcat - Banner Grabbing #BANNER GRABBING# (This is how you can know what port is on a box, using the transport layer protocol. You would get a result of TCP if you scanned 22 (ssh), this is especially convenient when 
                                            trying to see the versions of each protocol. Different versions are vulnerable to their own exploits.)
      Find what is running on a particular port (examples):
        nc [Target IP] [Target Port]
        nc 172.16.82.106 22
        nc -u 172.16.82.106 53
      -u : To switch to UDP
    Note: Sometimes this command takes a few seconds to enumerate your information. Don't Ctr+C just because it's taking a little while. 
    
Curl and Wget #CURL and WGET interface with webservers#  (WGET is by far the more helpful one. Use this one instead if you have the choice.)
    Both can be used to interact with the HTTP, HTTPS and FTP protocols.
    Curl - Displays ASCII
      curl http://172.16.82.106
      curl ftp://172.16.82.106
    Wget - The Download option is '-r' (recursive). You want to download it to get everything. It will create a directory of everything it got. You can use this with websites as a way of navigating them. It might be worth learning                how to navigate websites as a means of exploring them, instead of using the webbrowser. (Look into it!)
      Syntax:
      wget -r http://172.16.82.106
      wget -r ftp://172.16.82.106
    ftp 10.10.0.40
      ftp> get README  (learn a little more about how to make this work)

    If you get a png file, you can open it by using the 'eog' command. 
    example:
     > eog hint-01 
Describe Methods Used for #Passive Internal Discovery#
   
#Packet Sniffers#
    Wireshark
    Tcpdump
    p0f
  Limited to traffic in same local area of the network

#IP Configuration#
    Windows: ipconfig /all
    Linux: 'ip address' (ifconfig depreciated) or 'ip addr'
    VyOS: show interface

#DNS configuration#
    Windows: ipconfig /displaydns ( this command will display the contents of the DNS client resolver cache)
    Linux: cat /etc/resolv.conf

#ARP Cache#
    Windows: arp -a
    Linux: ip neighbor (arp -a depreciated)

#Network connections#
    Windows: netstat
    Linux: ss (netstat depreciated) 
    Note: when you see 0.0.0.0*, it's a wildcard; 'everything but this port'. if you see 127.0.0.1:6010, that means you can only access 6010 through loopback!
          'ss' will show what to connect to a port through. Go based of what it shows. 
          
    Example options useful for both netstat and ss: -antp
    a = Displays all active connections and ports.
    n = No determination of protocol names. Shows 22 not SSH.
    t = Display only TCP connections.
    u = Display only UDP connections.
    p = Shows which processes are using which sockets.

#Services File#
    Windows: %SystemRoot%\system32\drivers\etc\services
    Linux/Unix: /etc/services

#OS Information#
    Windows: systeminfo
    Linux: uname -a and /etc/os-release

#Running Processes#
    Windows: tasklist
    Linux: ps or top (ps - elf, htop, top -tree)
      note: to kill processes, you can you 'kill -9' or 'pkill', you need its name for pkill.
      
    Example options useful for ps: -elf
    e = Show all running processes
    l = Show long format view
    f = Show full format listing
  
#Command path#
    which        (if you don't have permission to run 'whereis' you can run this one instead)
    whereis      (whereis tcpdump - this checks for the location of tcpdump if it's installed)


#Routing Table#
    Windows: route print 
    Linux: ip route (netstat -r deprecated) (these are routes to networks)
    VyOS: show ip route
    
#File search#
    find / -name hint* 2> /dev/null 
    find / -iname flag* 2> /dev/null
  Note: (consider using these throughout the challenges. They might actually be helpful ._. )
  
#SSH Config#
    Windows: C:\Windows\System32\OpenSSH\sshd_config
    Linux: /etc/ssh/sshd_config

Describe Methods Used for #Active Internal Discovery#

Active Internal Network Reconnaissance
    Will use similar tools as Active External Network Reconnaissance
    Scope and addresses may differ

#ARP Scanning#
    arp-scan --interface=eth0 --localnet 
    nmap -sP -PR 172.16.82.96/27

#Ping Scanning# (PING SWEEPS!)
    ping -c 1 172.16.82.106
    for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done    (this is will mass scan for all boxes within the range provided at the beginning)
    sudo nmap -sP 172.16.82.96/27
     note: Ping sweeping is the quickets way to see if the box is up. This should be the first thing you do when targetting a box. It'll save you time before mass nmap scanning, by showing you which IPs are up first!
   
#DEV TCP Banner Grab#
    exec 3<>/dev/tcp/172.16.82.106/22; echo -e "" >&3; cat <&3
    nmap -sn 192.168.1.1-100
    
#DEV TCP Scanning#
    for p in {1..1023}; do(echo >/dev/tcp/172.16.82.106/$p) >/dev/null 2>&1 && echo "$p open"; done 
   note: If you don't have netcat, you can use this isntead. 

Perform Network Forensics

#Network Forensics - Mapping# (ALWAYS REQUEST A NETWORK MAP WHEREVER YOU GO ON MISSION, this will give you a baseline of what's presently in use and allow you to pinpoint anything new)  
    Diagram devices
    Line Types
    Written Information
    Coloring
    Groupings

Network Forensics - Mapping (see link)
https://net.cybbh.io/public/networking/latest/07_discovery/fg.html#_7_5_1_map_a_network

Things to include on your Map:
    Device type (Router/host)
    System Host-names
    Interface names (eth0, eth1, etc)
    IP address and CIDRs for all interfaces
    TCP and UDP ports
    MAC Address
    OS type/version
    Known credentials

Network Mapping Tools
    Draw.io Local (Template)
    Draw.io Web
    Witeboard.com
    Draw.Chat
    SmartDraw
    Ziteboard
    Tutorialspoint Whiteboard
    Explain Everything Whiteboard

#CTFs Network Reconnaissance:#
  start by:
    > dig networking-ctfd-1.server.vta TXT
    from here you can decrypt the base64 text found, and that is your start flag.

  connect to float: ssh net1_student1@10.50.26.58 (password is: password1)
    conduct active recon against target: Red Boundry Router
        for i in {1..254}; do (ping -c 1 172.16.120.$i | grep "bytes from" &) ; done 
        result:
      64 bytes from 172.16.120.1: icmp_seq=1 ttl=62 time=0.877 ms
      64 bytes from 172.16.120.2: icmp_seq=1 ttl=63 time=0.329 ms
      64 bytes from 172.16.120.10: icmp_seq=1 ttl=62 time=0.605 ms
      64 bytes from 172.16.120.9: icmp_seq=1 ttl=61 time=1.50 ms
      64 bytes from 172.16.120.18: icmp_seq=1 ttl=61 time=0.821 ms
      64 bytes from 172.16.120.17: icmp_seq=1 ttl=60 time=2.09 ms

        maybe perform nmap against these targets?

    you can also SSH into the router: ssh vyos@172.16.120.1 (password is: password), hostname RED-SCR ,
      to get hostname: show host name [enter]
    
    Routers that vyos@172.16.120.1 is connected to: 
                  
     eth2 ether 172.16.101.2 , fa:16:3e:90:0f:13 , Linux 4.19.0-18 Debian , known creds : net1_student1:password14, ports:       22
     
     ^these are all hosts, and you can ssh into each of them with the creds: net_student1:password1

     interface ethernet:
      eth 0 172.16.120.1/29 Description 'INTERNET' , fa:16:3e:0f:8a:8a <><><><><>
      eth1 172.16.120.10/29 Description 'REDNET', hostname: RED-SCR (Donovian Boundary) 
                         172.16.120.9, fa:16:3e:eb:49:e6, vyos 1.1.7 , known creds vyos:password, ports 22 (router), hostname RED-IPs (device connected to donovian boundary on eth1) ,
                               (1)   eth0             172.16.120.9/29                   u/u  INTERNET 
                                                 (1) 172.16.120.12,  fa:16:3e:0f:8a:8a
                               (1)   eth1             172.16.120.18/29                  u/u  REDNET 
                                       172.16.120.17            ether   fa:16:3e:9e:5b:43   C                     eth1 , host name , RED-POP, vyos 1.1.7,  (Inner Boundary)
                                              eth0             172.16.120.17/29                  u/u  INTERNET 
                                                  (1) 172.16.120.18            ether   fa:16:3e:e9:25:1e   C                     eth0
                                              eth1             172.16.182.126/27                 u/u  REDHOSTS 
                                                  (1) 172.16.182.106, ports 22 , (T4) , Linux 3.1, hostname red-host-1 , 
                                                  (2) 172.16.182.110, ports 22 80 1980 1982 1988 1989 (TCP) & 1984 1989                                                           (UDP), (T2), Linux 3.1
                                                  (3) 172.16.182.114 ports 22 , (T5) Linux 3.1 , hostname red-host-3
                                                  (4) 172.12.182.118, ports 22 , (T6) Linux 3.1, hostname red-host4
                                                  (5) 172.16.182.126, ports 22, Linux 3.2
                                              eth2             172.16.140.6/29                   u/u  REDINTDMZ 
                                                      (1) 172.16.140.5/29 , hostname: REP-POP2,
                                                               eth1             172.16.140.62/27                  u/u  REDINTDMZ2
                                                      (2) 172.16.140.62/27 
                                                          172.16.140.6/29   
                                                          172.16.140.33, ports 22 80 2305 2800 2828 (TCP) , (T3)
                                                               172.16.140.35, ports 22 , (T7) , hostname red-int-dmz2-host-2 , creds net1_student14:password14
                                                           
                                               

      eth2 172.16.101.30/27 Description 'DMZ' , creds: vyos:password, hostname : RED-SCR
                      eth0             172.16.120.1/29      

                      

FLAGS:
show interfaces (this will show the total number of host devices. In this case it's only one, as only one has a different IP)
nmap -sV 172.16.101.30/27 (this will show you the total number of host device(s) under the DMZ network, which is 172.16.101.30/27)
                          (this will also get you the well known ports (in this case, just port 22))
ssh 172.16.101.2 (use the creds provided, and then run a hostname to get its hostname).
sudo nmap -sU 172.16.182.126/27 ( this will list hidden UDP ports)
echo "hello" | nc -u 172.16.82.106 53 (this will allow you to touch a port and prompt a question it may have, if any.).
          (the answer to this prompted question is 'which dig")
ping -s ( this can be used to send an abnormally large ICMP packet to the target).
 'eog hint-01.png' (this will open the image file so that you can get the hint).
    (The port range you get from the answer is 2000-2999)
traceroute 10.50.23.214 (this will get you the total number of hops from the Internet_host we're signed into, to the T1 host).
'nslookup -type=NS dtic.mil' or 'dig dtic.mil NS' (this will get you the total number of Name Server (NS) records for a given host)
sudo nmap -sU 172.16.140.33 -p 2000-2999 (this will get you the total number of UDP ports open within the specified range, for the specified ip address)
nslookup dtic.mil, whois 214.48.252.101 (the nslookup will resolve the domain name to an IP address. From there you can use the whois command to successfully get the associated city and state, and other info).
36). echo "hello" | nc -u 172.16.140.33 2000 (the -u option will allow you to use the 'nc' command on UDP ports)
                start by looking up 214.48.252.101 on https://hackertarget.com/as-ip-lookup/ to get the ASN
                look up the found ASN (27064) on https://bgpview.io/asn/27064#info. This explore this page and you'll see your answer.
          

37). echo "hello" | nc -u 172.16.140.33 2011
                to get this one, try running dig on 208.64.202.36 (resolved IP for steampowered.com)
                look up dnslookup.com, and put in the domain name (steampowered.com)
To get a SSL Certificate issuer, go to the provided website and look at the 'Site information' button on the left side of the address bar. 
http://archive.org/web/ (This site can be used to find a history of websites that no longer exists on the ordinary world wide web).



  File Transfer 
      And
   Redirection
=========================
=======   Day 4 =========
=========================


CTF Challenges Netcat Relay:
       T1  (Internet Host/Me) = 10.50.30.41
       RELAY (Blue-int-dmz-host-1) = 172.16.40.10 
       T2  (Blue_Host-4) = 172.16.82.115

  start: 
1).   (from RELAY): nc -lvp 1234 > file.jpg 
      (from Internet_host): nc -lvp 1111 > file1.jpg
      (from RELAY): nc 10.10.0.40 1111 < file.jpg (10.10.0.40 is the internal IP, which we use to txfer this)
      (from Internet_host): [ctrl + c] and check for the file. 
                         steghide extract -sf file1.jpg
                         (file is extracted)
                         cat phrase1.txt | md5sum
                         you now have your answer.
                      


  start: 
2).   (from RELAY): nc 4321 > 2steg.jpg
      (from Internet_host): nc -lvp 1111 > 2steg.jpg
      (from RELAY): nc 10.10.0.40 1111 < 2steg.jpg
      (from Internet_host): [ctrl + c ]  and check for file
                            steghide extract -sf 2steg.jpg
                            (file is extracted)
                            cat phrase2.txt | md5sum
                            you now have your answer.

3).   (from RELAY): nc 172.16.82.115 6789 > 3steg.jpg (this one is contacting T2 and basically saying "I've made contact, give me the message" and that's how you get it)
      (from Internet_host): nc -lvp 1111 > 3steg.jpg
      (from RELAY): nc 10.10.0.40 1111 < 3steg.jpg
      (from internet_host): [ctrl + c] and check for file
                            steghide extract -sf 3steg.jpg
                            cat phrase3.txt | md5sum
                            you now have your answer

4).   (from RELAY) nc 172.16.82.115 9876 > 4steg.jpg
      (from Internet_host): nc -lvp 1111 > 4steg.jpg
      (from RELAY): nc 10.10.0.40 1111 < 4steg.jpg
      (from internet_host): [ctrl + c ]  and check for file
                            steghide extract -sf 4steg.jpg
                            (file is extracted)
                            cat phrase4.txt | md5sum
                            you now have your answer.




GySgt Stone's Methodology
=========================
Whenever you finish, take notes. Improve your toolkit as you put it together. 
Cryptic notification from: 
RIP - BOB floats 10.50.23.190

Create a diagram.
Create a square that says "Hostname: BOB??? Ip: Ports:"
start by trying to ssh into Bob. 
no success?
pay attention to the error message.
"Connection closed by remote host"
Figure out what's on the ssh port, because something is there. 

Try banner grabbing. 
nc 10.50.23.190
"this is not the port you are looking for. Try again"
Okay, so... they're playing games with you. Try to nmap next! see what ports are open. 
nmap -Pn 10.50.23.190 -p - -T5            ('-'all the ports, also T5 is okay to use on the first box in)
ports open!: 21, 22, 25, 90, 443, 3389    (ftp and http are free info!)
take a screenshot and copy the info to your diagram.
run a 'wget -r 10.50.23.190' 

it worked? Yes.
try 'wget -r ftp://10.50.23.190' 
this one didn't work. 
see what you got from the wget for now (http)
ls 10.50.23.190
eom 10.50.23.190/index.html

try to nc it:
nc 10.50.23.190  21
ftp 10.50.23.190
try username: bob
try password: bob

Now that you're in the fpt session:
  ftp> ls
     no info
     > exit
Update your map, show what you've got from the ports you've exploited.
try the port 25. 
nc 10.50.23.190 25
  provided an ssh version! seems like they designed ssh to port 25 instead. 
ssh 10.50.23.190 -p 25
  no success? it says permission denied. BUT, this implies the service is still up and running.
ssh bob@10.50.23.190 -p 25 
  but we don't have the creds for bob... how can we do this?
    sniff and wait on the port with wireshark until somebody tries to telnet in.
  bobs password: password.
  
Now you're in!
enumerate system info. 
  ip addr
    you found the real ip (as opposed to the float, which should never be relied on)
      'ip neig' will get you the ip addresses you have talked to. 
      you can also ping sweep the entire range to get all addresses in the network! try it, at least:
    for i in {1..254}; do (ping -c 1 10.0.0.$i | grep "bytes from" &) ; done
  Now you've got a list of addresses that have been reached. 
Try testing port 443, from bob-host now!
  ss -ntlp

Split screen
  nc 10.50.23.190 443
    it's another fake port... let's move on, or if there's a hint work with it. 
  look for files 
    find / -iname "*.hint" 2>/dev/null
    find / -iname "*.flag" 2>/dev/null
    find / -name "hint*" 2>/dev/null
    ! there was a hint found. 
    cat /srv/ftp/hint.txt
      It gave you a hint. 
dynamic tunnel
ssh bob@10.50.23.190 -p 25 -D 9050 -NT (this will create a dynamic tunnel, 9050 is the port you opened on you local machine)
ss -ntlp 
run:  'proxychains nmap -Pn 10.0.0.101/24 -p 20-23,80 -T5' or 'proxychains nmap -Pn 10.0.0.101-105 -p 20-23,80 -T5' or 'proxychains nmap -Pn 10.0.0.101,124 -p 20-23,80 -T5'


#SSH Tunneling and Covert Channels#
==================
==    Day 5     ==
==================

#CTFS (task 2)#
(1.) Localhost is associated with both Loopback address and 127.0.0.1
(2.) 'OPS$ ssh cctc@10.50.1.150 -p 1111' port 1111 is the alternate ssh port on 10.50.1.150
(3.) 'OPS$ ssh cctc@localhost -p 1111' port 1111 is the local listening port on OPS
(4.) 'ssh cctc@10.50.1.150' 10.50.1.150 is the IP we use to ssh to PC1 from OPS.
(5.) 'ssh -D 9050 student@10.50.1.150' will set up a Dynamic tunnel to PC1
(6.) 'ssh -L 1111:localhost:22 cctc@10.50.1.150 -NT' this syntax will set up a Local tunnel to PC1's ssh port.
         (7.) 'ssh -D 9050 cctc@localhost -p 1111 -NT' This will create a dynamic tunnel using the local tunnel                      created in question 6 (dynamic port forward through previously established port forward).
               (8.) 'wget -r http://localhost:1111' This will allow you to download the webpage of PC1 using the                           local tunnel created in question 7 (you already have a tunnel open on port 1111 on the local 
                     host, that's why you can use localhost:1111)
                     (9.) 'proxychains wget -r http://100.1.1.2' This will allow you to download the webpage of PC2 
                           using the dynamic tunnel created in question 8.
        (12.) 'ssh ssh cctc@localhost -p 1111 -L 2222:100.1.1.2:22 -NT' This will set up a second local tunnel to                    PC2's ssh port usin the tunnel made in Question 6.
               (14.) 'ssh -D 9050 cctc@localhost -p 2222 -NT' This will create a dynamic tunnel using the local                             tunnel from question 12. 
               (17.) 'ssh -L 3333:192.168.1.2:23 cctc@localhost -p 2222'  This will allow you to use the tunnels in                           questions 6 & 12 to set up a 3rd local tunnel to PC3's telnet port. 
                     (18). 'telnet localhost               
               (20). 'ssh cctc@localhost 2222 -L 5555:localhost:4444' this will connect the Tunnel made in                                 Question 19 to the tunnels in question 6 & 12. The reason 5555:localhost:4444 makes sense 
                     here is because port 4444 was ultimately assigned to localhost. 
        (13.) 'ssh -L 2222:100.1.1.2:80 cctc@localhost -p 111' This will create a second local tunnel to PC2's HTTP 
              port using the tunnel mdae in Question 6. 
(10.) 'ssh cctc@10.50.1.150 -L 1111:100.1.1.2:22 -NT' This will set up a local tunnel to PC2 using PC1 as your pivot.
(11.) 'ssh cctc@10.50.1.150 -L 1111:100.1.1.2:22 -NT' This will allow me to open a local tunnel to PC2's ssh port using PC1 as my pivot.
(15.) The error is in line 2, where the user authenticates to the wrong IP address. The IP address to authenticate to should be the local host. 
(16.) The error is in line 1, where the user targeted the wrong IP. The correct Ip is 192.168.1.2.
(19.) 'ssh -R 4444:192.168.2.2:22 cctc@192.168.2.1 -NT' This will allow the user to set up a remote tunnel from PC3 back to PC2 using PC3s ssh port as the target. 

#CTFS (Task 3)#

(1.)  
[IH]   [T3]10.3.0.27:80         (T3 (Atropia) Float IP address is - 10.50.27.164)
terminal 2: internet_host$ ssh net1_student14@10.50.30.41 -L 1111:10.3.0.27:80 -NT (once ran, you will see no 
response.)
terminal 1: wget -r http://localhost:1111
   check to see the contents retrieved.
   cd into the new directory. 
   now cat the html to get the answer (answer is 6to4)
summary: This creates a local port forward from me (internet_host) to T3 that targets 10.3.0.27:80 

(2.)
[IH]    [T3]10.3.0.1 
Terminal 2: ssh -D 9050 net1_student14@10.50.27.164 -NT (the NT will prevent any responses of making it into the tgt)
Terminal 1: proxychians wget -r ftp://10.3.0.1
      check for contents received
      ls into new directory
      check the files (answer is injection)
summary: this creates a dynamic port forward from me (internet_host) to T3. 

(3.)
[IH]    [T4]10.50.29.131:23
Terminal 2: telnet 10.50.29.131 (use the net1_student14:password14 credentials to login)
    Once in, conduct passive recon.
    In this case, find a file that has a question for your flag. 
    find / -type f -name "*flag.txt" 2>/dev/null
    cat /usr/share/cctc/flag.txt      (this was the file found)
    (answer is ~/.ssh/known_hosts)
Summary: we access the target here using telnet. 

(4.)
[IH]10.50.30.41    [T3]Pivot,10.50.27.164:80    [T4]10.50.29.131
Terminal 2:  [IH]: telnet 10.50.29.131   
          
Terminal 4: ssh net1_student14@10.50.27.164
            ip a    (confirm the inside IP: 10.3.0.10)
            exit
Terminal 2:  [Pineland] ssh net1_student14@10.3.0.10 -R 11411:localhost:22 -NT
(create remote port forward to bind T3's inside IP to a local machine authorized port. This instance connects T3 to localhosts authorized port:22 )

Terminal 3: ssh net1_student14@10.50.27.164 -L 11422:localhost:11411 -NT
(This will create a local port forward from IH to T3 that targets the port we established in the first tunnel)
confirm this port is open by checking from the internal host by running ss -ntlp, to see if the port 11422 is open.)

Terminal 4: ssh net1_student14@localhost -p 11422 -L 11433:10.2.0.2:80 -NT
(this will set up a local port forwarder through through the port you most recently opened [11422] and connect it to a new port, [11433], and runs to 10.2.0.2:80.)

Terminal 1: wget -r http://localhost:11433
(This will connect you through the most recent opening of the tunnel to get to 10.2.0.2 and get you your answer.)

summary: we start by creating a Remote port forward tunnel from T4 to T3 binding the source as on of my authorized
ports from the mission prompt, and targetting 10.20.0.2:80 (by connecting to its inside IP). We then use another 
terminal to create a local port to connect T3's tunnel via port 11411 to the local host's port 11422.

# When in doubt with what your tunnels are doing, test them out. SSH net1_student14@local -p [port most recently opened]. Remember to pay attention to where you're opening new ports! example: ssh net1_student14@localhost -p 11422.

(5.)
[IH]     [T4]
Terminal 2: Continue off of the last local port set up at 11422 for the last question. 
          open a new terminal. 
Terminal 4: ssh net1_student14@localhost -p 11422 -D 9050 -NT
            (we connect to 11422 here because it's the last port that was able to touch 10.2.0.2)
Terminal 3: (or which ever terminal is open to use)
            proxychains nmap -T4 -vvvv 10.2.0.2     (see the ports open)
            proxychains wget -r ftp://10.2.0.2:21   (this will get you the file that holds the question. The answer is 
            /etc/ssh/ssh_config)

STEPS: set up tunnel 1: ssh net1_student14@10.3.0.10 -R 11411:localhost:22 -NT
              tunnel 2: ssh net1_student14@10.50.27.164 -L 11422:localhost:11411 -NT
              tunnel 3: ssh net1_student14@localhost -p 11422 -D 9050 -NT
              from IH: proxychains ./scan.sh
              This will get you the IPs/Ports open on the 10.2.0.0 Network. 
              We figured out from here that 10.3.0.10 can touch the 10.2.0.0 network. 
              
(6.)
terminal 2: continue from the last local port set up at 11422 in Question 4. 
Terminal 4: ssh net1_student14@10.50.27.164 -D 9050 -NT
Terminal 2: proxychains ./scan.sh    (this will scan for the ports, across a range of IPs, more quickly than nmap).
            Identify the IPs  that have an HTTP server (port 80 open)
            proxychains wget -r http://10.3.0.1:80 
            cd 10.3.0.1
            cat flag.txt (answer is: substitution)
            
(7.)
Terminal 2: from the last question (6). scan for the FTP server on T3. 
            proxychains ./scan.sh (start at 10.3.0 , start at 1 , end at 254 , 21-23 80 )
            proxychains wget -r ftp://10.3.0.27
            cat 10.3.0.27/flag.txt (answer is: Teredo)
(8.)
Terminal 4: Start by leaving the last dynamic tunnel you created, and reestablish the dynamic tunnel (was able to reach 10.2.0.0/24)
            STEPS:
              tunnel 1: ssh net1_student14@10.3.0.10 -R 11411:localhost:22 -NT
              tunnel 2: ssh net1_student14@10.50.27.164 -L 11422:localhost:11411 -NT
              tunnel 3: ssh net1_student14@localhost -p 11422 -D 9050 -NT
              from IH: proxychains ./scan.sh
              enumerate the results from the above and try to ssh into the networks found. 
              Telnet into T4 
              T4: ssh into the box it really is (10.2.0.3)
              look for hints. 
              find / -iname '*hint*' 
              cat /etc/share/cctc/hint.txt (says we used to have access to: 10.4.0.0/24 and 10.5.0.0/24)
              scan the networks found now.
            
              # Extend your tunnel
              Close out the above tunnel(s) ^
              Tunnel 1: ssh user@T3 -D 9050 -NT
                    IH: proxychains ./scan.sh (10.4.0.0/24 info 10.4.0.1 [baja-republic])
                        try to extend this tunnel to reach from 10.4.0.1.

              #Extend your tunnel once more
              Tunnel 1: ssh user@T3(pivot) -L 11411:10.4.0.1:22 -NT
              Tunnel 2: ssh usre@localhost -L 11411 -D 9050 -NT
                    IH: proxychains ./scan.sh (10.5.0.0/24 info)
                        (exit the ssh session)
                        proxychains wget -r ftp://10.5.0.1
                        cd 10.5.0.1
                        cat flag.txt (answer is: ssh-connect)

(9.)
              Tunnel 1: ssh user@T3(pivot) -L 11411:10.4.0.1:22 -NT
              Tunnel 2: ssh usre@localhost -L 11411 -D 9050 -NT    
                    Ih: proxychains wget -r http://10.5.0.1:80 
                        cat 10.5.0.1/index.html (answer is: SSH-TRANS)
(10). 
              Tunnel 1: ssh user@T3(pivot) -L 11411:10.4.0.1:22 -NT
              Tunnel 2: ssh usre@localhost -L 11411 -D 9050 -NT  
                    Ih: proxychains wget -r ftp://10.5.0.57
                        cat 10.5.0.57/flag.txt (answer is: 10.10.0.40)
(11).
              Tunnel 1: ssh user@T3(pivot) -L 11411:10.4.0.1:22 -NT
              Tunnel 2: ssh usre@localhost -L 11411 -D 9050 -NT 
                    Ih: proxychains wget -r http://10.5.0.57 
                        cat 10.5.0.57/index.html (answer is: 172.16.82.106)
(12).
                        

#CTFs Task 4#
credentials for this env:
netY_studentX:passwordX
T5 float: 10.50.28.46 (inside Ip 192.168.0.10, on /24)
(0.)
    nmap -vvvv -T4 10.50.28.46 -Pn    (just checks for open ports)
      Port 23 open (answer)
    telnet 10.50.28.46

(1.) 
    telnet 10.50.28.46
    tunnel 1: ssh student@10.50.30.41 -R 11411:localhost:22      (localhost in this isntance is 10.50.28.46 because it's where the 
    ssh starts)
    tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT (if it doesn't connect, the keys may need to be flushed, try below:)
              (optional for key flushing: ssh-keygen -f "/home/student/.ssh/known_hosts" -R "[localhost]:11411")
              Try to establish the tunnel again now, if needed. 
          Ih: proxychains ./scan.sh (enumerate all found hosts)
              proxychains wget -r http://192.168.0.10:80 
              eom 192.168.0.10/flag.png (answer: Tatu Ylönen)

(2.) 
    telnet 10.50.28.46
    tunnel 1: ssh student@10.50.30.41 -R 11411:localhost:22      (localhost in this isntance is 10.50.28.46 because it's where the 
    ssh starts)
    tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT (if it doesn't connect, the keys may need to be flushed, try below:)
          Ih: proxychains nmap -vvvv -T4 192.168.0.30 -Pn 
              proxychains nc 192.168.0.30 4444 (answer is: Finland)
(3.)
    telnet 10.50.28.46
    tunnel 1: ssh student@10.50.30.41 -R 11411:localhost:22      (localhost in this isntance is 10.50.28.46 because it's where the 
    ssh starts)
    tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT (if it doesn't connect, the keys may need to be flushed, try below:)
          Ih: proxychains nmap -vvvv -T4 192.168.0.20 -Pn 
              proxychains ssh 192.168.0.20 -p 3333

(4.)
    telnet 10.50.28.46
    tunnel 1: ssh student@10.50.30.41 -R 11411:localhost:22      (localhost in this isntance is 10.50.28.46 because it's where the 
    ssh starts)
    tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT (if it doesn't connect, the keys may need to be flushed, try below:)
          Ih: proxychains ./scan.sh
              proxychains wget -r http://192.168.0.20:80 
              eom 192.168.0.20/hint.png 
              proxychains wget -r ftp://192.168.0.20
              eom 192.168.0.20/flag.png (answer is: Helsinki University of Technology)
(5.)          
     telnet 10.50.28.46
     tunnel 1: ssh student@10.50.30.41 -R 11411:localhost:22      (localhost in this isntance is 10.50.28.46 because it's where the 
     ssh starts)
     tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT (if it doesn't connect, the keys may need to be flushed, try below:)
            IH:
              proxychains nmap -vvvv -T4 192.168.0.20 -Pn
              proxychains ssh 192.168.0.20 3333 (only this device has access to the next machine)
              hint found through 192.168.0.20 ports. 
              create new tunnel to touch new network. 
      tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.20:3333 -NT
      tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT
            Ih: proxychains nmap -vvvv -T4 192.168.0.50 -Pn
                proxychains wget -r ftp://192.168.0.50
                eom 192.168.0.50/flag.png
    
(6.)
    telnet 10.50.28.46
    Tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.10:22 -NT
    Tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT
          Ih: proxychains wget -r 192.168.0.40
              eom 192.168.0.40/flag.png (answer is: AES)
              
(7.)
    telnet 10.50.28.46
    Tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.10:22 -NT
    Tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT
          Ih: Proxychains wget -r 192.168.0.40
              eom 192.168.0.40/hint.png
            (8.) Proxychains ./scan.sh (scan for the 172.16.0.0 network)
                 proxychains nmap -vvvv -t4 172.16.0.60 -Pn 
                 (found 172.16.0.60)
                 
(9.)
      telnet 10.50.28.46
      Tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.40:5555 -NT
      Tunnel 2: ssh net1_student14@localhost -p 11411 -D 9050 -NT
            Ih: proxychains wget -r ftp://172.16.0.60
                proxychains wget -r 172.16.0.60
                eom 172.16.0.60/flag.png (answer is: OpenSSH)
(10.)
  Network Space Donovia
  Net1_comrade14:privet14
      telnet 10.50.28.46 
      R Tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.40:5555 -NT                         
      L Tunnel 2: ssh net1_student14@localhost -p 11411 -L 11422:172.16.0.60:23 -NT
              IH: telnet localhost 11422                                            (see is port 22 is open by running an ss -ntld. If it is, you can use it to open a tunnel for the .40)
                  Tunnel 3: ssh net1_student14@192.168.0.40 -p 5555 -R 11433:localhost:22 -NT   (this will set up a remote tunnel to the last accessible IP, which is 192.168.0.40)
      L Tunnel 4: ssh net1_student14@localhost -p 11411 -L 11444:localhost:11433 -NT
              IH: proxychains ./scan.sh                                              (collect the info you need for the net)
                  proxychains nmap -vvvv -T4 172.16.0.80 -Pn
                  proxychains nc 172.16.0.80 3389         (answer is: Diffie-Hellman)
                  (12). 
                  proxychains nmap -vvv -T4 172.16.0.90 -Pn
                  Proxychains nc 172.16.0.90 2222
                  proxychains wget -r 172.16.0.90
                  proxychains wget -r ftp://172.16.0.90
                  eom 172.16.0.90/flag.png                 (answer is: Terrapin)

(11.)
      IH: telnet 10.50.28.46 
      R Tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.40:5555 -NT                         
      L Tunnel 2: ssh net1_student14@localhost -p 11411 -L 11422:172.16.0.60:23 -NT
              IH: telnet localhost 11422                                            (see is port 22 is open by running an                               ss -ntld. If it is, you can use it to open a tunnel for the .40)
                  Tunnel 3: ssh net1_student14@192.168.0.40 -p 5555 -R 11433:localhost:22 -NT   (this will set up a                                    remote tunnel to the last accessible IP, which is 192.168.0.40)
      L Tunnel 4: ssh net1_student14@localhost -p 11411 -L 11444:localhost:11433 -NT  (can now ssh into this through ssh                                net1_comrade14@localhost -p 11444)
              Ih: Proxychains nmap 172.16.0.70 1337
                  proxychains nc 172.16.0.70 1337      (answer is: Shellshock)
(13).
              IH: telnet 10.50.28.46 
      R Tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.40:5555 -NT                         
      L Tunnel 2: ssh net1_student14@localhost -p 11411 -L 11422:172.16.0.60:23 -NT
              IH: telnet localhost 11422                                            (see is port 22 is open by running an ss -ntld. If it is, you can use it to open a tunnel for the .40)
                  Tunnel 3: ssh net1_student14@192.168.0.40 -p 5555 -R 11433:localhost:22 -NT   (this will set up a remote tunnel to the last accessible IP, which is 192.168.0.40)
      L Tunnel 4: ssh net1_student14@localhost -p 11411 -L 11444:localhost:11433 -NT  (can now ssh into this through ssh net1_comrade14@localhost -p 11444)
      L Tunnel 5: ssh net1_comrade14@localhost -p 11444 -L 11455:172.16.0.90:2222 -NT 
      D Tunnel 6: ssh net1_comrade14@localhost -p 11455 -D 9050 -NT
              IH: proxychains ./scan.sh (host found: 172.16.0.100

(14).
      IH: telnet 10.50.28.46 
      R Tunnel 1: ssh student@10.50.30.41 -R 11411:192.168.0.40:5555 -NT                         
      L Tunnel 2: ssh net1_student14@localhost -p 11411 -L 11422:172.16.0.60:23 -NT
              IH: telnet localhost 11422                                            (see is port 22 is open by running an                               ss -ntld. If it is, you can use it to open a tunnel for the .40)
                  Tunnel 3: ssh net1_student14@192.168.0.40 -p 5555 -R 11433:localhost:22 -NT   (this will set up a                                    remote tunnel to the last accessible IP, which is 192.168.0.40)
      L Tunnel 4: ssh net1_student14@localhost -p 11411 -L 11444:localhost:11433 -NT  (can now ssh into this through ssh                                net1_comrade14@localhost -p 11444)
      L Tunnel 5: ssh net1_comrade14@localhost -p 11444 -L 11455:172.16.0.90:2222 -NT 
      D Tunnel 6: ssh net1_comrade14@localhost -p 11455 -D 9050 -NT
              Ih: ssh net1_comrade14@localhost -p 11455
                Tunnel 7: 
      L tunnel 7: ssh net1_comrade14@localhost -p 11455 -L 11466:172.16.0.100:23 -NT
              IH: telnet localhost 11466
                  tunnel 8: ssh net1_comrade14@172.16.0.90 -p 2222 -R 11477:localhost:22 -NT
              IH: 
                  tunnel 9: ssh net1_comrade14@localhost -p 11455 -L 11488:localhost:11477 -NT
              Ih: ssh net1_comrade14@localhost -p 11488 (this will put you into net-ssh-10)
                IH:
              
    tcpdump -X icmp
                ssh net1_student14@192.168.0.40 -p 5555 -R 11433:localhost:22 -NT
        






# Avater Challenge:
Tunnel 1: ssh Sokka@10.50.20.250 -L 11411:192.168.1.39:22 -NT
Tunnel 2: ssh Aang@localhost -p 11411 -L 11422:10.0.0.50:22 -NT
Tunnel 3: ssh Katara@localhost -p 11422 -L 11433:172.16.1.8:22 -NT
Tunnel D: ssh Toph@localhost -p 11433 -D 9050 -NT
Ih: ssh Toph@localhost -p 11433
    ss -ntld
Ih: proxychains nc localhost 12345


# Rick n Morty Challenge:
telnet 10.50.24.223 (rick)
  tunnel 1: ssh student@10.50.30.41 -R 11411:localhost:22 -NT
  tunnel 2: ssh Rick@localhost -p 11411 -L 11422:10.2.1.18:2222 -NT
  tunnel 3: ssh Morty@localhost -p 11422 -L 11433:172.16.10.121:2323 -NT
  tunnel 4: ssh Jerry@localhost -p 11433 -L 11444:192.168.10.69:22 -NT
  tunnel 5: ssh Beth@localhost -p 11444 -D 9050 -NT (dynamic forwarder to bring our tools over)
        IH: proxychains nc localhost 54321
            echo 'Life is effort and I'll stop when I die!' | md5sum
            (this is your answer).

# Bender Challenge:

Float: 10.50.20.10
User: Bender:password 

Tunnel D: ssh Bender@10.50.20.10 -p 1234 -D 9050 -NT
tunnel 1: ssh Bender@10.50.20.10 -p 1234 -L 11411:172.17.17.28:23 -NT
      IH: telnet localhost 11411
          tunnel 2: ssh Bender@172.17.17.17 -p 1234 -R 11422:localhost:4321
tunnel 3: ssh Bender@10.50.20.10 -p 1234 -L 11433:127.0.0.1:11422 -NT
tunnel 4: ssh Philip@localhost -p 11433 -L 11444:192.168.30.150:1212 -NT
tunnel 5: ssh Leela@localhost -p 11444 -L 11455:10.10.12.121:2932 -NT
Tunnel D (Reestablish): ssh Professor@localhost -p 11455 -D 9050 -NT
      IH: ssh Professor@localhost -p 11455
          ss -ntld  (see the random highport that is open)
      IH: proxychains nc localhost 23456



Network analysis
================
==== Day 6 =====
================

for CTFs WireShark
- change info to packet bytes? To look for a string inside a packet.
- filter:' tcp contains "password" '(a filter that will see if a header contains the information provided. It's very powerful). 
- filter:'!(contains "password")' (looks for results NOT containing password)
- TACACS+ is an authentication protocol that allows you to log into multiple decides. If you don't know what a protocol does look into it.



Traffic Filtering
=================
====  Day 7 =====
=================


# South Park Tunnel

from BIH:

telnet Eric's_IP
Eric: ssh student@10.50.30.41 -R 11411:localhost:8462 (tunnel 1)
IH: ssh Eric@localhost -p 11411 -L 11422:192.168.100.60:22 -NT (tunnel 2)
IH: ssh Kenny@localhost -p 11422 -L 11433:10.90.50.140:6481 -NT (tunnel 3)
IH: ssh Kyle@localhost -p 11433
Kyle: telnet 172.20.21.5 
Stan: ssh Kyle@172.20.21.4 -R 11444:localhost:22 -NT
IH: ssh Kyle@localhost -p 11433 -L 11455:localhost:11444 (this should connect to Stan)
IH: ssh Stan@localhost -p 11455 -D 9050 -NT  (place our tools there on Stan)
IH: ssh Stan@localhost -p 11455  
    Stan: (you can now work in Stan)



# from Archer:

IH: ssh Sterling@float

Sterling: telnet 10.12.128.200
Lana: ssh Sterling@localhost -R 11411:localhost:8976 (tunnel 2)

IH: ssh Sterling@float -L 11422:localhost:11411 -NT
IH: ssh Lana@localhost -p 11422 -L 11433:10.2.5.20:22 -NT
IH: ssh Cheryl@localhost -p 11433
Cheryl: telnet 10.3.9.39
Malory: ssh Cheryl@10.3.9.33 -R 11444:localhost:3597 -NT
IH: ssh cheryl@localhost -p 11433 -L 11455:localhost:11444 -NT
IH: ssh malory@localhost -p 11455 -D 9050 -NT
IH: proxy chains (etc...)

OR

(this is used in the instance the boxes you're ssh'ing through don't have telnet)
IH: ssh sterling@float -L 11499:10.1.2.200:23 -NT
IH: telnet localhost 11499
Lana: ssh sterling@10.1.2.130 -R 114211:localhost:8976 -NT
IH: ssh sterling@float -L 11422:localhost:11411 -NT
IH: ssh lana@localhost -p 11422 -L 11433:10.2.5.20:22 -NT 
IH: ssh Cheryl@localhost -p 11433 -L 11498:10.3.9.39:23 -NT
IH: telnet localhost 11498
Malory: ssh Cheryl@10.3.9.33 -L 11444:localhost:3597
IH: ssh Cheryl@localhost -p 11433 -L 11455:10.3.9.39:11444
IH: ssh Malory@localhost -p 11455 -D 9050 -NT




Access Control -
Network


OUTCOMES
Demonstrate the Use of Firewalls
Discuss Filtering with Routers
Explain Filtering with an Intrusion Detection System (IDS)
Discuss Operation System Filtering

Describe firewall type
Zone-Based Policy Firewall (Zone-Policy Firewall, ZBF or ZFW)
Host Based Firewalls
Network Based Firewalls

Determine positioning of filtering devices on a network
Determine network segments
Conduct Audit
Filtering devices we need
Device placement

Typical locations for filtering devices
IPS
Firewalls
Routers
Switches

Interpret Cisco access control list (ACL)


Syntax to create Access Lists
Demo> enable #enter privileged exec mode
Demo# configure terminal #enter global config mode
Demo(config)# access-list 37 ... (output omitted) ...
Demo(config)# ip access-list standard block_echo_request
Demo(config)# access-list 123  ... (output omitted) ...
Demo(config)# ip access-list extended zone_transfers
What types of ACLs were created?

Standard Numbered ACL Syntax
router(config)# access-list {1-99 | 1300-1999}  {permit|deny}  {source IP add}
                {source wildcard mask}
router(config)#  access-list 10 permit host 10.0.0.1
router(config)#  access-list 10 deny 10.0.0.0 0.255.255.255
router(config)#  access-list 10 permit any

nt example
placement4
Syntax to create Access Lists
Demo> enable #enter privileged exec mode
Demo# configure terminal #enter global config mode
Demo(config)# access-list 37 ... (output omitted) ...
Demo(config)# ip access-list standard block_echo_request
Demo(config)# access-list 123  ... (output omitted) ...
Demo(config)# ip access-list extended zone_transfers
What types of ACLs were created?

Standard Numbered ACL Syntax
router(config)# access-list {1-99 | 1300-1999}  {permit|deny}  {source IP add}
                {source wildcard mask}
router(config)#  access-list 10 permit host 10.0.0.1
router(config)#  access-list 10 deny 10.0.0.0 0.255.255.255
router(config)#  access-list 10 permit any
Standard Named ACL Syntax
router(config)# ip access-list standard [name]
router(config-std-nacl)# {permit | deny}  {source ip add}  {source wildcard mask}
router(config)#  ip access-list standard CCTC-STD
router(config-std-nacl)#  permit host 10.0.0.1
router(config-std-nacl)#  deny 10.0.0.0 0.255.255.255
router(config-std-nacl)#  permit any


Extended Numbered ACL Syntax
router(config)# access-list {100-199 | 2000-2699} {permit | deny} {protocol}
                {source IP add & wildcard} {operand: eq|lt|gt|neq}
                {port# |protocol} {dest IP add & wildcard} {operand: eq|lt|gt|neq}
                {port# |protocol}
router(config)# access-list 144 permit tcp host 10.0.0.1 any eq 22
router(config)# access-list 144 deny tcp 10.0.0.0 0.255.255.255 any eq telnet
router(config)# access-list 144 permit icmp 10.0.0.0 0.255.255.255 192.168.0.0
                0.0.255.255 echo
router(config)# access-list 144 deny icmp 10.0.0.0 0.255.255.255 192.168.0.0
                0.0.255.255 echo-reply
router(config)# access-list 144 permit ip any any


Extended Named ACL Syntax
router(config)# ip access-list extended  [name]
router(config-ext-nacl)# [sequence number] {permit | deny} {protocol}
                         {source IP add & wildcard} {operand: eq|lt|gt|neq}
                         {port# |protocol} {dest IP add & wildcard} {operand:
                         eq|lt|gt|neq} {port# |protocol}
router(config)# ip access-list extended CCTC-EXT
router(config-ext-nacl)# permit tcp host 10.0.0.1 any eq 22
router(config-ext-nacl)# deny tcp 10.0.0.0 0.255.255.255 any eq telnet
router(config-ext-nacl)# permit icmp 10.0.0.0 0.255.255.255 192.168.0.0
                         0.0.255.255 echo
router(config-ext-nacl)# deny icmp 10.0.0.0 0.255.255.255 192.168.0.0
                         0.0.255.255 echo-reply
router(config-ext-nacl)# permit ip any any


ACLs can be used for:
Filtering traffic in/out of a network interface.
Permit or deny traffic to/from a router VTY line.
Identify authorized users and traffic to perform NAT.
Classify traffic for Quality of Service (QoS).
Trigger dial-on-demand (DDR) calls.
Control Bandwidth.
Limit debug command output.
Restrict the content of routing updates.


ACLs rules
One ACL per interface, protocol and direction
Must contain one permit statement
Read top down
Standard ACL generally applied closer to traffic destination
Extended ACL generally applied closer to traffic source


ACLs rules
Inbound processed before routing
Outbound processed after routing
Does not apply for SSH or telnet traffic to device
Does not apply to traffic from the device
Only standard ACLs on VTY lines



Apply an ACL to an interface or line
router(config)#  interface {type} {mod/slot/port}
router(config)#  ip access-group {ACL# | name} {in | out}
router(config)#  interface s0/0/0
router(config-if)#  ip access-group 10 out
router(config)#  interface g0/1/1
router(config-if)#  ip access-group CCTC-EXT in
router(config)#  line vty 0 15
router(config)#  access-class CCTC-STD in


ACL Placement



ACL Placement 3
Interpret this ACL:

access-list 101 deny udp host 19.3.0.29 10.5.0.0 0.0.0.255 eq 69
access-list 101 deny tcp any 10.3.0.0 0.0.0.255 eq 22
access-list 101 deny tcp any 10.1.0.0 0.0.0.255 eq 23
access-list 101 deny icmp any 10.5.0.0 0.0.0.255 echo
access-list 101 deny icmp any 10.5.0.0 0.0.0.255 echo-reply
What Type of list is this?

What would it do?

Where should it be placed (use diagram on previous slide)?

What direction?



Understand Intrusion Detection or Prevention Systems


Contrast Intrusion Detection Systems and Intrusion Prevention Systems
Placement
  In line
  or not


Discuss Signature vs Behavior based detection
Recognition Methods
Signature
Heuristic aka Behavioral


Construct advanced IDS (snort) rules

Installation Directory
/etc/snort

Configuration File
/etc/snort/snort.conf

Rules Directory
/etc/snort/rules


Construct advanced IDS (snort) rules
Rule naming
  [name].rules
Default Log Directory
  /var/log/snort


Construct advanced IDS (snort) rules
Common line switches
-D - to run snort as a daemon
-c - to specify a configuration file when running snort
-l - specify a log directory
-r - to have snort read a pcap file


Construct advanced IDS (snort) rules
To run snort as a Daemon
sudo snort -D -c /etc/snort/snort.conf -l /var/log/snort

To run snort against a PCAP
sudo snort -c /etc/snort/rules/file.rules -r file.pcap


Snort IDS/IPS rule - Header
[action] [protocol] [s.ip] [s.port] [direction] [d.ip] [d.port] ( match conditions ;)
* Action - alert, log, pass, drop, or reject
* Protocol - TCP, UDP, ICMP, or IP
* Source IP address - one IP, network, [IP range], or any
* Source Port - one, [multiple], any, or [range of ports]
* Direction - source to destination or both
* Destination IP address - one IP, network, [IP range], or any
* Destination port - one, [multiple], any, or [range of ports]


Snort Rule Options
Categories
  General
  Payload detection
  Non-payload detection
  Post detection
  Thresholding and suppression

Snort IDS/IPS General rule options:
* msg:"text" - specifies the human-readable alert message
* reference: - links to external source of the rule
* sid: - used to uniquely identify Snort rules (required)
* rev: - uniquely identify revisions of Snort rules
* classtype: - used to describe what a successful attack would do
* priority: - level of concern (1 - really bad, 2 - badish, 3 - informational)
* metadata: - allows a rule writer to embed additional information about the rule
* 
Snort IDS/IPS Payload detection options:
* content:"text" - looks for a string of text.
* content:"|binary data|" - to look for a string of binary HEX
* nocase - modified content, makes it case insensitive
* depth: - specify how many bytes into a packet Snort should search for the
           specified pattern
* offset: - skips a certain number of bytes before searching (i.e. offset: 12)
* distance: - how far into a packet Snort should ignore before starting to
              search for the specified pattern relative to the end of the
              previous pattern match
* within: - modifier that makes sure that at most N bytes are between pattern
            matches using the content keyword
  
Snort IDS/IPS Non-Payload detection options:
* flow: - direction (to/from client and server) and state of connection
         (established, stateless, stream/no stream)
* ttl: - The ttl keyword is used to check the IP time-to-live value.
* tos: - The tos keyword is used to check the IP TOS field for a specific value.
* ipopts: - The ipopts keyword is used to check if a specific IP option is present
* fragbits: - Check for R|D|M ip flags.
* dsize: - Test the packet payload size
* seq: - Check for a specific TCP sequence number
* ack: - Check for a specific TCP acknowledge number.
* flags: - Check for E|C|U|A|P|R|S|F|0 TCP flags.
* itype: - The itype keyword is used to check for a specific ICMP type value.
* icode: - The icode keyword is used to check for a specific ICMP code value.

Snort IDS/IPS Post detection options:
* logto: - The logto keyword tells Snort to log all packets that trigger this rule to
           a special output log file.
* session: - The session keyword is built to extract user data from TCP Sessions.
* react: - This keyword implements an ability for users to react to traffic that
           matches a Snort rule by closing connection and sending a notice.
* tag: - The tag keyword allow rules to log more than just the single packet that
         triggered the rule.
* detection_filter - defines a rate which must be exceeded by a source or destination
                     host before a rule can generate an event.

Snort IDS/IPS Thresholding and suppression options:
threshold: type [limit | threshold | both], track [by_src | by_dst],
count [#], seconds [seconds]
* limit - alerts on the 1st event during defined period then ignores the rest.
* threshold - alerts every [x] times during defined period.
* both - alerts once per time internal after seeing [x] amount of occurrences
         of event. It then ignores all other events during period.
* track - rate is tracked either by source IP address, or destination IP address
* count - number of rule matching in [s] seconds that will cause event_filter
          limit to be exceeded
* seconds - time period over which count is accrued. [s] must be nonzero value

Snort rule example
Look for anonymous ftp traffic:
alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous";
sid:2121; )

This will cause the pattern matcher to start looking at byte 6 in the payload)
alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous";
offset:5; sid:2121; )

Snort rule example
This will search the first 14 bytes of the packet looking for the word “anonymous”.
alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous";
depth:14; sid:2121; )

Deactivates the case sensitivity of a text search.
alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous";
nocase; sid:2121; )


Interpret the effects of IDS/IPS rules on network traffic
IDS/IPS Performance
True Positive (TP)

True Negative (TN)

False Positive (FP)

False Negative (FN)


Technical Attacks on IDS/IPS
  packet sequence manipulation
  fragmenting payload
  overlapping fragments with different reassembly by devices
  Manipulating TCP headers
  Manipulating IP options
  Sending data during the TCP connection setup


Non-Technical attacks against IDS/IPS
  attacking during periods of low manning
  Example - Ramadan 2012 Saudi Aramco attack
  attacking during a surge in activity
  Example - Target Corp. Point of Sale machines during the Thanksgiving-Christmas 2013 shopping season

Strengthening Defensive Systems
  Linking IDS/IPS to other tools
  Multiconfig
  Tuning
  HIDS and File Integrity


Access Controls - Network Complete
Check intel on the CTF server for new information regarding mission tasks


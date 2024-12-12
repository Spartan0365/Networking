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
#Active External Discovery# - #Ping# , #NMAP Defaults# , #Traceroute - Firewalking# , #Netcat - Horizontal Scanning# , #Netcat - Vertical Scanning#
                              #TCP SCAN SCRIPT# , #UDP SCAN SCRIPT# , #BANNER GRABBING# , #CURL and WGET#
#Passive Internal Discovery# - #Packet Sniffers# , #IP Configuration# , #DNS configuration# , #ARP Cache# , #Network connections# , #Services File# , #OS Information# , #Running Processes# , #Command path# , #Routing Table#
                                #File search# , #SSH Config#
#Active Internal Discovery# - #ARP Scanning# , #Ping Scanning# , #DEV TCP Banner Grab# , #DEV TCP Scanning#  , 
#Network Forensics - Mapping#

=================


DAY 1
==================================================================

A 'float' must be used to get to the private net. This 'float' is not inside the network. Once inside the network, you won't be using the float anymore. 
Float info - ssh student@10.50.30.41 -X (connect through remmina)

==================
= Network Access =
==================

Protocol Data Unit:

Session-Application - Data
Transport - Segment/Datagram
Network   - packet
DataLink  - frame
Physical  - bit

Internet Standard Organizations:
IETF - Internet Engineering Task Force; If looking for information on a #header#, look into RFCs (requests for comment).  https://www.ietf.org/standards/
IANA - Internet Assigned Numbers Authority; responsible for global coordination of DNS root, IP addressing, Internet Numbers, etc. They Make the standards for much hardware in use today. https://www.iana.org/
RIR - Regional Internet Registries; 
IEEE - LAN/WAN electrical standards. https://www.ieee.org/

Layer 1: 
Binary (0000100010) - 1 bit, 4 bits (nibble), 8 bits (byte) 16 bits (half word) 32 bits (word)
Decmical - BASE10; regular numeric system.
Hexadecimal - BASE16 (16 symbols). format - 0x42, 0xE3, 0x73, 0xA5, etc. (examples) Single hex character is: 1 nibble. 
Base64 (A-z,a-z,0-9,+,/) format - MTI

LAN  Topologies and Devices:
Bus: All devices connected to a main line through junctions (terminators at the end).
Star: All devices connected to a central hub/switch. All devices talk to eachother but use their individual lines. 
Ring: All devices connected to each other from device-to-device, until all devices are connected in a ring. 
Mesh: All devices directly connected to every device. Partial Mesh: Devices are connected to most devices, if not it's no more than 1-2 hops away.
Wireless: All devices connected to an accept point that touches devices wirelessly. This allows for roaming (moving from one access-point area to another). 
Hierarchical: All devices connect their way op to a core lower of high-end switches. 

Devices:
Hubs - allow multiple nodes to connect on the same wire.
Switches - allows multiple nodes to connect on the network but on their own collision domain. 
Repeaters - extends your connection.
Routers - doesn't care for MAC addresses, but besides this it's a step up from a switch.

Ethernet Timing (Bit-Time):
Speed        Bit-time
10mbs        100ns


LAN Technologies and their benefits and hindrances
Ethernet - 
Wireless -
Token Ring -

Data Link Sub-Layers:
MAC (Media(or medium?) Access Control)
LLC (Logical Link Control)

Message Formatting Method and Teminology:
Frames -
Header 
Data 
Footer

Encapsulation and Decapsulation:
In order to pass information between protocl layers, PDUs (protocol data units) must be used, which pass informaiton down layers and back up. 

Switch Operation: 
Building MAC-Address (CAM) Table
  Learns bvy reading Source MAC Addresses
Forwarding Frames
  Decision based on Destination MAC Addresses

Switching Modes
  Cut-through mode
  Fragment-Free
  Store-and-forward

CAM Table Overflow Attack
  Send frames with bogus source MAC address to swtich
  Cause switch to fill table to bogus addresses
  Switch will not be able to learn new (valid) MAC addresses

Describe MAC Addressing
  48 bit length code
Format
  Windows - 01-23-45-12-34-56
  Linux 01:23:45:12:34:56
  Cisco 1234.5612.3456
Parts:
  OUI - the first 24-bits assigned by IANA
  Vendor assigned - last 24-bits assigned by vendor.

MAC Address Types:
  Unicast - one -to - one (unicast bit set to 0) 
  Multicast - sends to multiple (first bit set to 1) 01:00:5e:00:00:00.
  Broadcast - everyone is addressed: FF-FF-FF-FF-FF-FF or FF:FF:FF:FF:FF:FF or ffff.ffff.ffff

MAC Spoofing:


Ethernet Header and Frame:
IPv4 - 0x0800
ARP - 0x0806
IPv6 - 0x86DD
VLAN - 0x8100
Service VLAN tag identifier - 0x88A8
PPP over Ethernet (PPPoE) - 0x8863(4)
MPLS - 0x8847(8)
PROFINET - 0x8892

What is VLAN:
VLAN tag
  MAC Header is a 12-byte field. 6 bytes for Dest MAC and 6 bytes for Src Mac.


VLAN Types
  Default - VLAN 1 
  Data - User Traffic
  Voice - VOIP traffic
  Management - Switch and router management
  Native - Untagged switch and router traffic 

VLAN Hopping Attack
  Switching Spoofing (DTP)
  Single Tagging
  Double Tagging
  SCAPY Example Code

Describe ARP:
  Takes MAC and IP addresses in correspondence with each other.

#ARP Types#
  ARP (OP 1 and 2)
  RARP (OP 3 and 4)
  Proxy ARP (OP 2 )
  Gratuitous ARP (OP 2), think of this as unsolicited. It's not necessary. 

  Operation 1 is a request, and Operation 2 is a reply.
  Operation 3 is a RARP Request, Operation 4 is a RARP Reply. 
  
ARP Cache
  All resolved MAC to IP Resolutions
  If MAC is not in Cache then ARP is used
  Dynamic entries last 12-20 mins. 

MITM with ARP:
  Poison ARP cache with 
    Gratuitious arp
    Proxy arp

Explain VTP with its vulnerabilities:


VLAN Trunking Protocol
  Dynamically add/remove/modify/modify VLANs

VTP 
  Cisco proprietary
  Modes:
    Server
    Client
    Tansparent
    off mode

VTP Vulnerability
  Can cause switches to dump all VLAN information
  Cause a DoS as switch doens't support configured VLANs

Dynamic Trunking Protocl (DTP):
  used to dynamically create trunk links
  Cisco Proprietary
  Is turned on by default
  can send crafted messages to form a VLAN trunk link.
  Recommended to: 
    Disable DTP negotiations
      Manually assign as Access or Trunk

  CDP, FCP and LLDP
    Cisco Discvory Protocol
    Foundry Discovery Protocol
    Link Layer Discovery Protocol

      These: 
        Leak Valuable information, in clear text. 
        Enable by default.
        Disable this: globally, per interface. 
      These may be required for VOIP.

Explain Spanning Tree Protocol: 
  Spanning Tree Protocl (STP)
    It figures out the best route to a destination and then only used that one. 
    It asks every switch for their root switch and designated ports so it knows what not to use. 
    R is a port it uses to get to the root.
    D is a designated port that must be open. 

    1. Elect root Bridge
    2. ID the root ports on non-root bridge
    3. ID the designated port for each segment. 

  STP Types
    802.1D STP
    802.1w - Rapid Spanning Tree Protocol (RSTP)
    Rapid Per VLAN Spanning Tree (Rapid PVST)

  Spanning Tree attack
    Crafted bridge protocl data units. (BDPUs)

  Port Security
    Shutdown (default) - shut down a port, sends an SNMP trap notification.
    Protect - will drop any frames from unkown source addresses.
    Restrict - it will keep the port up, but this option will log it.

  Layer 2 attack mitigation techniques:
    Shutdown unused ports
    Enable port security
    IP source guard
    Manually assign STP Root
    BPDU Guard
    DHCP Snooping
  
  other techniques:
    802.1x - a client based authentication
    Dynamic ARP inspection (DAI)
    Static CAM entries (not recommended)
    Stat ARP entries
    Disable DTP negotiations
    Manually assign Access/Trunk Ports
    

====================
= Network Layer FG =
====================

IP versions
  IPv4 (ARPANET 1982)
    Classful subnetting
    classless subnetting
    NAT
  Ipv6
  
Describe Classful IPv4 Addressing and Subnetting
  Class A (0 - 127)
  Class B 
  etc.

Subnetting


Analyzing IPv4 Packet Header
  Version  Internet-Header-Length  Differentiated-Service-Code-Point  Explicit-Congestion-Notification  Total-Length  Identification  Flags  Fragment-Offset  

  
  Time-to-Live  Protocol  Header-Checksum  Src.Address  Dest.Address   Options
  

IPv4 Address Types
  Unicast
  ...

IPv4 Address Scopes
  Public
  Private (RFC1918)
  Loopback (127.0.0.0/8)
  Link-Local (APIPA) - automatically assigns an IP address to a newly registered device. 
  Multicast (class D)

IPv4 Fragmentation
  Breaks up packets from a higher MTU to a lower MTU.

Fragmentation Process
  Teardrop Attack - takes advantage of the fragmentation process. 

IPv6 Fragmentation
  does not support fragmentation within it's header.
  Routers do not fragmetn IPv6 packets
  Source adjusts MTU to avoid fragmentation
  Source can use IPv6 fragmentation extension header. 

Fragmentation Vulnerability

OS Fingerprinting with TTL
  Vendors have chosen different values for TTL which can provide insight to which OS family a generated packet is from. 

IPv4 Auto Configuration 
  APIPA
    169.254.0.0/16
    RFC 3927
  DHCP
    DORA Process
    RFC 1531

IPv4 Auto Config Vulnerability
  Rogue DHCP Server
  Evil Twin
  DHCP Starvation

Analyze ICMPv4 Protocol and Header Structure
  ICMP is more of a management protocol.
  Type 8 - echo request
  Type 0 - echo reply
  Type 3 - Destination Unreachable
  etc.

ICMPv4 OS Fingerprinting
  Linux   
    Default size is 64-bytes
    payload message: 
    ...

  Windows
    Default size is 48-bytes
    payload message:


  ICMPv4 Traceroute
    #Traceroute#
    #Firewalking#
traceroute 8.8.8.8
sudo traceroute 8.8.8.8 -T
sudo traceroute 8.8.8.8 -T -p 443
sudo traceroute 8.8.8.8 -U -p 123 
sudo traceroute 8.8.8.8 -I

  SMURF Attack
    Cracks a custom ICMP message.
    Takes advantage of broadcasting. 

  IPunreachable messages to map a network

  ICMP Cover Channel


Explain IPv6 Addressing
  128 bits long
  Same fields
    Fields no longer here: optons, padding, IHL, identification, Flags, Fragment Offset, Header Checksum. 
    New field: Flow label.
    
IPv6 Representation
    2001:0db8:85a3:0000:0000:8a2e:0370:7334,

Identify IPv6 Address Types:
  Type 128 - request
  Type 129 - reply
  Type 134 - Router Advertisement
  Type 136 - Neighbor Advertisement
  
Ipv6 Address Scopes

Ipv6 Zero Configuration (link-local)
  

Vulnerabilities;
  SLAAC MITM

ICMP also supports ICMPv6

Explain Neighbor Discovery Protocol (NDP)
 Router Solicitation 
 ...

Discuss Routing:
  How does a router know where to send a packet when it arrives? It looks at it's routing table. 
  The routing table is just a list of networks to which the packet can be fwded to. 
  
Think back to JCAC. The Enterprise Level Networking Mod provided a lot of examples of routing tables. These same tables are where we'll get all of our routing information from for a given network. 

Administrator Distance:
  Connected 0
  Static 1
  EIGRP 5
  External BGP 20
  Internal EIGRP 90
  IGPR 100
  OSPF 110
  IS-IS 115
  etc.

Lookup Process:

Metrics: 
  RIP - Hop
  EIGPR - Bandwidth, Delay, Load, Reliability
  OSPF - Cost
  BGP - Policy

Dynamic Routing Protocols
  Classful                          vs.      Classless
  -Doesn't carry
  subnet mask info within 
  the routing updates.
  -Exchange routing updates at
  Regular Time Intervals.
  -Use periodic updates
  -Do not use Hello messages
  -Consumes more network
    bandwidth.
  -Does not support CIDR and VLSM

Classless is newer. 

  Routed vs Routing Protocols
  
IGP and EGP 
 Interior Gateway Protocol - only functions within its AS (a number designated to your network).
 Exterior Gateway Protocol - used to exchange routing information between autonomous systems. 

BGP
 Border Gateway Protocol - the only currently viable EGP and is the official routing protocol used by the internet. 

AS
 Autonomous System - Collection of connected internet protocol routing prefixes unther the control of one or more network operators on behalf of a single administrative entity or domain, that presents a common and clearly defined routing  policy to the internet. 
 Usually these ASs are regionally based, and these regions are assigned by IANA. 

Autonomous systems are 16-bit or 32-bit: 
AS109   CISCO-EU-109 Cisco Systems Global ASN
AS193   FORD-ASN - Lockheed Martin Western Development Labs
AS721   DoD Network Information Center Network
AS3598  MICROSOFT-CORP-AS - Microsoft Corporation
AS15169 GOOGLE - Google Inc.

Distance Vector Routing Protocols: 

  
Link State Routing Protocol:
  Builds its own tree, which is then broadcasted out and all devices wil then use the broadcasted route. 

Distance Vector vs Link State:


Routing Protocol Vulnerabilities:
  DDOS
  PMA - Packet Mistreating Attack
  RTP - Routing Table Poisoning
  HAR - 
  PA

BGP
  again, this is the road-map of the internet.
  Routes traffic between AS numbers.
  Advertises IP CIDR Address blocks. 
  Establishes peer relationships. 

BGP Operation
  How it chooses the best path:
    Advertises a more specific route. 
    Offers a shorter route

BGP Hijacking
  Illegitimate advertising of Addresses
  BGP Propogates false informaiton
  Purpose:
    Stealing prefixes
    monitoring traffic
    intercept internet traffic
    'black hoking' traffic
    perform MitM

BGP Hijacking Defense
  IP prefix filtering
  BGP Hijacking detection
    tracking the change in TTL of incoming packets
    increased roung tip time (RTT) which increases latency.
    Monitoring misdirected traffic
  BGPSec

Dynamic vs. Static Routing
  Dynamic is often preferred because it is easy. Static won't send updates (burn bandwidth) and it's data path is pre-determined. However, it's also time-consuming, prone to error, must have its problems resolved by an admin, and does      not scale well for large network growth. 

  Dynamic Routing is easy to configure and maintain, no intervention needed for network outages and scales well for large networks. However, it consumes a lot of badnwidth and resources, updates can be intercepted and data-path is NOT      predetermined. 

First Hop Redundancy Protocol
  HSRP - provides default gateway redundancy using one active and one stadby router.
  VRRP - Open standard alternative to Cisco's HSRP, providing the same functionality.
  GLBP - Supports arbitrary load balancing in addition to redundancy across gateways; cisco proprietary. 

FHRP Attack
  Intercept the FHRP message exchange
  Inject manipulated messages
  MitM by becoming the active forwarder.

============================
= Transport to Application =
============================

Transport Layer Protocols
  Connection-oriented
    TCP - Segments
    Unicast Traffic
  Connetion-less
    UDP - Datagrams
    Broadcast, Multicast, or unicast traffic.

Port Ranges
  0 - 1023 Well-known (system)
  1024 - 49151 Registered (User)
  49152 - 65535 Dynamic (Private)

TCP Reliability
  1 Connection Establishment
    3-way handshake
  2 Data Txfer
    Extablished phase
  3 Connection Termination
    4-way termination

TCP Headers

TCP States

TCP Options


UDP Headers
  Cares about the source, destination and how big the packet is. 
  (Fire and Forget)

Virtual Private Networks (VPN)
  Connects through a network that is not accessible to everyone else. This "private" connection makes it look like it is a direct connection when it is in fact NOT.   
  Types:
    Remote Access (Client-to-Client)
    Site-to-Site (Router-to-Router)

L2TP
  Layer 2 Tunneling protocol. Everything is clear-text visible with this. 

PPTP
  Some encryption, but mostly obsolete.
    
IPSec 
  Most popular suite of protocols used today because it DOES provide encryption.
  Transport mode: only encrypts the payload   
  Tunnel mode: used for end to end communication between two hosts or devices.
  
OpenVPN
  
Proxies 
  A vital intermediary that stands between a user's device, either a computer or smartphone, and the vast expanse of the internet. It acts as a sophisticated gateway. 
  They are instrumental guardians of privacy, gatekeepers for access control and enchangers of overall inernet efficiency. 

SOCKS 4/5 (TCP 1080)
  Socket Secure, is a protocol that facilitates communication between clients and servers through a proxy server. 

SOCKS 4
  No authentication
  only IPv4
  No UDP Support
  No Proxy binding. CLient's IP is not relayed to destination. 
SOCKS 5
  Better than SOCKS 4

Network Basic Input Output System Protocol
  TCP 139 and UDP 138

RPC (any port)
  Allows a program to execute a request on a local/remote computer
  Hides network complexities

API   
  A Framework of rules and protocols for software components to interact
  Methods, parameters, and data formats for requests and responses.
    REST and SOAP

Presentation Layer
  Translation and transformation

Telnet (TCP 23)
  Remote login
  Authentication
  Clear Text
  Credentials susceptible to interception

SSH (TCP 22)
  Messages provided:
    Client/Server Authentication
    Asymmetric or PKI for key exchange
    Symmetric for session
    User authentication
    Data Stream Channeling

Components of SSH Architecture
  Client/Server/Session
    Keys
      User Key
      Host Key 
      Session Key

SSH Implementation Concerns
  Using password authentication only
  Key rotation
  key management
  implementation specification (libssh, sshtrangerthings)

SSH Usage
#SSH#
$ ssh {user}@{ip}
$ ssh student@172.16.82.106


-X = This will enable X11 graphics to be forwarded from the server to the client. This will allow you to open graphical applications such as pcmanfm, gimp, eog, eom, firefox, terminator, and more. ssh student@172.16.82.106 -X
    This option will allow you to view images.  
-v = Enables verbose mode, which provides detailed debugging information about the SSH connection process. This can be helpful for diagnosing connection issues or troubleshooting SSH configuration problems. ssh student@172.16.82.106 -v

-f = Requests SSH to go to the background just before command execution. This is useful when running SSH commands as part of scripts or automation tasks. This is not to be confused with the & option which is used to background most applications. ssh student@172.16.82.106 -f

-i {identity file} = Selects a file from which the identity (private key) for RSA or DSA authentication is read. The default is ~/.ssh/identity for protocol version 1, and ~/.ssh/id_rsa and ~/.ssh/id_dsa for protocol version 2. ssh student@172.16.82.106 -i idfile.pub

-F {config file} = Specifies an alternative per-user configuration file. If a configuration file is given on the command line, the system-wide configuration file (/etc/ssh/ssh_config) will be ignored. The default for the per-user configuration file is ~/.ssh/config. ssh student@172.16.82.106 -F my.config

-N = Requests that no command be executed on the remote server after establishing the SSH connection. This can be useful when setting up port forwarding or establishing a tunnel without running a command on the remote server. ssh student@172.16.82.106 -NT

-T = Disables pseudo-terminal allocation, preventing the allocation of a terminal on the remote server. This can be useful when executing commands that do not require interaction or terminal emulation. ssh student@172.16.82.106 -NT

-C = Enables compression of data during transmission over the SSH connection, reducing bandwidth usage, especially over slow or high-latency connections. ssh student@172.16.82.106 -C

-J user@host = Specifies a jump host to connect through when establishing the SSH connection. This simplifies the process of connecting to a remote host that is not directly accessible from the local machine. ssh -J student@10.10.0.40, student@172.16.1.15, student@172.16.40.10 student@172.16.82.106

-L [bind_address:]port:host:hostport = Sets up local port forwarding, allowing connections to a local port to be forwarded over the SSH tunnel to a specified host and port on the remote server. This can be useful for accessing services running on a remote server through a secure tunnel. ssh student@172.16.82.106 -L 1234:192.168.1.10:22

-R [bind_address:]port:host:hostport = Sets up remote port forwarding, allowing connections to a specified port on the remote server to be forwarded over the SSH tunnel to a host and port on the local machine or another remote server. This can be useful for exposing services running on the local machine to the remote server or other remote machines. ssh student@10.10.0.40 -L 1234:172.16.40.10:22

-D {port} = Specifies a local "dynamic" port forwarding port. This creates a SOCKS proxy on the specified port, allowing other applications to tunnel their traffic through the SSH connection securely. ssh student@172.16.1.15 -D 9050

Expect a warning when initially connecting through SSH.
  Warns that the Host Key Changed (you connected to somebody else this session than you did during your last session).
  This could be a warning if you noticed you're getting this message but you hadn't connected to any different users since the last time you SSHd.

#SSH Files# , SSH Configuration Files
  cat .ssh/known_hosts
      /etc/ssh/ssh_config
      /etc/ssh/sshd_config

View/Change SSh Port
  To view current configured SSH Port 
    cat /etc/ssh/sshd_config | grep Port
  To edit file to change the SSH Port
    sudo nano /etc/ssh/sshd_config

  SSH-KeyGen
    ssh-keygen -t rsa -b 4096 -C "Student"

  SH-Copy-ID
    ssh-copy-id student@172.16.82.106

HTTP(S) (TCP 80/443)
  User Request Methods
    Get/HEAD/POST/PUT
  Server Response Codes 
  100,200,300,400,500
  Vulnerabilities
    Flooding
    Amplification - makes the attack appear as if it is originating from multiple sources.
    Low and slow - functions by opening connections to a targeted web-server and then keeping those connections open as long as it can. 
    Drive-by Downloads - 
    BeEF Framework

DNS (TCP/UDP 53)
  DNS Query / Response
    Resolves Names to IP Addresses
    Queries and responses use UDP
    DNS response larger than 512 bytes
      DNS Zone transfer

  DNS Records
  A - Ipv4
  AAAA - IPv6
  MX - Mail Server Record
  TXT - Human-readable text
  NS - Name Server Record
  SOa - Start of Authority

  Architecture
    Root Domain
    Tol-Level Domain : .com .org .net .gov
    Second-Level Domain : .att .google .lana .wikipedia
    Third-Level Domain : www drive mail 

FTP (TCP 20/21)
  RFC 959
  Port 21 open for Control
  Port 20 only open during data transfer
  Authentication or anonymous
  Clear text
  Modes: 
    Active (default)
    Passive

  FTP Active
    Client initiates the connection with a server on port 21 from the client's ephemeral high port. 
    3-Way Handshake 
  FTP Active Issues
    NAT and Firewall Traversal issues
    Complications with tunneling
  
  FTP Passive
    Passive FTP sidesteps the issue of Active mode by reversing the conversation. Client initiates both the command and the data connections. 

TFTP (UDP 69)
  Clear text
  Reliability provided at Application layer
  Used by routers and switches to transfer IOS and config files

SMTP (TCP 25)
  Used to send email
  No encryption
  SMTP over...

POP (TCP 110)

IMAP (TCP 143)

DHCP (UDP 67/68)
  How you get an IP address if you don't have one.

DHCPv4
  DORA

DHCPv6
  SLAAC

NTP (UDP 123)
   Stratum 0 - authoritative time source
     Up to stratum 15
     Vulnerable to crafted packet injection
     Can break time sensitive applications.

AAA Protocols
  Authentication, Authorization, Accounting
  For Third party authentication

    TACACS (TCP 49) Simple/Extended
      It's a network security protocol used for centralized authentication, authorization and accounting services in network devices such as routers, switches and firewall.

  RADIUS (UDP 1645/1646 and 1812/1813)

  Analyze Diamaeter Protocol (TCP 3868)

  SNMP (UDP 161/162)
    7 Message Types:
      Get Request
      Set Request
      Get Next
      Get Bulk
      Response
      Trap
      Inform
    Vulnerabilities: 
      Weak community string
      Lack of encryption
      Information disclosure

RTP (UDP any above 1023)

RDP (TCP 3389)
  Developed by Microsoft (open standard)
  No server software needed

KERBEROS (UDP 88)
  Issues out tickets. 
  Secure network authentication protocol.
  Clients obtain tickets to access services.
  mutual athentication.
  used by active directory. 

LDAP (TCP 389 and 636)
  Client/server model
  Higherarchical
  Directory Schema
  Unsecure and secure versions







==================================
=========     Day 2    ===========
==================================







Sniffing Tools and Methods
  Practical Uses
    Network troubleshooting
    diagnosing improper routing or switching
    identifying port/protocol misconfigurations
    monitoring networking consumption
    intercepting usernames and passwords
    eavesdrop on network communications.
  Disadvantages:
    Requires elevated permissions
    Can only capture what the NIC can see
    Cannot capture local traffic
    can consume massive amounts of system resources
    lost packets on busy networks
  Packets can be captured by:
    Hardware packet sniffers
    Software Packet sniffers

Describe Socket Types
  User Space Sockets
    Stream socket - TCP
    Datagram socket - UDP
  Kernel Space Sockets
    RAW Sockets

Capture library 
  Requires root for:
    promiscious mode (listens on all NICs)
    All captured packets are created as RAW sockets

Types of Sniffing
  Active
  Passive

Popular Software Packet Capture Programs
  tcpdump, tshark, NetworkMiner, SolarWinds, EtterCap
  Wireshark, p0f, NetMiner, BetterCap

  other:
  Kismet, McAfee, Nmap, Snort, L0phCrack, ngrep, Scapy
  Suricata

Interface Naming
  Traditional: 
    eth0, eth1
  Consistent:
    eno1, ens3

Explain TCPDUMP Primitives #tcpdump#
  User Friendly capture expressions:
    src or dst
    host or net
    tcp or udp

basic tcpdump options:
  -A = print payload in ASCII
  -D = list interfaces
  -i = specify capture interfaces
  -e = print data-link headers
  -X or XX = print payload in HEX and ASCII
  -w = write to pcap
  -r = read from pcap
  -v, vv, or vvv = verbosity
  -n = no inverse lookups

TCPdump primitve qualifier:
  type- the 'kind of thing' that the id name or nubmer refers to:
    host, net, port, or portrange.
  dir - transfer direction to and/or from.
    src or dst
  proto- restricts the match to a particular protocol
    ether, arp, ip, ip6, icmp, tcp, or udp. 

Logical operators:
  Primitives can be combined using: 
    'and' (&&)
    'or' ( || )
    'not' (!)
Relational Operators
  < or <=
  > or >=
 = or == or !=

tcpdump primitive examples:
  simple
  extended

examples: sudo tcpdump -i eth0 arp
          or
          sudo tcpdump -i eth0 icmp
          sudo tcpdump -VVn-i eth0 icmp
          sudo tcpdump -vvn -i eth 0 icmp host 10.10.0.40
          sudo tcpdump -vvn -i eth 0 icmp dst host 10.10.0.40 or sudo tcpdump -vvn -i eth 0 icmp src host 10.10.0.40
          sudo tcpdump -vvn -i eth 0 icmp src host 10.10.0.0/24
          sudo tcpdump -vvn -i eth 0 icmp port 22
          sudo tcpdump host 192.168.1.1 and \( 1.1.1.1 or 10.1.1.2\) or sudo tcpdump host 192.168.1.1 and '1.1.1.1 or 10.1.1.2'

if having problems with tcpdump, you can enter debug mode. 
  ex. tcpdump "ether[12:2] = 0x800" -d 

  -d = Dump the compiled packet-matching code in human readable form. 
  lhd - loads half-word value in the accumulator from offset 12 in the ethernet header.
  jeq - check if the value is "0x800" and if this is true "jump true" to line if it is false "jump false" to line 3.

  
Construct a BPF #BPF# this is great for filtering out as much as possible and can make your job up to x20 quicker.
  tcpdump requests a RAW socket creation
  Filters are set using the SO_Attach_Filter
  So_Attach_Filter allows us to attach a Berkley Packet Filter to the socket to capture incoming packets. 

BPF examples:
  tcpdump -i eth0 'ether[12:2] = 0x0806'
  tcmpdump -e eth1 'ip[9] = 0x06'
  tcmpdump -i eth0 'tcp[0:2] =53 || tcp [2:2] = 53'
  tcpdump 'ether[12:2] 0x0800 && (tcp[2:2] != 22 && tcp[2:2] != 23)'
  [ :2] read 2 bytes
  [ :4] reads 4 bytes
  [ : ] reads 1 byte by default

  Bitwise masking examples
    tcpdump 'ether 'ether[12:2] = 0x0806'
    tcpdump ip[1] & 252 = 32' (filters for DSCP information, all DSCP value is between 32 and 4. (a 4 is a 1 for DSCP))
    tcpdump 'ip[6] & 224 = 32' 
    tcpdump 'tcp[13] & 0x11 = 0x11'
    tcpdump 'tcp[12] & 0xf0 > 0x50' (filters for byte 12, and the for bits turned on within the offset value only ( 0xf0) that are greater than 0x50. 
  
Filter logic most exclusive:
  tcp[13] & 0x11 = 0x11
Least exclusive:
  tcp[13] & 0x11 > 0
  tcp[13] & 0x11 !=0

BPFS at the Data-Link Layer
  Searching for the destination broadcast MAC address.
    'ether[0:4] = 0xffffffff && ether[4:2] = 0xffff'
    'ether[0:2] = 0xffff && ether[2:2]= 0xffff && ether[4:2] = 0xffff'

  Searching for the source MAC address.
    'ether[6:4] = 0xfa163ef0 && ether[10:2] = 0xcafc'
    'ether[6:2] = 0xfa16 && ether[8:2] = 0x3ef0 && ether[10:2] = 0xcafc'

BPFS at the Data-Link Layer
  'ether[0] & 0x01 = 0x00'
  'ether[0] & 0x01 = 0x01'
  'ether[6] & 0x01 = 0x00'
  'ether[6] & 0x01 = 0x01'

Search for IPv4, ARP, VLAN Tag, and IPv6 (respectively)
  ether[12:2] = 0x0800
  ether[12:2] = 0x0806
  ether[12:2] = 0x8100
  ether[12:2] = 0x86dd

Searching for 802.1Q VLAN 100
  'ether[12:2] = 0x8100 && ether[14:2] & 0x0fff = 0x0064'
  'ether[12:4] & 0xffff0fff = 0x81000064'
  
Search for double VLAN tag
  'ether[12:2] = 0x8100 && ether[16:2] = 0x8100'

BFPS at the Network Layer
  Search for IHL greater than 5
    'ip[0] & 0x0f > 0x05'
    'ip[0] & 15 > 5'

Search for ipv4 DSCP value of 16
  'ip[1] & 0xfc = 0x40'
  'ip[1] & 252 = 64'
  'ip[1] >> 2 = 16' (>> means drop two bytes from the right, meaning the start point moves further to the left (by 2))

Search for traffic class in ipv6 having a value
  'ip6[0:2] & 0x0ff0 != 0'

Search only for the RES flag set. DF and MF must be off. 
  'ip[6] & 0xE0 = 0x80'
  'ip[6] & 224 = 128'

Search for RES bit set. The other 2 flags are ignored so they can be on or off. 
  'ip[6] & 0x80 = 0x80'
  'ip[6] & 128 = 128'

Search for ONLY the DF flag set. RES and MF must be off.
  'ip[6] & 0xE0 = 0x40'
  'ip[6] & 224 = 64'

Search for #TCP DF (Don't Fragment) bit# set. The other 2 flags are ignored so they can be on or off.
  'ip[6] & 0x40 = 0x40'
  'ip[6] & 64 = 64'
  example:
    'ip[6] & 64 != 0' (this will filter for all IPv4 packets with at least the Dont Fragment bit set)
    sudo tcpdump -n "ip[6] & 64 != 0" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l
    
Search for ONLY the MF flag set. RES and DF must be off.
  'ip[6] & 0xe0 = 0x20'
  'ip[6] & 224 = 32'

Search for MF bit set. The other 2 flags are ignored so they can be on or off.
  'ip[6] & 0x20 = 0x20'
  'ip[6] & 32 = 32'

Search for offset field having any value greater than zero (0).
  'ip[6:2] & 0x1fff > 0'
  'ip[6:2] & 8191 > 0'

Search for MF set or offset field having any value greater than zero (0).
  'ip[6] & 0x20 = 0x20 || ip[6:2] & 0x1fff > 0'
  'ip[6] & 32 = 32 || ip[6:2] & 8191 > 0'

 Search for #TTL# in ipv4(6) packet.
  'ip[8] = 128'
  'ip[8] < 128'
  'ip[8] >= 128'
  'ip6[7] = 128'
  'ip6[7] < 128'
  'ip6[7] >= 128'
  example syntax:
  "ip[8]<65||ip6[7]<65" ( this will search for ip and ipv6 packets with a ttl of 64 and less)
  sudo tcpdump -n "ip[8] < 65 or ip6[7] < 65" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l
  "ip[8]<=64 or ip6[7]<=64"

Search for ICMPv4(6), TCP, or UDP encapsulated within an ipv4(6) packet. #Filter for UDP and TCP Packets#
  'ip[9] = 0x01'
  'ip[9] = 0x06'
  'ip[9] = 0x11'
  'ip6[6] = 0x3A'
  'ip6[6] = 0x06'
  'ip6[6] = 0x11'
   example:
      'ip[9] = 0x11||ip6[6] = 0x11' (will filter for all UDP packets utilizing ipv4 and ipv6 headers)
      sudo tcpdump -n "ip[9] = 0x11||ip6[6] = 0x11" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

      
Search for ipv4 source or destination address of 10.1.1.1.
  'ip[12:4] = 0x0a010101'
  'ip[16:4] = 0x0a010101'

Search for ipv6 source or destination address starting with FE80.
  'ip6[8:2] = 0xfe80'
  'ip6[24:2] = 0xfe80'

Search for #TCP source port# 3389.
  'tcp[0:2] = 3389'
    example:
      'tcp[0:2] > 1024 || udp[0:2] > 1024' (this will filter for all ports greater than 1024)
      sudo tcpdump -n "tcp[0:2] > 1024 || udp[0:2] > 1024" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

      
Search for TCP destination port 3389.
  'tcp[2:2] = 3389'

Search for TCP source or destination port 3389.
  'tcp[0:2] = 0x0d3d || tcp[2:2] = 0x0d3d'

Search for TCP with options.
  'tcp[12] & 0xF0 > 0x50'
  'tcp[12] & 240 > 80'

Search for TCP Reserve field with a value.
  'tcp[12] & 0x0F != 0'
  'tcp[12] & 15 > 0'

Search for TCP Flags set to ACK+SYN. No other flags can be set.
  'tcp[13] = 0x12'

Search for TCP Flags set to ACK+SYN. The other flags are ignored.
  'tcp[13] & 0x12 = 0x12'

Search for TCP Flags ACK and SYN (both or 1 must be on).
  'tcp[13] & 0x12 != 0'
  'tcp[13] & 0x12 > 0'

Search for TCP Urgent Pointer having a value.
  'tcp[18:2] != 0'
  'tcp[18:2] > 0'

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



Recon Stages
    Passive External ( 
    Active External (on the outside trying to hit something on the inside)
    Passive Internal (internal means you must be on the network. with passive, just listening and observing.)
    Active Internal (you are actively sending packets out. )


BLUE/GRAY/RED Space
    Blue Space (This is you, you have 100% authorized access here)
    Gray Space (This is the internet, i.e. the world, you must be careful not to step on other people's toes here, you will have left and right lateral limits here)
    Red Space (This is hostile space)

Recon Steps
    Network Footprinting
    Network Scanning 
    Network Enumeration (where you tie all information gathered together on your map)
    Vulnerability Assessment (identify vulnerabilities either to harden your security on your network, or exploit an enemy network)

Network Footprinting
      Collect information relating to targets:
          Networks
          Systems
          Organizations

Network Scanning
      Port Scanning (scan for open ports)
      Network Scanning (scan for open networks)
      Vulnerability Scanning 

Network Enumeration
      Network Resource and shares
      Users and Groups
      Routing tables
      Auditing and Service settings
      Machine names
      Applications and banners
      SNMP and DNS details
      Other common services and ports

Vulnerability Assessment
      Injection
      Broken Authentication
      Sensitive Data Exposure
      XML External Entities
      Broken Access Control
      Security Misconfiguration
      Software/Components with Known Vulnerabilities


#Passive External Discovery#
    
Create a Sock Puppet (Think social media. You're using a 'sock puppet', a fake account, to gather information from on other people)
      The Ultimate Guide to Sockpuppets in OSINT
      Fake Name Generator
      This Person does not exist

Useful Sites
      OSINT Framework
      Malfrat’s OSINT Map
      Mark@OSINT-Research pages
      Pentest-Standard
      SecuritySift

Passive Recon Activities  
     Open-Source Intelligence (OSINT)
     Publicly Available Information (PAI)

Passive Recon Activities
     IP Addresses and Sub-domains
     Identifying External/3rd Party sites
     Identifying People
     Identifying Technologies
     Identifying Content of Interest
     Identifying Vulnerabilities
    
IP Addresses and Sub-domains
     IP Registries:
        IANA IPv4
        IANA IPv6

IP Addresses and Sub-domains
    DNS Lookups:
        arin.net
        whois.domaintools.com
        viewdns.info
        dnsdumpster.com
        centralops.net

IP Addresses and Sub-domains
    URL Scan:
        sitereport.netcraft.com
        web-check.xyz
        web-check.as93.net
        urlscan.io

IP Addresses and Sub-domains
    IP GeoLocation lookup:
        maxmind.com
        iplocation.io
        iplocation.net
        infosniper.net

IP Addresses and Sub-domains
    BGP prefixes:
        bgpview.io
        hackertarget.com
        bgp.he.net
        bgp4.as

Identifying External/3rd Party sites
    Parent/Subordinate organizations
    Clients/Customers
    Service organizations
    Partners

Identifying People
    Target website
    Crawler tools like Maltego or Creepy
    Search engines
    Social Media
    Job Portals
    Tracking active emails
    Family Tree

Identifying Technologies
    File extensions
    Server responses
    Job listing
    Website content
    Google Hacking
    Shodan.io
    MAC OUI Lookup

Identifying Content of Interest
    /etc/passwd and /etc/shadow or SAM database
    Configuration files
    Log files
    Backup files
    Test pages
    Client-side code

Identifying Vulnerabilities
    Known Technologies
    Error messages responses
    Identify running services
    Identify running OS
    Monitor running Applications

Dig vs Whois #Ways to Look up DNS information#
    Whois - queries DNS registrar over TCP port 43
        Information about the owner who registered the domain
    Dig - queries DNS server over UDP port 53 
        Name to IP records

Whois
    whois zonetransfer.me

Dig
    dig zonetransfer.me A
    dig zonetransfer.me AAAA
    dig zonetransfer.me MX
    dig zonetransfer.me TXT
    dig zonetransfer.me NS
    dig zonetransfer.me SOA


Zone Transfer
    Between Primary and Secondary DNS over TCP port 53
    https://digi.ninja/projects/zonetransferme.php
                            dir axfr {@soa.server} {target-site}
                            dig axfr @nsztm1.digi.ninja zonetransfer.me
        

NETCRAFT
     Similar to whois but web-based
     https://sitereport.netcraft.com/

Historical Content
    Wayback Machine
    http://archive.org/web/

Google Searches
    Advanced searches.
    List of filters
    Dork Search
      site:*.ccboe.net
      site:*.ccboe.net "administrator"

Shodan
    Shodan: A search engine for Internet-connected devices
    https://www.shodan.io
    Be aware of attribution

Passive OS Fingerprinter (p0f)
    p0f: Passive scanning of network traffic and packet captures.
          more /etc/p0f/p0f.fp
          sudo p0f -i eth0
          sudo p0f -r test.pcap

Passive OS Fingerprinter (p0f)
    Examine packets sent to/from target
    Can guess Operating Systems and version
    Can guess client/server application and version

Social Tactics
    Social Engineering (Hack a person)
    Technical based (Email/SMS/Bluetooth)
    Other Types (Dumpster Diving/Shoulder Surf)

Describe Methods Used for #Active External Discovery#
    
Scanning Nature
    Active
    Passive
    
Scanning Strategy
    Remote to Local
    Local to Remote
    Local to Local
    Remote to Remote

Scanning Approach
    Aim
        Wide range target scan
        Target specific scan
    Method
        Single source scan
            1-to-1 or 1-to-many
        Distributed scan
            many-to-one or many-to-many

Vertical Scan
    Scan some (or all ports) on a single target

Horizontal Scan
    Scan a single (or set) port(s) on a range of targets.

Strobe Scan
    Scan a predefined subset of ports on a range of targets.

Block Scan
    Scan all (or a range) ports on a range of targets.

Distributed Scan - Block
    A distributed scan uses multiple scanning systems or nodes to perform scanning activities. These systems work together to cover larger or more complex networks.

Distributed Scan - Strobe
    Each system is designated specific ports to scan across all target hosts.

#Ping#
    Ping one IP:
      ping 172.16.82.106 -c 1
    Ping a range:
      for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done

#NMAP Defaults#
    Default Scan Types:
        User: TCP Full Connect Scan (-sT)
        Root: TCP SYN Scan (-sS)
    By default the ports scanned: 1000 most commonly used TCP or UDP ports (Tell nmap what you want it to scan)

NMAP Port States (responses)
    open
    closed
    filtered
    unfiltered
    open|filtered
    closed|filtered

NMAP Scan Types
    Broadcast Ping/Ping sweep (-sP, -PE)
    SYN scan (-sS)
    Full connect scan (-sT)
    Null scan (-sN)
    FIN scan (-sF)
    XMAS tree scan (-sX)
    UDP scan (-sU)
    Idle scan (-sI)
    Decoy scan (-D)
    ACK/Window scan (-sA)
    RPC scan (-sR)
    FTP scan (-b)
    OS fingerprinting scan (-O)
    Version scan (-sV)
    Discovery probes

NMAP - Other options
    -PE - ICMP Ping
    -Pn - No Ping

NMAP - Time-Out
    -T0 - Paranoid - 300 Sec
    -T1 - Sneaky - 15 Sec
    -T2 - Polite - 1 Sec
    -T3 - Normal - 1 Sec
    -T4 - Aggresive - 500 ms
    -T5 - Insane - 250 ms

NMAP - Delay
    --scan-delay <time> - Minimum delay between probes
    --max-scan-delay <time> - Max delay between probes

NMAP - Rate Limit
    --min-rate <number> - Minimum packets per second
    --max-rate <number> - Max packets per second

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
      TCP
    for i in {1..254}; do nc -nvzw1 172.16.82.$i 20-23 80 2>&1 & done | grep -E 'succ|open'
         or 
      UDP
    for i in {1..254}; do nc -nuvzw1 172.16.82.$i 1000-2000 2>&1 & done | grep -E 'succ|open'

#Netcat - Vertical Scanning#
    Range of ports on specific IP
      TCP
    nc -nzvw1 172.16.82.106 21-23 80 2>&1 | grep -E 'succ|open'
        or
      UDP
    nc -nuzvw1 172.16.82.106 1000-2000 2>&1 | grep -E 'succ|open'

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


Netcat - Banner Grabbing #BANNER GRABBING#
      Find what is running on a particular port
        nc [Target IP] [Target Port]
        nc 172.16.82.106 22
        nc -u 172.16.82.106 53
      -u : To switch to UDP

Curl and Wget #CURL and WGET#
    Both can be used to interact with the HTTP, HTTPS and FTP protocols.
    Curl - Displays ASCII
      curl http://172.16.82.106
      curl ftp://172.16.82.106
    Wget - Downloads (-r recursive)
      wget -r http://172.16.82.106
      wget -r ftp://172.16.82.106


Describe Methods Used for #Passive Internal Discovery#
   
#Packet Sniffers#
    Wireshark
    Tcpdump
    p0f
  Limited to traffic in same local area of the network

#IP Configuration#
    Windows: ipconfig /all
    Linux: ip address (ifconfig depreciated)
    VyOS: show interface

#DNS configuration#
    Windows: ipconfig /displaydns
    Linux: cat /etc/resolv.conf

#ARP Cache#
    Windows: arp -a
    Linux: ip neighbor (arp -a depreciated)

#Network connections#
    Windows: netstat
    Linux: ss (netstat depreciated)

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
    Linux: ps or top

    Example options useful for ps: -elf
    e = Show all running processes
    l = Show long format view
    f = Show full format listing
  
#Command path#
    which
    whereis

#Routing Table#
    Windows: route print
    Linux: ip route (netstat -r deprecated)
    VyOS: show ip route
    
#File search#
    find / -name hint* 2> /dev/null
    find / -iname flag* 2> /dev/null

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

#Ping Scanning#
  ping -c 1 172.16.82.106
  for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done
  sudo nmap -sP 172.16.82.96/27

#DEV TCP Banner Grab#
  exec 3<>/dev/tcp/172.16.82.106/22; echo -e "" >&3; cat <&3

#DEV TCP Scanning#
  for p in {1..1023}; do(echo >/dev/tcp/172.16.82.106/$p) >/dev/null 2>&1 && echo "$p open"; done


Perform Network Forensics

#Network Forensics - Mapping#
    Diagram devices
    Line Types
    Written Information
    Coloring
    Groupings

Network Forensics - Mapping (see link)
https://net.cybbh.io/public/networking/latest/07_discovery/fg.html#_7_5_1_map_a_network

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













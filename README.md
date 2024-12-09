# Networking
Notes for the Networking Course

http://networking-ctfd-1.server.vta:8000/login
https://net.cybbh.io/public/networking/latest/index.html
https://miro.com/app/board/o9J_klSqCSY=/?share_link_id=16133753693

#START 
=================
#TAGS: #header#,#ARP Types#, #Traceroute# #Firewalking#, #SSH#, #SSH Files# 
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


















  
    








 


  

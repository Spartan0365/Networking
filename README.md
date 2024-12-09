# Networking
Notes for the Networking Course

http://networking-ctfd-1.server.vta:8000/login
https://net.cybbh.io/public/networking/latest/index.html
https://miro.com/app/board/o9J_klSqCSY=/?share_link_id=16133753693

#START 
=================
#TAGS: #header#,#ARP Types#, #Traceroute# #Firewalking#, 
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



























 


  

# custom_firewall_script1.1.sh	17/01/17
#this script can be added to AFWall+ > Settings > Set Custom Script > [/path/to/script/custom_firewall_script1.1.sh] > OK


#AFWALL CHAINS:
#==============
#    afwall - This is the main AFWall+ chain. All OUTPUT packets will pass through it. It is therefore the >perfect place if you want to add rules that apply to any interface.
#
#    afwall-3g - This chain will only receive OUTPUT packets for the cellular network interface (no matter >if it is 2G, 3G, 4G, etc).
#
#    afwall-wifi - This chain will only receive OUTPUT packets for the WiFi interface.
#
#    afwall-reject - This chain should be used as a target when you want to reject and log a >packet. >When the logging is disabled, this is exactly the same as the built-in REJECT target

#-----------------------------------------------------------------------------------------------
IP6T=/system/bin/ip6tables
IPT=/system/bin/iptables
IP6TABLES=/system/bin/ip6tables #########################
IPTABLES=/system/bin/iptables ###########################

#-----------------------------------------------------------------------------------------------
# Interface configuration - replace with your interfaces (ifconfig -a)
# This is for advance users only which like o work with specific interfaces only!
WAN_IF="eth1"	##
LAN_IF="eth0"	##
DMZ_IF="eth2"	##
LAN_NET="2001:db8:1::/64"	##
DMZ_NET="2001:db8:2::/64"	##

# ifconfig -a run on 09/01/17:
# lo        Link encap:Local Loopback
# sit0      Link encap:IPv6-in-IPv4
# ip6tnl0   Link encap:UNSPEC
# wlan0     Link encap:Ethernet  HWaddr 1c:99:4c:ab:8e:f6
# p2p0      Link encap:Ethernet  HWaddr 1e:99:4c:ab:8e:f6
# rmnet0    Link encap:Point-to-Point Protocol
# rmnet1    Link encap:Point-to-Point Protocol
# rmnet2    Link encap:Point-to-Point Protocol

#-----------------------------------------------------------
# Set policies to drop
$IPT -P INPUT DROP
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IP6T -P OUTPUT DROP
$IP6T -P FORWARD DROP
$IP6T -P OUTPUT DROP

#Undo the drop.ipt scripts rules##############################################################
$IPT --policy INPUT ACCEPT -t mangle
$IPT --delete INPUT -j DROP -t mangle
$IP6T --policy INPUT ACCEPT -t mangle
$IP6T --delete INPUT -j DROP -t mangle

$IPT --policy OUTPUT ACCEPT -t mangle
$IPT --delete OUTPUT -j DROP -t mangle
$IP6T --policy OUTPUT ACCEPT -t mangle
$IP6T --delete OUTPUT -j DROP -t mangle

$IPT --policy FORWARD ACCEPT -t mangle
$IPT --delete FORWARD -j DROP -t mangle
$IP6T --policy FORWARD ACCEPT -t mangle
$IP6T --delete FORWARD -j DROP -t mangle

$IPT --policy PREROUTING ACCEPT -t mangle
$IPT --delete PREROUTING -j DROP -t mangle
$IP6T --policy PREROUTING ACCEPT -t mangle
$IP6T --delete PREROUTING -j DROP -t mangle

$IPT --policy POSTROUTING ACCEPT -t mangle
$IPT --delete POSTROUTING -j DROP -t mangle
$IP6T --policy POSTROUTING ACCEPT -t mangle
$IP6T --delete POSTROUTING -j DROP -t mangle

$IPT --delete OUTPUT -j DROP
$IPT --delete FORWARD -j DROP
$IP6T --delete OUTPUT -j DROP
$IP6T --delete FORWARD -j DROP

################################################################################################
# INPUT CHAIN
# begin by flushing/purging all previous INPUT rules:
$IPT -F INPUT
$IP6T -F INPUT

# Prevent INPUT attacks
# SYN attacks
##$IPT -I TCP -p tcp --match recent --update --seconds 60 --name TCP-PORTSCAN -j DROP  ##chain name "TCP"?!
##$IP6T -I TCP -p tcp --match recent --update --seconds 60 --name TCP-PORTSCAN -j DROP  ##chain name "TCP"?!
$IPT -A INPUT -p tcp --match recent --set --name TCP-PORTSCAN -j DROP
$IP6T -A INPUT -p tcp --match recent --set --name TCP-PORTSCAN -j DROP

# SMURF attacks
$IPT -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
$IPT -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
$IPT -A INPUT -p icmp -m limit --limit 2/second --limit-burst 2 -j ACCEPT
$IPT -A INPUT -p icmpv6 -m limit --limit 2/second --limit-burst 2 -j ACCEPT

#---------------------------------------------------------------------------------------------------------------
#Drop normal Multicast-addresses
$IPT -A INPUT -s 224.0.0.0/4 -j DROP -m comment --comment "Drop normal Multicast-addresses"
$IPT -A INPUT -d 224.0.0.0/4 -j DROP -m comment --comment "Drop normal Multicast-addresses"
$IPT -A INPUT -s 224.0.0.0/5 -j DROP -m comment --comment "Drop normal Multicast-addresses"
$IPT -A INPUT -d 224.0.0.0/5 -j DROP -m comment --comment "Drop normal Multicast-addresses"

$IPT -A INPUT -s 0.0.0.0/8 -j DROP -m comment --comment "Drop normal Multicast-addresses"
$IPT -A INPUT -d 0.0.0.0/8 -j DROP -m comment --comment "Drop normal Multicast-addresses"

$IPT -A INPUT -d 239.255.255.0/24 -j DROP -m comment --comment "Drop normal Multicast-addresses"
$IPT -A INPUT -d 255.255.255.255 -j DROP -m comment --comment "Drop normal Multicast-addresses"

#-----------------------------------------------------------------------------------------------
# Allow INPUT that is ESTABLISHED,RELATED
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IP6T -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

##############################################################################################
##DO WE NEED to accept OUTPUT established,related (via afwall chain)?
#$IPT -I afwall -m state --state ESTABLISHED,RELATED -j ACCEPT
#$IP6T -I afwall -m state --state ESTABLISHED,RELATED -j ACCEPT  #should this be allowed? all other traffic seems to be getting blocked..

################################################################################################
#ACCEPT PING requests on IPv6:
##############################################################################################

# ICMPv6 - Do not allow that IPv6 gets control over everything
# Type 1: Destination unreachable
# Type 2: Time Exceeded
# Type 3: Parameter problem
# -> Multicast Listener Discovery (130, 131, 132 INPUT and OUTPUT)
# -> Ping (128 + 129, INPUT, OUTPUT and FORWARDING)
# -> Neighbor Discovery (ICMPv6-Typen 135 + 136)
# -> Router Discovery (ICMPv6-Typen 133 + 134)
# -> Path MTU-Discovery (ICMPv6-Typ 2)
# If you want multicast connections you can use some of this shown rules as an example!
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 1 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 2 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 3 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 4 -j ACCEPT
###$IP6TABLES -A FORWARD -i $WAN_IF -p icmpv6 --icmpv6-type 1 -j ACCEPT		#not sure what $WAN_IF is supposed to be..
###$IP6TABLES -A FORWARD -i $WAN_IF -p icmpv6 --icmpv6-type 2 -j ACCEPT         #not sure what $WAN_IF is supposed to be..
###$IP6TABLES -A FORWARD -i $WAN_IF -p icmpv6 --icmpv6-type 3 -j ACCEPT         #not sure what $WAN_IF is supposed to be..
###$IP6TABLES -A FORWARD -i $WAN_IF -p icmpv6 --icmpv6-type 4 -j ACCEPT         #not sure what $WAN_IF is supposed to be..

# Router & Neighbor Discovery in-/outgoing
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT
$IP6TABLES -A afwall -p icmpv6 --icmpv6-type 133 -j ACCEPT
$IP6TABLES -A afwall -p icmpv6 --icmpv6-type 134 -j ACCEPT
$IP6TABLES -A afwall -p icmpv6 --icmpv6-type 135 -j ACCEPT
$IP6TABLES -A afwall -p icmpv6 --icmpv6-type 136 -j ACCEPT

# Ping-Request to the Firewall from the LAN and DMZ
###$IP6TABLES -A INPUT ! -i $WAN_IF -p icmpv6 --icmpv6-type 128 -j ACCEPT         #not sure what $WAN_IF is supposed to be..

# Ping-Request from the Firewall, LAN and DMZ
$IP6TABLES -A afwall -p icmpv6 --icmpv6-type 128 -j ACCEPT
###$IP6TABLES -A FORWARD ! -i $WAN_IF -p icmpv6 --icmpv6-type 128 -j ACCEPT         #not sure what $WAN_IF is supposed to be..

# Allow incoming ICMP ping 
###$IP6TABLES -A INPUT -i $WAN_IF -p ipv6-icmp -j ACCEPT         #not sure what $WAN_IF is supposed to be..
###$IP6TABLES -A afwall -o $WAN_IF -p ipv6-icmp -j ACCEPT         #not sure what $WAN_IF is supposed to be..

################################################################################################

#rather than reject, DROP all packets entering the afwall-reject chain
$IPT -D afwall-reject -j DROP -m comment --comment "rather than reject, DROP all packets entering the afwall-reject chain"
$IPT -I afwall-reject -j DROP -m comment --comment "rather than reject, DROP all packets entering the afwall-reject chain"
## there is no afwall-reject in IPv6tables

################################################################################################
#ACCEPT loopback interface
#=========================
#xxxxxxxxxxxxxxxxxxxxxxxxxxx
#xxxxxxxxxxxxxxxxxxxxxxxxxxx
#xxxxxxxxxxxxxxxxxxxxxxxxxxx
#xxxxxxxxxxxxxxxxxxxxxxxxxxx

################################################################################################
#DROP packets with state: INVALID
#================================
$IPT -I INPUT -m state --state INVALID -j DROP
$IP6T -I INPUT -m state --state INVALID -j DROP

$IPT -D FORWARD -m state --state INVALID -j DROP
$IP6T -D FORWARD -m state --state INVALID -j DROP
$IPT -I FORWARD -m state --state INVALID -j DROP
$IP6T -I FORWARD -m state --state INVALID -j DROP

$IPT -D afwall -m state --state INVALID -j DROP
$IP6T -D afwall -m state --state INVALID -j DROP
$IPT -I afwall -m state --state INVALID -j DROP
###$IP6T -I afwall -m state --state INVALID -j DROP	#this breaks afwall firewall: "ip6tables: No chain/target/match by that name"

################################################################################################
# iptables......-j ACCEPT -m comment --comment "this is a comment"
################################################################################################


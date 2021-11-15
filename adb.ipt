apt update
apt install android-tools-adb

#this script punches holes in the host ADB device's firewall to allow an ADB connection to the phone
iptables -I OUTPUT 2 -o lo -p tcp --dport 5037 -j ACCEPT
iptables -I OUTPUT 2 -o lo -p udp --dport 5037 -j ACCEPT
ip6tables -I OUTPUT 2 -o lo -p icmpv6 -j ACCEPT

# Run this script as root.
cat > '/etc/rc.local' <<EOF
#!/bin/bash
# Add NAT interface for qemu vm.
ip link add br0 type bridge
ip addr add 192.168.4.1/24 dev br0
ip link set br0 up
systemctl restart dnsmasq
sysctl -w net.ipv4.ip_forward=1
iptables-save > /etc/iptables/rules.v4
exit 0
EOF
systemctl restart rc-local
iptables -t nat -A PREROUTING -i br0 -s 192.168.4.0/24 -p udp --dport 53 -j DNAT --to 8.8.8.8
iptables -t nat -A POSTROUTING -o enp4s0 -s 192.168.4.0/24 -j MASQUERADE # remote: ens18, local:enp4s0
iptables-save > /etc/iptables/rules.v4
cat >> /etc/dnsmasq.conf <<EOF
interface=br0
dhcp-range=192.168.4.2,192.168.4.254,12h
EOF
systemctl restart dnsmasq

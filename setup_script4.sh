# Verify settings.
ip addr show dev br0
sysctl net.ipv4.ip_forward
sudo iptables -t nat -L
Verify
sudo mkdir /etc/qemu/
sudo bash -c "echo 'allow all' >> /etc/qemu/bridge.conf"

sudo qemu-system-x86_64 -name qvm0 -smbios type=0,uefi=on -enable-kvm -smp 2 -m 4096 -hda /home/user/qvm0.qcow2 -boot c -netdev bridge,br=br0,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:43:00 -vnc 0.0.0.0:0
sudo qemu-system-x86_64 -name qvm0 -smbios type=0,uefi=on -smp 2 -m 4096 -hda /home/user/qvm0.qcow2 -boot c -netdev bridge,br=br0,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:43:00 -vnc 0.0.0.0:0

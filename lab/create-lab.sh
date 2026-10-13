#!/bin/sh
# Create the three lab VMs on the Proxmox host. Touches ONLY VM IDs 9101-9103.
# Run on the Proxmox host as root. Every qm call is echoed so it can be logged
# in docs/PROGRESS.md.
set -e
W=/var/tmp/lk-lab
STORE=tree3
q() { echo "+ qm $*"; qm "$@"; }

for id in 9101 9102 9103; do
  if qm status $id >/dev/null 2>&1; then echo "VM $id already exists, abort"; exit 1; fi
done

# --- 9101 OPNsense 26.1.2 firewall (WAN=vmbr0, LAN=private UDP link to 9102)
q create 9101 --name opn-l7-fw --memory 4096 --cores 2 --cpu host --ostype other \
  --scsihw virtio-scsi-single --net0 virtio=BC:24:11:91:01:01,bridge=vmbr0 \
  --serial0 socket --onboot 0 --description "LKPLUGIN lab: OPNsense 26.1 firewall"
q set 9101 --args "-netdev socket,id=lan0,udp=127.0.0.1:19102,localaddr=127.0.0.1:19101 -device virtio-net-pci,netdev=lan0,mac=BC:24:11:91:01:02"
q importdisk 9101 $W/opn.img $STORE --format qcow2
q set 9101 --scsi0 $STORE:9101/vm-9101-disk-0.qcow2,iothread=1 --boot order=scsi0
q resize 9101 scsi0 32G

# --- 9102 Ubuntu 24.04 client (mgmt NIC on vmbr0, test NIC on OPNsense LAN)
q create 9102 --name l7-client --memory 2048 --cores 1 --cpu host --ostype l26 \
  --scsihw virtio-scsi-single --net0 virtio=BC:24:11:91:02:01,bridge=vmbr0 --onboot 0 \
  --description "LKPLUGIN lab: client behind OPNsense LAN (mgmt 192.168.1.72)"
q set 9102 --args "-netdev socket,id=lan0,udp=127.0.0.1:19101,localaddr=127.0.0.1:19102 -device virtio-net-pci,netdev=lan0,mac=BC:24:11:91:02:02"
q importdisk 9102 $W/noble.img $STORE --format qcow2
q set 9102 --scsi0 $STORE:9102/vm-9102-disk-0.qcow2,iothread=1 --boot order=scsi0
q resize 9102 scsi0 16G
q set 9102 --ide2 $STORE:cloudinit --ciuser lk --ipconfig0 ip=192.168.1.72/24 --sshkeys /root/.ssh/lk_lab.pub

# --- 9103 Ubuntu 24.04 "cloud" management server
q create 9103 --name l7-cloud --memory 2048 --cores 2 --cpu host --ostype l26 \
  --scsihw virtio-scsi-single --net0 virtio=BC:24:11:91:03:01,bridge=vmbr0 --onboot 0 \
  --description "LKPLUGIN lab: cloud-style management server (192.168.1.73)"
q importdisk 9103 $W/noble.img $STORE --format qcow2
q set 9103 --scsi0 $STORE:9103/vm-9103-disk-0.qcow2,iothread=1 --boot order=scsi0
q resize 9103 scsi0 20G
q set 9103 --ide2 $STORE:cloudinit --ciuser lk --ipconfig0 ip=192.168.1.73/24,gw=192.168.1.1 --nameserver 192.168.1.1 --sshkeys /root/.ssh/lk_lab.pub
qm list | grep -E '^ *91(01|02|03)'

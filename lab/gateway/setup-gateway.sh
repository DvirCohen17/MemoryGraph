#!/usr/bin/env bash
# Turns an Ubuntu-based VM (REMnux recommended: INetSim is already installed) into the lab's fake internet.
# Run once inside that VM WHILE it still has internet (to install packages), then move it to the lab
# network (VMnet9). Afterwards it answers the victims' DNS, HTTP(S), SMTP, FTP, IRC ... with fake replies,
# so samples behave as if they were online and their C2 attempts show up in memory.
#   sudo bash setup-gateway.sh [interface]
set -euo pipefail
IFACE="${1:-$(ip -o -4 route show to default | awk '{print $5}' | head -n1)}"
IFACE="${IFACE:-ens33}"
LAB_IP="10.66.0.1"

if ! command -v inetsim >/dev/null 2>&1; then
  apt-get update
  apt-get install -y inetsim
fi
apt-get install -y iptables-persistent >/dev/null 2>&1 || true

echo "[gateway] static address ${LAB_IP}/24 on ${IFACE}"
cat >/etc/netplan/99-malware-lab.yaml <<EOF
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: false
      addresses: [${LAB_IP}/24]
EOF
chmod 600 /etc/netplan/99-malware-lab.yaml

echo "[gateway] INetSim listens on ${LAB_IP}; every DNS name resolves to ${LAB_IP}"
CONF=/etc/inetsim/inetsim.conf
sed -i -E "s/^#?\s*service_bind_address\s+.*/service_bind_address ${LAB_IP}/" "$CONF"
sed -i -E "s/^#?\s*dns_default_ip\s+.*/dns_default_ip ${LAB_IP}/" "$CONF"
grep -q "^service_bind_address" "$CONF" || echo "service_bind_address ${LAB_IP}" >> "$CONF"
grep -q "^dns_default_ip" "$CONF" || echo "dns_default_ip ${LAB_IP}" >> "$CONF"
# REMnux's default inetsim.conf ships the DNS service OFF. Without it, names never resolve to the
# gateway and samples that use a C2 domain make no connection at all. Make sure it is enabled.
grep -qE "^\s*start_service\s+dns" "$CONF" || echo "start_service dns" >> "$CONF"

echo "[gateway] traffic to ANY address is answered here (samples with hard-coded C2 IPs)"
sysctl -w net.ipv4.ip_forward=0 >/dev/null     # never route anywhere
iptables -t nat -F PREROUTING
for port in 21 25 53 80 110 443 465 587 993 995 6667 8080 8443; do
  iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$port" ! -d "$LAB_IP" -j DNAT --to-destination "${LAB_IP}:${port}"
done
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 53 ! -d "$LAB_IP" -j DNAT --to-destination "${LAB_IP}:53"
command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save || true

systemctl enable inetsim >/dev/null 2>&1 || true
echo
echo "Done. Now: shut this VM down, set its network adapter to the lab network (VMnet9, custom) in"
echo "VMware Workstation, start it, run 'sudo netplan apply && sudo systemctl restart inetsim'."
echo "INetSim logs what the samples sent: /var/log/inetsim/ and /var/lib/inetsim/."

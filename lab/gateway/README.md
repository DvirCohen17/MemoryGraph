# The fake-internet VM

Samples that cannot reach their server often do nothing, and the dump then shows little. This VM sits
on the isolated lab network (`VMnet9`, `10.66.0.1`) and pretends to be the internet with
[INetSim](https://www.inetsim.org/): every DNS name resolves to it, and it answers HTTP, HTTPS, SMTP,
FTP, IRC and more with fake replies. Nothing ever leaves the lab network: `VMnet9` has no NAT and no
host adapter, and this VM does not route.

1. Download the REMnux VMware appliance (OVA) and import it in Workstation (*File > Open*).
   Any Ubuntu VM works too; the script installs INetSim.
2. While it still has its NAT adapter, copy `setup-gateway.sh` into it and run `sudo bash setup-gateway.sh`.
3. Shut it down, set its network adapter to *Custom: VMnet9*, start it, run
   `sudo netplan apply && sudo systemctl restart inetsim`.
4. Put its `.vmx` path in `lab/terraform/terraform.tfvars` (`gateway_vmx`) so Terraform starts it with the lab,
   or start it by hand before a run.

What the samples tried to send is in INetSim's logs (`/var/log/inetsim/`, `/var/lib/inetsim/`):
handy for checking the network part of a dump's answer key.

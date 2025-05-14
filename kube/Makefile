swap-off:
	@sudo swapoff -a
	@sudo sed -i '/ swap / s/^\(.*\)/#&/' /etc/fstab

setup-network:
	@sudo bash -c 'echo "network:" > /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "  version: 2" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "  renderer: networkd" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "  ethernets:" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "    enp1s0:" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "      addresses:" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "        - 192.168.122.100/24" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "      routes:" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "        - to: default" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "          via: 192.168.122.1" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "      nameservers:" >> /etc/netplan/50-cloud-init.yaml'
	@sudo bash -c 'echo "          addresses: [8.8.8.8, 8.8.4.4]" >> /etc/netplan/50-cloud-init.yaml'
	sudo netplan apply

setup-kube-config:
	mkdir -p $$HOME/.kube
	@sudo cp -i /etc/kubernetes/admin.conf $$HOME/.kube/config
	@sudo chown $$(id -u):$$(id -g) $$HOME/.kube/config
	export KUBECONFIG=/etc/kubernetes/admin.conf

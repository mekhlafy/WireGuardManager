#! /usr/bin/env python3

import subprocess
import os
import re
import json
import argparse

# Constants
WG_CONFIG_FILE = "/etc/wireguard/wg0.conf"
WG_INTERFACE = "wg0"
IPTABLES_SAVE_FILE = "/etc/iptables/rules.v4"
PEER_DATA_FILE = "peers_data.json"
CLIENT_CONFIG_DIR = "client_configs"  # Directory to store client configuration files
SERVER_IP = os.getenv('SERVER_IP', 'your.server.ip.address')  # Server IP address
USED_PORTS = set()
USED_IPS = set()
DEFAULT_PORT_RANGE = (8000, 9000)  # Default range for external ports
PRIVATE_KEY_FILE = "/etc/wireguard/server_private.key"
PUBLIC_KEY_FILE = "/etc/wireguard/server_public.key"

class WireGuardManager:
    def __init__(self, port_range=DEFAULT_PORT_RANGE):
        self.port_range = port_range
        self.peers = self._load_peers()
        self._initialize_used_ports_and_ips()
        if not os.path.exists(CLIENT_CONFIG_DIR):
            os.makedirs(CLIENT_CONFIG_DIR)

    def run_command(self, command):
        """
        Utility function to run a command using subprocess with bash.
        """
        try:
            result = subprocess.run(["/bin/bash", "-c", command], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.stdout.decode().strip()
        except subprocess.CalledProcessError as e:
            print(f"Command '{command}' failed: {e.stderr.decode().strip()}")
            return None

    def _load_peers(self):
        """
        Loads peer data from the persistent storage file.
        """
        if os.path.exists(PEER_DATA_FILE):
            with open(PEER_DATA_FILE, 'r') as f:
                return json.load(f)
        return {}

    def _save_peers(self):
        """
        Saves peer data to the persistent storage file.
        """
        with open(PEER_DATA_FILE, 'w') as f:
            json.dump(self.peers, f, indent=4)

    def _initialize_used_ports_and_ips(self):
        """
        Initializes the set of used ports and IPs from the loaded peers.
        """
        for peer in self.peers.values():
            USED_PORTS.add(peer['external_port'])
            USED_IPS.add(peer['peer_ip'])

    def load_key_pair(self):
        """
        Loads a WireGuard key pair from the specified files.
        """
        with open(PRIVATE_KEY_FILE, 'r') as f:
            private_key = f.read().strip()
        with open(PUBLIC_KEY_FILE, 'r') as f:
            public_key = f.read().strip()
        return private_key, public_key

    def generate_key_pair(self):
        """
        Generates a WireGuard key pair (private and public key).
        """
        private_key = self.run_command("wg genkey")
        public_key = self.run_command(f"echo {private_key} | wg pubkey")
        return private_key, public_key

    def _generate_peer_ip(self):
        """
        Generates a unique IP address for the WireGuard peer.
        """
        base_ip = "10.0.0."
        for i in range(2, 255):  # Starting from 10.0.0.2 to avoid conflicts
            potential_ip = f"{base_ip}{i}"
            if potential_ip not in USED_IPS:
                USED_IPS.add(potential_ip)
                return potential_ip
        raise Exception("No available IP addresses for peers.")

    def _get_available_external_port(self):
        """
        Finds an available external port within the defined range.
        """
        for port in range(self.port_range[0], self.port_range[1]):
            if port not in USED_PORTS:
                USED_PORTS.add(port)
                return port
        raise Exception("No available ports in the specified range.")

    def generate_peer(self, internal_port):
        """
        Creates a WireGuard peer with specified internal port and an automatically assigned external port.
        """
        external_port = self._get_available_external_port()

        private_key, public_key = self.load_key_pair()
        peer_name = f"Peer_{internal_port}_{external_port}"
        peer_ip = self._generate_peer_ip()
        allowed_ips = f"{peer_ip}/32"

        # Add peer to WireGuard configuration (restricting AllowedIPs to only the server IP)
        peer_config = (f"[Peer]\n"
                       f"# {peer_name}\n"
                       f"PublicKey = {public_key}\n"
                       f"AllowedIPs = {allowed_ips}\n")
        self._append_to_wg_config(peer_config)
        self.peers[peer_name] = {'internal_port': internal_port, 'external_port': external_port, 'peer_ip': peer_ip, 'allowed_ips': allowed_ips, 'public_key': public_key, 'private_key': private_key}

        # Add iptables rules for forwarding
        self.add_forwarding_rules(peer_ip, internal_port, external_port)
        self._save_peers()

        # Generate and save client configuration file
        self._generate_client_config(peer_name, private_key, peer_ip)

    def generate_peers(self, peer_count, internal_port):
        """
        Generates the specified number of WireGuard peers.
        """
        for _ in range(peer_count):
            self.generate_peer(internal_port)

    def add_forwarding_rules(self, peer_ip, internal_port, external_port):
        """
        Adds forwarding rules to iptables restricted to the WireGuard peer IP.
        This includes rules for both incoming and outgoing traffic to allow bidirectional forwarding.
        """
        # Forward incoming traffic from any source to the external port
        command_incoming = (f"iptables -t nat -A PREROUTING -p tcp --dport {external_port} -j DNAT --to-destination {peer_ip}:{internal_port}")
        self.run_command(command_incoming)

        # Forward outgoing traffic from the external port back to the peer IP and internal port
        command_outgoing = (f"iptables -t nat -A OUTPUT -d {peer_ip} -o {WG_INTERFACE} -p tcp --dport {external_port} -j DNAT --to-destination {peer_ip}:{internal_port}")
        self.run_command(command_outgoing)

        self._save_iptables()

    def remove_forwarding_rules(self, peer_ip, internal_port, external_port):
        """
        Removes forwarding rules from iptables restricted to the WireGuard peer IP.
        This includes rules for both incoming and outgoing traffic.
        """
        # Remove incoming traffic forwarding rule
        command_incoming = (f"iptables -t nat -D PREROUTING -s {peer_ip} -i {WG_INTERFACE} -p tcp --dport {internal_port} -j REDIRECT --to-port {external_port}")
        self.run_command(command_incoming)

        # Remove outgoing traffic forwarding rule
        command_outgoing = (f"iptables -t nat -D OUTPUT -d {peer_ip} -o {WG_INTERFACE} -p tcp --dport {external_port} -j DNAT --to-destination {peer_ip}:{internal_port}")
        self.run_command(command_outgoing)

        self._save_iptables()

    def remove_peer(self, peer_name):
        """
        Removes a WireGuard peer by name.
        """
        if peer_name not in self.peers:
            print("Peer not found.")
            return

        # Remove peer from configuration file
        self._remove_peer_from_wg_config(peer_name)
        internal_port = self.peers[peer_name]['internal_port']
        external_port = self.peers[peer_name]['external_port']
        peer_ip = self.peers[peer_name]['peer_ip']
        
        # Remove iptables forwarding rules
        self.remove_forwarding_rules(peer_ip, internal_port, external_port)
        
        # Remove peer from dictionary
        del self.peers[peer_name]
        USED_PORTS.discard(external_port)
        USED_IPS.discard(peer_ip)
        self._save_peers()

        # Remove client configuration file
        client_config_file = os.path.join(CLIENT_CONFIG_DIR, f"{peer_name}.conf")
        if os.path.exists(client_config_file):
            os.remove(client_config_file)

    def _generate_peer_name(self, internal_port, external_port):
        """
        Helper function to generate a peer name based on internal and external port.
        """
        return f"Peer_{internal_port}_{external_port}"

    def _append_to_wg_config(self, peer_config):
        """
        Helper function to append a peer configuration to the WireGuard config file.
        """
        with open(WG_CONFIG_FILE, 'a') as f:
            f.write(f"\n{peer_config}\n")
        # Apply changes
        self.run_command(f"wg syncconf {WG_INTERFACE} <(wg-quick strip {WG_INTERFACE})")

    def _remove_peer_from_wg_config(self, peer_name):
        """
        Helper function to remove a peer from the WireGuard configuration file by peer name.
        """
        with open(WG_CONFIG_FILE, 'r') as f:
            config_lines = f.readlines()

        with open(WG_CONFIG_FILE, 'w') as f:
            inside_peer_block = False
            for line in config_lines:
                if re.search(f"# {peer_name}", line):
                    inside_peer_block = True
                elif inside_peer_block and line.startswith("["):
                    inside_peer_block = False

                if not inside_peer_block:
                    f.write(line)

        # Apply changes
        self.run_command(f"wg syncconf {WG_INTERFACE} <(wg-quick strip {WG_INTERFACE})")

    def _save_iptables(self):
        """
        Saves iptables rules to make them persistent across reboots.
        """
        self.run_command(f"iptables-save > {IPTABLES_SAVE_FILE}")

    def _generate_client_config(self, peer_name, private_key, peer_ip):
        """
        Generates a WireGuard client configuration file for the peer.
        """
        client_config = (f"[Interface]\n"
                         f"PrivateKey = {private_key}\n"
                         f"Address = {peer_ip}/32\n"
                         f"DNS = 1.1.1.1\n\n" # Cloudflare DNS or we can use Google DNS which is 8.8.8.8 or our own DNS if we have more control over client connection
                         f"[Peer]\n"
                         f"PublicKey = {self._get_server_public_key()}\n"
                         f"Endpoint = {SERVER_IP}:51820\n"
                         f"AllowedIPs = {SERVER_IP}/32\n")
        client_config_file = os.path.join(CLIENT_CONFIG_DIR, f"{peer_name}.conf")
        with open(client_config_file, 'w') as f:
            f.write(client_config)
        print(f"Client configuration file generated: {client_config_file}")

    def _get_server_public_key(self):
        """
        Retrieves the server's public key from the WireGuard configuration.
        """
        return self.run_command(f"wg show {WG_INTERFACE} public-key")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WireGuard Manager")
    parser.add_argument("action", choices=["generate_peer", "generate_peers", "remove_peer"], help="Action to perform")
    parser.add_argument("--internal_port", type=int, help="Internal port for WireGuard peer")
    parser.add_argument("--peer_count", type=int, help="Number of peers to generate")
    parser.add_argument("--peer_name", type=str, help="Name of the peer to remove")
    parser.add_argument("--port_range", type=int, nargs=2, help="Range of external ports to use (e.g., 8000 9000)")

    args = parser.parse_args()
    port_range = tuple(args.port_range) if args.port_range else DEFAULT_PORT_RANGE
    manager = WireGuardManager(port_range=port_range)

    if args.action == "generate_peer" and args.internal_port:
        manager.generate_peer(args.internal_port)
    elif args.action == "generate_peers" and args.internal_port and args.peer_count:
        manager.generate_peers(args.peer_count, args.internal_port)
    elif args.action == "remove_peer" and args.peer_name:
        manager.remove_peer(args.peer_name)
    else:
        print("Invalid arguments. Please provide the necessary parameters for the chosen action.")

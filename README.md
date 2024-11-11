# WireGuard Peer Manager

## Overview
This Python script is a console application designed to manage WireGuard peers and configure network forwarding rules on an Ubuntu server. It provides functionality for generating WireGuard peers, managing forwarding rules using `iptables`, and creating client configuration files.

## Features
- **Generate WireGuard Peers**: Automatically generates a specified number of WireGuard peers, complete with public and private keys, and configuration settings.
- **Manage Port Forwarding**: Sets up `iptables` rules to forward network traffic between internal and external ports for each WireGuard peer.
- **Automatic Port Assignment**: Assigns unique external ports within a specified range.
- **Client Configuration Generation**: Creates and stores WireGuard client configuration files for each peer.

## Requirements
- Python 3
- WireGuard tools (`wg`, `wg-quick`)
- `iptables`
- Root privileges (run the script using `sudo`)

To install the requirements:
```bash
sudo apt install python3 wireguard-tools iptables
```

## Setup
1. **Clone the repository or copy the script** to your local machine.
2. **Ensure Python 3 is installed**: This script is designed for Python 3.
3. **Set the server IP address**:
   - You can set the server IP address via an environment variable named `SERVER_IP`. Alternatively, you can pass it as an argument when running the script.

## Usage
The script can be executed using the command line. Below are the available actions and arguments:

### Shebang Setup (Optional)
To run the script as an executable, add the shebang line to the top of the script:
```python
#!/usr/bin/env python3
```
Then make it executable:
```bash
chmod +x wireguard_manager.py
```

### Command Line Arguments
The script accepts several command-line arguments to manage WireGuard peers:

```bash
sudo ./wireguard_manager.py [action] [options]
```

- `action` (required): Specifies the action to perform. Possible values are:
  - `generate_peer`: Generates a single WireGuard peer.
  - `generate_peers`: Generates multiple WireGuard peers.
  - `remove_peer`: Removes an existing WireGuard peer.

### Options
- `--server_ip`: (Optional) The IP address of the WireGuard server. Can also be set via the `SERVER_IP` environment variable.
- `--internal_port`: (Required for `generate_peer` and `generate_peers`) Specifies the internal port for WireGuard peer communication.
- `--peer_count`: (Required for `generate_peers`) Specifies the number of peers to generate.
- `--peer_name`: (Required for `remove_peer`) Specifies the name of the peer to remove.
- `--port_range`: (Optional) Specifies the range of external ports to use (e.g., `8000 9000`).

### Examples
1. **Generate a Single Peer**:
   ```bash
   sudo python3 wireguard_manager.py generate_peer --internal_port 51820
   ```

2. **Generate Multiple Peers**:
   ```bash
   sudo python3 wireguard_manager.py generate_peers --internal_port 51820 --peer_count 5
   ```

3. **Remove a Peer**:
   ```bash
   sudo python3 wireguard_manager.py remove_peer --peer_name Peer_51820_8001
   ```

## Generated Files
- **WireGuard Configuration File** (`wg0.conf`): Peers are added to this configuration file located at `/etc/wireguard/wg0.conf`.
- **Client Configuration Files**: The script generates client configuration files for each peer and saves them in the `client_configs` directory.
- **Persistent Peer Data** (`peers_data.json`): Peer information is saved to this JSON file to persist configuration across script executions.

## Important Notes
- **Root Privileges**: Since the script modifies `iptables` and WireGuard configurations, it must be run with root privileges (`sudo`).
- **Environment Variable for Server IP**: You can set the server IP by running:
  ```bash
  export SERVER_IP=your.server.ip.address
  ```
- **Dependencies**: Ensure WireGuard and `iptables` are installed, and Python 3 is used to run the script.

## Security Considerations
- **Use a Secure Environment**: The script interacts with sensitive network configurations and should be run in a trusted, secure environment.
- **Avoid Hardcoding Sensitive Data**: Use environment variables for sensitive information like the server IP.

## License
This script is open-source, and you are free to use, modify, and distribute it under the MIT License.

## Contribution
Feel free to contribute by opening issues or submitting pull requests to enhance the script's features, improve the code structure, or add error handling and additional checks.


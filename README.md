# Hack The Box AI Pentesting Agent

This project builds an AI-powered pentesting assistant for Hack The Box Acadmey challenges, using a Parrot OS VM, Dockerized Open WebUI, and a custom SSH command execution tool. The agent executes commands (e.g., `whoami`, `ifconfig`) on a remote VM via a clean chat interface, logging details separately, and supports my Penetration Tester path with enhanced performance using OpenAI’s `gpt-4o-mini`.

## Project Overview
- **Goal**: Create a user-friendly AI agent to run pentesting commands on a Hack The Box VM, delivering raw outputs (e.g., `user` for `whoami`) while logging debug info (e.g., SSH connections) to a file.
- **Tech Stack**:
    - **Parrot OS VM**: Runs at `10.0.0.215` for command execution.
    - **Docker**: Hosts Open WebUI (`ghcr.io/open-webui/open-webui:main`) with mounted tools, SSH key, and logs.
    - **Open WebUI**: Provides a chat interface with `gpt-4o-mini` (via OpenAI API) for tool-calling, upgraded from `llama3-groq-tool-use:8b` for speed.
    - **Python**: Powers `ssh_command_executor.py` (version 1.0.3) using `paramiko` for SSH.
    - **Ollama**: Previously served `llama3` at `http://host.docker.internal:11434`.
- **Status**: Successfully executes commands, handles errors (e.g., `bash: fakecommand: command not found`), and delivers fast, clean chat outputs.

## Setup Steps
### 1. Parrot OS VM Configuration
- **Installation**: 
  - [Install Parrot OS Hack The Box edition on VirtualBox](https://help.hackthebox.com/en/articles/6369713-installing-parrot-security-on-a-vm) with the following settings:
      - Type: Linux, Debian (64-bit).
      - Memory: 4GB (minimum 2GB).
      - Storage: 20GB dynamic disk.
      - Network: Bridged Adapter (to allow SSH access from your host machine to the VM’s HTB-assigned IP).
  - After setup, checked the VM’s username with `whoami` (e.g., `user`) and IP address using `ifconfig` (e.g., my VM was assigned `10.0.0.215` by the network).
```bash
ifconfig
# Example output:
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
      inet 10.0.0.215  netmask 255.255.255.0  broadcast 10.0.0.255
# Note your VM’s IP (e.g., inet address) for SSH configuration.
```
_Note:_ Your VM’s IP will depend on your network settings (e.g., DHCP). Use the IP shown by `ifconfig` in place of 10.0.0.215 for all initial SSH commands and tool configurations (before we start interacting with HTB network).

- **Connect to Hack The Box VPN**: 
  - **Purpose**: Connect the VM to the HTB network to assign it an HTB IP (e.g., `10.10.14.7`) for challenge access.
  - **Steps**:
    1. Sign up for an HTB account at `hackthebox.com`.
    2. In the VM, download your OpenVPN configuration file (e.g., `academy-regular.ovpn`) from `https://academy.hackthebox.com/vpn` using a browser (e.g., Firefox in Parrot OS).
    3. Install OpenVPN in the VM:
    ```bash
    sudo apt update
    sudo apt install openvpn
    ```
    4. Start the OpenVPN Server:
    ```bash
    sudo systemctl start openvpn
    sudo systemctl status openvpn
    ```
    5. Connect to the HTB VPN:
    ```bash
    sudo openvpn ~/academy-regular.ovpn
    ```
    6. Verify the connection:
    ```bash
    ip addr show tun0
    # Expect a tun0 interface with an IP (e.g., 10.10.10.x)
    ```
    _Note_: Keep the VPN running in the VM to maintain HTB network access.

- **SSH Server**: 
    - Install and enable `openssh-server`:
    ```bash
    sudo apt install openssh-server
    sudo systemctl enable ssh --now
    sudo systemctl status ssh
    ```
    - Configure Key-Based Authentication between VM and host machine:
        1. Generate a SSH Key Pair on host machine: `ssh-keygen -t rsa`
        _Note_: Take note of the passphrase you entered. 
        2. Copy the Public Key to the VM: `ssh-copy-id -i ~/.ssh/id_rsa.pub user@<your-vm-ip>`
        3. Configure the VM to Allow Key-Based Authentication:
            - On the VM, edit the SSH configuration file: `sudo nano /etc/ssh/sshd_config`
            - Find the line that says **PasswordAuthentication** and change its value to no.
             - Save the file and restart the SSH service: `sudo systemctl restart ssh`

- **Verification**: 
    - Tested SSH from the host:
    ```bash
    ssh user@<your-vm-ip>
    ```
    - Confirmed VPN connectivity:
    ```bash
    ping 10.10.14.7  # HTB network IP
    ```
![WM SSH Setup](images/parrot-ssh-verification.png)
*Screenshot: Parrot OS VM configuration validation.*

### 2. Docker and Open WebUI Setup

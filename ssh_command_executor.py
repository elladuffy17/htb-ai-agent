"""
title: SSH Command Executor
author: Ella Duffy
version: 1.0.0
description: Executes commands on my remote HTB Parrot OS VM and returns the output, with logging.
"""

import paramiko
import os
import logging
import re

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
    def __init__(self):
        pass
    
    def ssh_command_executor(self, host: str, username: str, command: str) -> str:
        """
        Execute a command on my remote HTB Parrot OS VM using the SSH agent for authentication.
    
        Args:
            host (str): The IP address or hostname of the HTB VM (e.g., '192.168.1.100').
            username (str): The SSH username (e.g., 'parrot' or 'user').
            command (str): The command to execute (e.g., 'whoami').
    
        Returns:
            str: The output of the command (stdout + stderr).

        Raises:
            ValueError: If the SSH_PASSPHRASE environment variable is not set.
        """
        logger.info(f"Connecting to {host} as {username}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        #key_path = "/app/tools/id_rsa"  # Path inside the container
        key_path = "/Users/elladuffy/.ssh/id_rsa" # Local testing
        passphrase = os.environ.get("SSH_PASSPHRASE")
        if not passphrase:
            logger.error("SSH_PASSPHRASE environment variable not set")
            raise ValueError("SSH_PASSPHRASE environment variable not set")
        try:
            client.connect(host, username=username, key_filename=key_path, passphrase=passphrase)
            full_command = f"PATH=$PATH:/sbin:/usr/sbin {command}"
            logger.info(f"Executing command: {full_command}")
            stdin, stdout, stderr = client.exec_command(full_command)
            stderr_data = stderr.read().decode()
            if stderr_data:
                logger.warning(f"Command stderr: {stderr_data.strip()}")
            result = stdout.read().decode() + stderr.read().decode()
            logger.info(f"Command output:\n {result}")
            return result
        except Exception as e:
            logger.error(f"SSH execution failed: {str(e)}")
            raise
        finally:
            client.close()
            logger.debug("SSH connection closed")
    
    def scan_ports(self, host: str, username: str, target: str) -> dict:
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
            return ports
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {}
    
    def enumerate_users(self, host: str, username: str, target: str, wordlist="/usr/share/seclists/Usernames/Names/names.txt") -> list:
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
            return users_list
        except Exception as e:
            logger.error(f"User enumeration failed: {str(e)}")
            return []
        
    def main(self, host: str, username: str, target: str):
        logger.info(f"Starting attack chain on {target} via {host}")
        ports = self.scan_ports(host, username, target)
        if ports:
            logger.info(f"Found ports: {ports}")
            if "79" in ports:
                users = self.enumerate_users(host, username, target)
                logger.info(f"Found users: {users}")
            else:
                logger.warning("No exploitable ports with finger service (79) found")
        else:
            logger.warning("Port scan failed or no ports found")

if __name__ == "__main__":
    tools = Tools()
    host = "10.0.0.215"  # IP of Local VM for testing
    username = "user"  # Username for VM
    target = "10.10.10.76"  # HTB Sunday target
    tools.main(host, username, target)
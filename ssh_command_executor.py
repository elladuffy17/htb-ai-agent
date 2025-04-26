"""
title: SSH Command Executor
author: Ella Duffy
version: 1.0.0
description: Executes commands on my remote HTB Parrot OS VM and returns the output, with logging.
"""

import paramiko
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/ssh_executor.log'),  # Save logs to file
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
        key_path = "/app/tools/id_rsa"  # Path inside the container
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
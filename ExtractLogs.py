import subprocess
import os

# Function to extract network logs
def extract_network_logs():
    # Replace this command with the command to extract network logs on your system
    network_logs_command = "netstat -a"
    network_logs = subprocess.check_output(network_logs_command, shell=True)
    with open("network_logs.txt", "w") as file:
        file.write(network_logs.decode("utf-8"))

# Function to extract system usage logs
def extract_system_usage_logs():
    system_usage_logs_command = "tasklist"
    system_usage_logs = subprocess.check_output(system_usage_logs_command, shell=True)
    with open("system_usage_logs.txt", "w") as file:
        file.write(system_usage_logs.decode("utf-8"))

# Function to extract entire system logs
def extract_entire_system_logs():
    entire_system_logs_command = "wevtutil qe System /c:1000 /rd:true /f:text"
    entire_system_logs = subprocess.check_output(entire_system_logs_command, shell=True)
    with open("entire_system_logs.txt", "w") as file:
        file.write(entire_system_logs.decode("utf-8"))

# Call the functions to extract logs from different sources
extract_network_logs()
extract_system_usage_logs()
extract_entire_system_logs()



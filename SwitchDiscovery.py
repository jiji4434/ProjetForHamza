import csv
import ipaddress
import paramiko
import socket
import concurrent.futures
from threading import Lock
from ping3 import ping

def check_ping(ip):
    result = ping(str(ip), timeout=1)
    return result is not None and result != False

def get_serial_number(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(str(ip), username=username, password=password, timeout=5)
        
        commands = [
            "show version | include Serial Number",
            "show inventory | include SN:",
            "show sprom backplane 1 | include Serial Number",
            "show diag | include Serial Number"
        ]
        
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode().strip()
            if "Serial Number" in output or "SN:" in output:
                serial = output.split(":")[-1].strip()
                client.close()
                return serial
        
        client.close()
        return "Numéro de série non trouvé"
    except Exception as e:
        return f"Erreur: {str(e)}"

def check_ssh(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(str(ip), username=username, password=password, timeout=2)
        client.close()
        return "OK"
    except:
        return "NOT OK"

def scan_ip(ip, ssh_username, ssh_password):
    if check_ping(ip):
        ssh_status = check_ssh(ip, ssh_username, ssh_password)
        if ssh_status == "OK":
            serial = get_serial_number(ip, ssh_username, ssh_password)
        else:
            serial = "N/A"
        return str(ip), 'OK', ssh_status, serial
    else:
        return str(ip), 'NOT OK', 'N/A', 'N/A'

def main():
    company_name = input("Entrez le nom de l'entreprise : ")
    ip_range = input("Entrez la plage d'adresses IP à scanner (ex: 192.168.1.0/24) : ")
    ssh_username = input("Entrez le nom d'utilisateur SSH : ")
    ssh_password = input("Entrez le mot de passe SSH : ")

    network = ipaddress.ip_network(ip_range)
    
    with open(f"{company_name}_network_scan.csv", 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Ping Status', 'SSH Status', 'Serial Number']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        file_lock = Lock()
        
        def write_result(result):
            ip, ping_status, ssh_status, serial = result
            with file_lock:
                writer.writerow({'IP': ip, 'Ping Status': ping_status, 'SSH Status': ssh_status, 'Serial Number': serial})
            print(f"Scanned {ip}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_ip, ip, ssh_username, ssh_password) for ip in network.hosts()]
            for future in concurrent.futures.as_completed(futures):
                write_result(future.result())

    print(f"Scan terminé. Les résultats ont été enregistrés dans {company_name}_network_scan.csv")

if __name__ == "__main__":
    main()
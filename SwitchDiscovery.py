import csv
import ipaddress
import paramiko
import socket
import concurrent.futures
from threading import Lock
from ping3 import ping
import re
import os

def sanitize_filename(filename):
    return re.sub(r'[^\w\-_\. ]', '_', filename)

# Fonction pour vérifier si une adresse IP est valide
def check_ping(ip):
    result = ping(str(ip), timeout=1)
    return result is not None and result != False

# Fonction pour vérifier si un hôte est joignable via SSH
def check_ssh(ip, username, password):
    ip_str = str(ip)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip_str, username=username, password=password, timeout=2)
        client.close()
        return "OK"
    except:
        return "NOT OK"
# Fonction pour scanner une adresse IP
def scan_ip(ip, ssh_username, ssh_password):
    if check_ping(ip):
        ssh_status = check_ssh(ip, ssh_username, ssh_password)
        return str(ip), 'OK', ssh_status
    else:
        return str(ip), 'NOT OK', 'N/A'
# Fonction pour valider une entrée utilisateur
def get_valid_input(prompt, validation_func):
    while True:
        user_input = input(prompt)
        if validation_func(user_input):
            return user_input
        print("Entrée non valide. Veuillez réessayer.")
# Fonction pour valider le nom de l'entreprise
def validate_company_name(name):
    return bool(name.strip()) and len(name) <= 50
 # Fonction pour valider la plage d'adresses IP
def validate_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range)
        return True
    except ValueError:
        return False

def main():
    company_name = get_valid_input("Entrez le nom de l'entreprise : ", validate_company_name)
    ip_range = get_valid_input("Entrez la plage d'adresses IP à scanner (ex: 192.168.1.0/24) : ", validate_ip_range)
    ssh_username = input("Entrez le nom d'utilisateur SSH : ")
    ssh_password = input("Entrez le mot de passe SSH : ")

    network = ipaddress.ip_network(ip_range)
    
    safe_filename = sanitize_filename(f"{company_name}_network_scan.csv")
    full_path = os.path.join(os.getcwd(), safe_filename)
    
    with open(full_path, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Ping Status', 'SSH Status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        file_lock = Lock()
        # Fonction pour écrire les résultats dans un fichier CSV
        def write_result(result):
            ip, ping_status, ssh_status = result
            with file_lock:
                writer.writerow({'IP': ip, 'Ping Status': ping_status, 'SSH Status': ssh_status})
            print(f"Scanned {ip}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_ip, ip, ssh_username, ssh_password) for ip in network.hosts()]
            for future in concurrent.futures.as_completed(futures):
                write_result(future.result())   

    print(f"Scan terminé. Les résultats ont été enregistrés dans {safe_filename}")

if __name__ == "__main__":
    main()
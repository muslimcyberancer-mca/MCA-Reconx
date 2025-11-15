import requests
import socket
import whois
import os
from bs4 import BeautifulSoup

# --------------- Banner ---------------
def banner():
    print("""
╔══════════════════════════════════════╗
║          🛰️ MCA-ReconX v1.0          ║
║     Cyber Team of Ansar | Ifnyt_404  ║
╚══════════════════════════════════════╝
    """)

# ------------- Subdomain Scan -------------
def subdomain_scan(domain):
    print("\n[+] Subdomain Enumeration Running...\n")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            print("[!] Failed to fetch subdomains.")
            return

        data = r.json()
        subs = set()

        for entry in data:
            sub = entry["name_value"]
            subs.update(sub.split("\n"))

        if not os.path.exists("results"):
            os.mkdir("results")

        with open("results/subdomains.txt", "w") as f:
            for s in subs:
                f.write(s + "\n")

        print("[✓] Subdomain scan complete. Saved: results/subdomains.txt")

    except Exception as e:
        print("[!] Error:", e)

# ------------- Port Scan -------------
def port_scan(domain):
    print("\n[+] Port Scanning Started...\n")
    target_ip = socket.gethostbyname(domain)
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

    open_ports = []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()

    if not os.path.exists("results"):
        os.mkdir("results")

    with open("results/ports.txt", "w") as f:
        for p in open_ports:
            f.write(str(p) + "\n")

    print("[✓] Port scan complete. Saved: results/ports.txt")

# ------------- WHOIS Lookup -------------
def whois_lookup(domain):
    print("\n[+] WHOIS Lookup Running...\n")
    try:
        info = whois.whois(domain)

        if not os.path.exists("results"):
            os.mkdir("results")

        with open("results/whois.txt", "w") as f:
            f.write(str(info))

        print("[✓] WHOIS Saved: results/whois.txt")

    except:
        print("[!] WHOIS Lookup Failed")

# ------------- Technology Detector -------------
def tech_detect(url):
    print("\n[+] Technology Detection Started...\n")
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        tech = []

        if "wp-content" in r.text:
            tech.append("WordPress")

        if soup.find("meta", {"name": "generator"}):
            tech.append(soup.find("meta", {"name": "generator"})["content"])

        if not os.path.exists("results"):
            os.mkdir("results")

        with open("results/tech.txt", "w") as f:
            for t in tech:
                f.write(t + "\n")

        print("[✓] Technology Detection Saved: results/tech.txt")

    except:
        print("[!] Technology Detection Failed")

# ------------- Menu -------------
def menu():
    banner()
    print("""
[1] Subdomain Scan
[2] Port Scan
[3] WHOIS Lookup
[4] Technology Detection
[5] Full Recon
[0] Exit
""")

    choice = input("Select Option: ")

    domain = ""

    if choice in ["1", "2", "3", "5"]:
        domain = input("Enter Domain (example.com): ")

    if choice == "4":
        url = input("Enter URL (https://example.com): ")

    if choice == "1":
        subdomain_scan(domain)

    elif choice == "2":
        port_scan(domain)

    elif choice == "3":
        whois_lookup(domain)

    elif choice == "4":
        tech_detect(url)

    elif choice == "5":
        subdomain_scan(domain)
        port_scan(domain)
        whois_lookup(domain)
        tech_detect("https://" + domain)

        print("\n[✓] Full Recon Complete!")

    elif choice == "0":
        print("Goodbye…")

    else:
        print("Invalid Option!")

# ---------- Start Program ----------
if __name__ == "__main__":
    menu()

import requests
import socket
import whois
import os
import sys
import time
from bs4 import BeautifulSoup
import subprocess

# --------------- Slow Print Function -----------------
def slow(text, speed=0.002):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

# ---------------- Auto Updater -----------------------
REPO_URL = "https://github.com/muslimcyberancer-mca/MCA-Reconx.git"

def auto_update():
    slow("\n[🔄] Checking for updates...\n", 0.002)
    try:
        if not os.path.exists(".git"):
            slow("[⚠] Git repo missing! Auto-update not available.", 0.002)
            return

        result = subprocess.run(["git", "pull"], capture_output=True, text=True)
        
        if "Already up to date" in result.stdout:
            slow("[✓] You are using the latest version.\n", 0.002)
        else:
            slow("[🚀] Update installed! Restarting tool...\n", 0.002)
            time.sleep(2)
            os.execv(sys.executable, ['python'] + sys.argv)

    except Exception as e:
        slow(f"[!] Update failed: {e}\n", 0.002)

# --------------- Banner -----------------
def banner():
    art = """
╔════════════════════════════════════════════╗
║                🛰️ MCA-ReconX v2.0          ║
║    Cyber Team of Ansar | By Ifnyt_404      ║
╚════════════════════════════════════════════╝
"""
    slow(art, 0.001)

# ------------- Subdomain Scan -------------
def subdomain_scan(domain):
    slow("\n[+] Subdomain Enumeration Running...\n", 0.002)
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        data = r.json()

        subs = set()
        for entry in data:
            sub = entry["name_value"]
            subs.update(sub.split("\n"))

        if not os.path.exists("reports"):
            os.mkdir("reports")

        with open("reports/subdomains.txt", "w") as f:
            for s in subs:
                f.write(s + "\n")

        slow("[✓] Saved: reports/subdomains.txt\n", 0.002)

    except Exception as e:
        slow(f"[!] Error: {e}\n", 0.002)

# ------------- Port Scan -------------
def port_scan(domain):
    slow("\n[+] Port Scanning Started...\n", 0.002)
    try:
        target_ip = socket.gethostbyname(domain)
    except:
        slow("[!] Domain resolution failed.\n", 0.002)
        return

    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]
    open_ports = []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        if s.connect_ex((target_ip, port)) == 0:
            open_ports.append(port)
        s.close()

    if not os.path.exists("reports"):
        os.mkdir("reports")

    with open("reports/ports.txt", "w") as f:
        for p in open_ports:
            f.write(str(p) + "\n")

    slow("[✓] Saved: reports/ports.txt\n", 0.002)

# ------------- WHOIS Lookup -------------
def whois_lookup(domain):
    slow("\n[+] WHOIS Lookup Running...\n", 0.002)
    try:
        info = whois.whois(domain)

        if not os.path.exists("reports"):
            os.mkdir("reports")

        with open("reports/whois.txt", "w") as f:
            f.write(str(info))

        slow("[✓] Saved: reports/whois.txt\n", 0.002)

    except:
        slow("[!] WHOIS Lookup Failed\n", 0.002)

# ------------- Technology Detector -------------
def tech_detect(url):
    slow("\n[+] Technology Detection Started...\n", 0.002)
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        tech = []

        if "wp-content" in r.text:
            tech.append("WordPress")

        gen = soup.find("meta", {"name": "generator"})
        if gen:
            tech.append(gen["content"])

        if not os.path.exists("reports"):
            os.mkdir("reports")

        with open("reports/tech.txt", "w") as f:
            for t in tech:
                f.write(t + "\n")

        slow("[✓] Saved: reports/tech.txt\n", 0.002)

    except:
        slow("[!] Technology Detection Failed\n", 0.002)

# ------------- Menu -------------
def menu():
    auto_update()
    banner()

    slow("""
[1] Subdomain Scan
[2] Port Scan
[3] WHOIS Lookup
[4] Technology Detection
[5] Full Recon
[0] Exit

""", 0.002)

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
        slow("\n[✓] FULL RECON COMPLETE!\n", 0.002)

    elif choice == "0":
        slow("Goodbye…", 0.002)
        exit()

    else:
        slow("Invalid Option!", 0.002)


# ---------- Start Program ----------
if __name__ == "__main__":
    menu()
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

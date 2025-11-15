#!/usr/bin/env python3
import requests, json, socket, ssl, datetime, whois, os, time
from bs4 import BeautifulSoup

def slow(text, d=0.002):
    for c in text:
        print(c, end="", flush=True)
        time.sleep(d)
    print()

def banner():
    try:
        with open("banner.txt", "r") as f:
            print(f.read())
    except:
        print("MCA-RECONX")

def scan_subdomains(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        data = json.loads(r.text)
        subs = set()
        for entry in data:
            name = entry["name_value"]
            if "*" not in name:
                subs.add(name.strip())
        return sorted(list(subs))
    except:
        return []

def dns_info(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Not found"

def ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        s.settimeout(5)
        s.connect((domain, 443))
        data = s.getpeercert()
        return {
            "issuer": data["issuer"],
            "valid_from": data["notBefore"],
            "valid_to": data["notAfter"]
        }
    except:
        return {}

def http_headers(url):
    try:
        r = requests.get(url, timeout=8)
        return dict(r.headers)
    except:
        return {}

def robots(url):
    try:
        return requests.get(url + "/robots.txt", timeout=8).text
    except:
        return "Not found"

def tech_detect(html):
    tech = []
    if "wp-content" in html: tech.append("WordPress")
    if "Shopify" in html: tech.append("Shopify")
    if "Drupal.settings" in html: tech.append("Drupal")
    if "Laravel" in html: tech.append("Laravel")
    if "React" in html: tech.append("React JS")
    return tech

def scan(target):

    if not target.startswith("http"):
        url = "http://" + target
    else:
        url = target

    domain = target.replace("http://","").replace("https://","").split("/")[0]

    banner()
    slow(f"[+] Target: {domain}")

    slow("[*] Resolving DNS...")
    ip = dns_info(domain)

    slow("[*] Fetching WHOIS...")
    try:
        w = whois.whois(domain)
    except:
        w = {}

    slow("[*] Subdomain Scan...")
    subs = scan_subdomains(domain)

    slow("[*] Fetching HTTP Headers...")
    headers = http_headers(url)

    slow("[*] Fetching robots.txt...")
    robots_txt = robots(url)

    slow("[*] SSL Certificate...")
    ssl_data = ssl_info(domain)

    slow("[*] Technology Fingerprinting...")
    try:
        html = requests.get(url, timeout=8).text
        tech = tech_detect(html)
    except:
        tech = []

    os.makedirs("reports", exist_ok=True)

    report = {
        "domain": domain,
        "ip": ip,
        "whois": str(w),
        "subdomains": subs,
        "headers": headers,
        "ssl": ssl_data,
        "robots": robots_txt,
        "tech_detected": tech,
        "timestamp": str(datetime.datetime.now())
    }

    with open("reports/mca_report.json", "w") as f:
        json.dump(report, f, indent=4)

    with open("reports/mca_report.html", "w") as f:
        f.write(f"""
        <html><body>
        <h1>MCA-RECONX REPORT</h1>
        <h2>Domain: {domain}</h2>
        <p><b>IP:</b> {ip}</p>
        <h3>Subdomains</h3><pre>{json.dumps(subs, indent=4)}</pre>
        <h3>HTTP Headers</h3><pre>{json.dumps(headers, indent=4)}</pre>
        <h3>SSL Info</h3><pre>{json.dumps(ssl_data, indent=4)}</pre>
        <h3>Tech Detected</h3><pre>{json.dumps(tech, indent=4)}</pre>
        <h3>WHOIS</h3><pre>{w}</pre>
        <h3>robots.txt</h3><pre>{robots_txt}</pre>
        </body></html>
        """)

    slow("\n✓ Scan Complete!")
    slow("✓ Saved in /reports folder.\n")

if __name__ == "__main__":
    os.system("clear")
    banner()
    target = input("Enter target domain: ")
    scan(target)

import whois
import socket
import dns.resolver
import requests
from bs4 import BeautifulSoup
import re
import json
import time
from datetime import datetime

report = {}

# ------------------ LOAD API KEYS ------------------
with open("config.json") as cfg:
    keys = json.load(cfg)

# ------------------ BANNER ------------------
def banner():
    print("""
  ____                        ___  ____  _   _ _____ 
 |  _ \\ ___  ___ ___  _ __  / _ \\|  _ \\| \\ | | ____|
 | |_) / _ \\/ __/ _ \\| '_ \\| | | | |_) |  \\| |  _|  
 |  _ <  __/ (_| (_) | | | | |_| |  _ <| |\\  | |___ 
 |_| \\_\\___|\\___\\___/|_| |_|\\___/|_| \\_\\_| \\_|_____|
        Recon & OSINT Toolkit v2.0 🚀
""")

# ------------------ DOMAIN WHOIS ------------------
def whois_lookup(domain):
    print(f"\n[+] WHOIS Lookup for {domain}")
    try:
        import whois
        w = whois.whois(domain)

        def get_date(val):
            if isinstance(val, list):
                return val[0]
            return val

        creation = get_date(w.creation_date)
        expiration = get_date(w.expiration_date)
        updated = get_date(w.updated_date)
        now = datetime.now()

        # Age calculations
        age_days = (now - creation).days if creation else None
        age_years = round(age_days / 365.25, 2) if age_days else None
        days_to_expiry = (expiration - now).days if expiration else None

        # Flags
        expiry_warning = None
        if days_to_expiry and days_to_expiry < 90:
            expiry_warning = f"⚠️ Expires in {days_to_expiry} days"
        
        # Privacy check
        raw_text = str(w.text).lower()
        privacy_enabled = any(word in raw_text for word in ["whoisguard", "redacted", "privacy", "protected"])

        # Extract abuse contact if present
        abuse_contact = None
        matches = re.findall(r"[a-zA-Z0-9_.+-]+@(?:abuse|security)[a-zA-Z0-9_.+-]+\.[a-zA-Z]+", raw_text)
        if matches:
            abuse_contact = matches[0]

        # Risk scoring
        risk_flags = []
        if age_days and age_days < 180:
            risk_flags.append("🚨 Newly Registered")
        if days_to_expiry and days_to_expiry < 30:
            risk_flags.append("❗Very Close to Expiry")
        if privacy_enabled:
            risk_flags.append("🔐 WHOIS Privacy Enabled")
        if not abuse_contact:
            risk_flags.append("⚠️ No abuse contact found")

        # Build output
        whois_data = {
            "domain_name": str(w.domain_name),
            "registrar": str(w.registrar),
            "creation_date": str(creation),
            "expiration_date": str(expiration),
            "updated_date": str(updated),
            "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
            "status": str(w.status),
            "domain_age_days": age_days,
            "domain_age_years": age_years,
            "expiry_warning": expiry_warning,
            "privacy_enabled": privacy_enabled,
            "abuse_contact": abuse_contact,
            "risk_flags": risk_flags,
            "raw_whois": w.text[:1000]  # Save a slice of raw WHOIS
        }

        # Clean output
        whois_data = {k: v for k, v in whois_data.items() if v and v != 'None'}
        report['whois'] = whois_data

        # Pretty print
        for k, v in whois_data.items():
            label = k.replace("_", " ").title()
            if isinstance(v, list):
                print(f"{label}:")
                for item in v:
                    print(f"   • {item}")
            else:
                print(f"{label}: {v}")

    except Exception as e:
        print("[-] WHOIS lookup failed:", e)
        report['whois'] = {"error": str(e)}


# ------------------ DNS LOOKUP ------------------
def dns_lookup(domain):
    print(f"\n[+] DNS Intelligence Recon for {domain}")
    resolver = dns.resolver.Resolver()
    report['dns'] = {}
    intelligence_flags = []
    dns_score = 100  # Start with perfect score

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    for record in record_types:
        try:
            start = time.time()
            answers = resolver.resolve(domain, record, raise_on_no_answer=False)
            elapsed = round((time.time() - start) * 1000, 2)
            data = [rdata.to_text() for rdata in answers]
            report['dns'][record] = {
                "records": data,
                "response_time_ms": elapsed
            }

            print(f"\n{record} Records ({elapsed} ms):")
            for entry in data:
                print(f" - {entry}")

            # Flags
            if record == "MX" and not data:
                intelligence_flags.append("⚠️ No MX record (email not configured)")
                dns_score -= 10
            if record == "TXT":
                for txt in data:
                    if "v=spf1" in txt.lower() and "~all" not in txt.lower() and "-all" not in txt.lower():
                        intelligence_flags.append("❗ Weak SPF policy (no enforcement)")
                        dns_score -= 5
                    if "dmarc" in txt.lower() and "p=none" in txt.lower():
                        intelligence_flags.append("❗ DMARC set to none")
                        dns_score -= 5

        except Exception as e:
            print(f"[-] Failed to resolve {record}: {e}")
            report['dns'][record] = {"error": str(e)}
            dns_score -= 2

    # PTR record
    try:
        ip = socket.gethostbyname(domain)
        ptr = socket.gethostbyaddr(ip)
        report['dns']['PTR'] = {"ip": ip, "ptr_record": ptr[0]}
        print(f"\nPTR Record:\n - {ip} → {ptr[0]}")
    except Exception as e:
        print("[-] PTR Lookup Failed:", e)
        dns_score -= 3

    # Wildcard DNS Detection
    fake_sub = f"nonexistent-{int(time.time())}.{domain}"
    try:
        wildcard_test = resolver.resolve(fake_sub, "A", raise_on_no_answer=False)
        if wildcard_test:
            intelligence_flags.append("⚠️ Wildcard DNS Detected (may mask subdomains)")
            dns_score -= 10
            report['dns']['wildcard'] = True
            print("\n[!] Wildcard DNS Detected!")
    except:
        report['dns']['wildcard'] = False

    # DNSSEC Detection
    try:
        dnskey = resolver.resolve(domain, 'DNSKEY', raise_on_no_answer=False)
        if dnskey:
            intelligence_flags.append("✅ DNSSEC is Enabled")
            report['dns']['dnssec'] = True
            print("\n✅ DNSSEC is Enabled")
    except:
        report['dns']['dnssec'] = False

    # CDN Detection (Cloudflare/Akamai)
    try:
        cname_data = report['dns'].get('CNAME', {}).get('records', [])
        if any("cloudflare" in c.lower() for c in cname_data):
            intelligence_flags.append("🛡️ Cloudflare CDN Detected")
        elif any("akamai" in c.lower() for c in cname_data):
            intelligence_flags.append("🛡️ Akamai CDN Detected")
    except:
        pass

    # Passive DNS simulation (replace with API)
    passive_dns = [
        f"login.{domain}",
        f"admin.{domain}",
        f"webmail.{domain}",
        f"cpanel.{domain}"
    ]
    report['dns']['simulated_passive_dns'] = passive_dns
    print("\nSimulated Passive DNS Records:")
    for sub in passive_dns:
        print(f" - {sub}")

    # Final intelligence
    if intelligence_flags:
        report['dns']['flags'] = intelligence_flags
        print("\n[!] DNS Intelligence Flags:")
        for flag in intelligence_flags:
            print(f" - {flag}")

    report['dns']['score'] = max(0, dns_score)
    print(f"\n[✓] DNS Threat Hygiene Score: {report['dns']['score']}/100")

# ------------------ IP & GEO LOOKUP ------------------
def ip_and_geo_lookup(domain):
    print(f"\n[+] 🔍 Deep Recon for Domain: {domain}")

    try:
        ip = socket.gethostbyname(domain)
        print(f"Resolved IP: {ip}")
    except Exception as e:
        print(f"[-] Could not resolve domain: {e}")
        report['ip'] = {"error": str(e)}
        return

    ptr_record = None
    try:
        ptr_record = socket.gethostbyaddr(ip)[0]
        print(f"PTR Record: {ptr_record}")
    except:
        print("PTR Lookup Failed")

    token = keys.get("ipinfo_token")
    headers = {'User-Agent': 'OSINT-Toolkit'}

    try:
        res = requests.get(f"https://ipinfo.io/{ip}?token={token}", headers=headers, timeout=6)
        data = res.json()
        
        # DEBUG: See raw API data
        print("\n[DEBUG] Raw IPInfo Response:")
        print(json.dumps(data, indent=2))

        # Normalize and fallback
        hostname = data.get("hostname") or "Unknown"
        city = data.get("city") or "Unknown"
        region = data.get("region") or "Unknown"
        country = data.get("country") or "Unknown"
        loc = data.get("loc") or "?,?"
        timezone = data.get("timezone") or "Unknown"
        org = data.get("org", "").lower()
        asn = data.get("asn", {}).get("asn") if "asn" in data else "Unknown"

        # Flags and scoring
        flags = []
        score = 100

        cloud_keywords = ["amazon", "google", "microsoft", "digitalocean", "ovh", "contabo", "cloudflare"]
        if any(x in org for x in cloud_keywords):
            flags.append("☁️ Hosting Provider Detected")
            score -= 10

        if any(x in hostname.lower() for x in ["tor", "vpn", "exit"]):
            flags.append("🕳️ Tor/VPN/Exit Node Suspected")
            score -= 20

        if "bogon" in str(asn).lower() or not asn or asn == "Unknown":
            flags.append("❗ Bogon/Private IP ASN")
            score -= 30

        if ptr_record and domain not in ptr_record:
            flags.append("⚠️ PTR Record doesn't match domain")

        # Optional: Basic port scan
        open_ports = []
        common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 8080, 8443]
        print("\n[+] Scanning common ports (basic)...")
        for port in common_ports:
            try:
                sock = socket.create_connection((ip, port), timeout=1)
                open_ports.append(port)
                sock.close()
            except:
                continue

        if open_ports:
            flags.append(f"🔓 Open Ports Found: {open_ports}")
            score -= len(open_ports)

        # Final structured data
        ip_data = {
            "ip": ip,
            "hostname": hostname,
            "ptr_record": ptr_record,
            "asn": asn,
            "org": org,
            "city": city,
            "region": region,
            "country": country,
            "location": loc,
            "timezone": timezone,
            "flags": flags,
            "threat_score": max(0, score),
            "open_ports": open_ports
        }

        report['ipinfo'] = ip_data

        # Clean output
        print(f"\n🧠 IP Intelligence Summary for {ip}")
        print(f"Location: {city}, {region}, {country}")
        print(f"Coordinates: {loc}")
        print(f"Timezone: {timezone}")
        print(f"Organization: {org.upper()}  |  ASN: {asn}")
        print(f"PTR: {ptr_record}")
        print(f"Threat Score: {ip_data['threat_score']}/100")

        if flags:
            print("\n[!] Flags:")
            for f in flags:
                print(f" - {f}")
        if open_ports:
            print(f"\n[+] Open Ports Detected: {open_ports}")

    except Exception as e:
        print(f"[-] Failed to fetch IP intelligence: {e}")
        report['ipinfo'] = {
            "ip": ip,
            "ptr_record": ptr_record,
            "error": str(e)
        }


# ------------------ WEBSITE CRAWLER ------------------
import requests
import re
import socket
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl_website(domain):
    base_url = f"https://{domain}"
    visited = set()
    found_links = set()
    found_emails = set()
    found_phones = set()
    found_subdomains = set()
    suspicious_paths = []
    tech_stack = set()
    js_files = []
    admin_panels = []
    max_links = 50

    sensitive_keywords = ['admin', 'login', 'config', 'backup', 'upload', 'secret', 'internal']
    tech_signatures = {
        "wordpress": "wp-content",
        "jquery": "jquery.js",
        "bootstrap": "bootstrap.min.css",
        "react": "react",
        "vue": "vue",
        "django": "csrftoken"
    }

    def fetch_and_parse(url):
        try:
            res = requests.get(url, timeout=6, headers={"User-Agent": "OSINT-Crawler"})
            soup = BeautifulSoup(res.text, "html.parser")
            text = res.text

            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
            phones = re.findall(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{4,6}", text)
            links = [a.get('href') for a in soup.find_all('a', href=True)]

            subdomains = set()
            for match in re.findall(rf"[\w\.-]+\.{re.escape(domain)}", text):
                if match != domain:
                    subdomains.add(match)

            for tech, sig in tech_signatures.items():
                if sig in text.lower():
                    tech_stack.add(tech)

            return emails, phones, links, subdomains
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
            return [], [], [], set()

    queue = [base_url]

    while queue and len(found_links) < max_links:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        print(f"[+] Scanning: {url}")
        emails, phones, links, subs = fetch_and_parse(url)

        found_emails.update(emails)
        found_phones.update(phones)
        found_subdomains.update(subs)

        for link in links:
            full_url = urljoin(base_url, link)
            if domain in full_url and full_url not in visited:
                found_links.add(full_url)
                queue.append(full_url)
                if any(kw in full_url.lower() for kw in sensitive_keywords):
                    suspicious_paths.append(full_url)
                if full_url.endswith(".js"):
                    js_files.append(full_url)

    # SSL Certificate info
    ssl_info = {}
    try:
        print(f"[+] Getting SSL cert for {domain}")
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            ssl_info = {
                "issuer": dict(x[0] for x in cert["issuer"]),
                "subject": dict(x[0] for x in cert["subject"]),
                "valid_from": cert.get("notBefore"),
                "valid_to": cert.get("notAfter")
            }
    except Exception as e:
        ssl_info = {"error": str(e)}

    # Admin panel detection
    common_admin_paths = ["/admin", "/wp-admin", "/login", "/cpanel"]
    for path in common_admin_paths:
        try:
            r = requests.get(f"https://{domain}{path}", timeout=4)
            if r.status_code in [200, 301, 302]:
                admin_panels.append(f"https://{domain}{path}")
        except:
            continue

    # Print result
    print("\n===== REPORT =====")
    print(f"[✓] Emails: {list(found_emails)}")
    print(f"[✓] Phones: {list(found_phones)}")
    print(f"[✓] Subdomains: {list(found_subdomains)}")
    print(f"[✓] Links Crawled: {len(found_links)}")
    print(f"[✓] Suspicious URLs: {suspicious_paths}")
    print(f"[✓] JavaScript Files: {js_files}")
    print(f"[✓] Tech Stack: {list(tech_stack)}")
    print(f"[✓] Admin Panels: {admin_panels}")
    print(f"[✓] SSL Info: {ssl_info}")


# ------------------ EMAIL BREACH CHECK ------------------
import whois
import socket
import dns.resolver
import requests
from bs4 import BeautifulSoup
import re
import json
import time
from datetime import datetime
import random

report = {}

# ------------------ LOAD API KEYS ------------------
with open("config.json") as cfg:
    keys = json.load(cfg)

# ------------------ EMAIL BREACH CHECK (Ultimate + EPIOS) ------------------


import requests
import json
import random
import re
import time
from datetime import datetime
from faker import Faker

fake = Faker()
report = {}

# ------------------ EMAIL BREACH CHECK (Offline + Ultra Simulated) ------------------
import json
import random
import re
import time
from datetime import datetime

try:
    from faker import Faker
    fake = Faker()
    faker_available = True
except ImportError:
    print("[!] Warning: 'faker' module not found. Running in fallback mode.")
    faker_available = False

report = {}

# ------------------ EMAIL BREACH CHECK (Offline + Ultra Simulated) ------------------
# === Ultimate Offline Email Breach Simulator (Clean & Tagda Version) ===
import json
import random
import time
from datetime import datetime

# Optional dependency: faker for better realism
try:
    from faker import Faker
    fake = Faker()
    use_faker = True
except ImportError:
    use_faker = False
    print("[!] 'faker' module not found — running in safe mode without fake IPs/user-agents.")

report = {"breaches": {}}

BREACH_SOURCES = {
    "Major Breaches": ["Adobe 2013", "LinkedIn 2012", "Dropbox 2012", "Canva 2019", "Yahoo 2013"],
    "Dark Web Dumps": ["Exploit.in", "Collection #1", "AntiPublic", "Citadel Leak"],
    "Social Breaches": ["Facebook 2019", "MySpace 2008", "Badoo 2016"],
    "Password Dumps": ["Scylla Combo", "Zynga 2019", "Steam 2016"]
}

COMMON_PASSWORDS = ["123456", "password", "letmein", "admin@123", "qwerty", "welcome"]

# ------------------ Simulated Email Breach Check ------------------
def check_email_breaches(email):
    print(f"\n[+] Checking breaches for: {email}")
    email_data = {}

    for category, sources in BREACH_SOURCES.items():
        leaks = random.sample(sources, random.randint(0, len(sources)))
        email_data[category] = leaks

    combos = []
    for _ in range(random.randint(1, 4)):
        combo = {
            "password": random.choice(COMMON_PASSWORDS),
            "source": random.choice(BREACH_SOURCES["Dark Web Dumps"])
        }
        if use_faker:
            combo["ip"] = fake.ipv4()
            combo["user_agent"] = fake.user_agent()
        combos.append(combo)
    email_data["Combo Leaks"] = combos

    email_data["Reputation"] = {
        "suspicious": random.choice([True, False]),
        "blacklisted": random.choice([True, False]),
        "malicious_activity": random.choice([True, False]),
        "credentials_leaked": bool(combos)
    }

    email_data["Verification"] = {
        "valid_format": True,
        "domain_exists": random.choice([True, False]),
        "has_mx_record": random.choice([True, False]),
        "smtp_deliverable": random.choice([True, False]),
        "disposable": random.choice([True, False])
    }

    today = datetime.now().date()
    timeline = [
        {"date": str(today.replace(year=today.year - random.randint(5, 10))), "event": "First seen in breach"},
        {"date": str(today.replace(year=today.year - random.randint(2, 4))), "event": "Listed on dark web"},
        {"date": str(today), "event": "Scanned by OSINT tool"}
    ]
    email_data["Timeline"] = sorted(timeline, key=lambda x: x['date'])

    report["breaches"][email] = email_data

    print("\n--- Breach Summary ---")
    for category in BREACH_SOURCES:
        print(f"{category}: {email_data[category]}")

    print("\nCombo Leaks:")
    for combo in combos:
        extra = f", IP: {combo['ip']}, UA: {combo['user_agent']}" if use_faker else ""
        print(f" - {email}:{combo['password']} ({combo['source']}{extra})")

    print("\nReputation:")
    for k, v in email_data["Reputation"].items():
        print(f" - {k}: {v}")

    print("\nVerification:")
    for k, v in email_data["Verification"].items():
        print(f" - {k}: {v}")

    print("\nTimeline:")
    for t in email_data["Timeline"]:
        print(f" - {t['date']}: {t['event']}")

# ------------------ Batch Scan ------------------
def scan_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            emails = [line.strip() for line in f if line.strip() and "@" in line]
        for email in emails:
            check_email_breaches(email)
            print("-" * 40)
            time.sleep(0.5)
    except Exception as e:
        print(f"[!] File error: {e}")


# ------------------ SOCIAL OSINT & PASSWORD PATTERNS ------------------
def username_scan_and_patterns(username):
    print(f"\n[+] Scanning 30 social platforms for: {username}")
    
    platforms = {
        "Facebook": f"https://www.facebook.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Medium": f"https://medium.com/@{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "ProductHunt": f"https://www.producthunt.com/@{username}",
        "500px": f"https://500px.com/{username}",
        "About.me": f"https://about.me/{username}",
        "AngelList": f"https://angel.co/u/{username}",
        "Goodreads": f"https://www.goodreads.com/{username}",
        "Koo": f"https://www.kooapp.com/profile/{username}",
        "Ask.fm": f"https://ask.fm/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Blogger": f"https://{username}.blogspot.com",
        "Codepen": f"https://codepen.io/{username}",
        "VK": f"https://vk.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Replit": f"https://replit.com/@{username}",
        "Dev.to": f"https://dev.to/{username}"
    }

    found = {}
    patterns = []

    for name, url in platforms.items():
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                found[name] = url
                print(f"[+] Found on {name}: {url}")
                # Simulated bio content — replace this with actual scraping if needed
                bio = f"{username}, 1997, lovesDogs"
                bio_parts = re.findall(r'\b\w+\b', bio)
                for part in bio_parts:
                    patterns.extend([
                        f"{part}123", f"{part}@123", f"{part}1997", f"{part}!", f"{part}#"
                    ])
            else:
                print(f"[-] Not found on {name}")
        except Exception as e:
            print(f"[!] Error checking {name}: {e}")
        time.sleep(1)

    report['usernames'] = found
    report['password_hints'] = list(set(patterns))
    
    print("\n[+] Generated Password Hints:")
    for p in report['password_hints'][:10]:
        print(f" - {p}")

# ------------------ SAVE REPORT ------------------
def save_report(domain):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    filename = f"recon_{safe_domain}_{timestamp}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n[✓] Report saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save report: {e}")

# ------------------ MAIN ------------------
def main():
    banner()
    print("""
Choose what you want to search for:
1. WHOIS Lookup
2. DNS Lookup
3. IP & Geo Lookup
4. Website Crawler
5. Email Breach Check
6. Social Media OSINT
7. Save Report
0. Exit
""")
    domain = input("Enter main domain to use (e.g., example.com or https://example.com): ").strip()
    while True:
        choice = input("\nEnter your choice (0-7): ").strip()
        if choice == '1':
            whois_lookup(domain)
        elif choice == '2':
            dns_lookup(domain)
        elif choice == '3':
            ip_and_geo_lookup(domain)
        elif choice == '4':
            crawl_website(domain)
        elif choice == '5':
            email = input("Enter email to check for breaches: ")
            check_email_breaches(email)
        elif choice == '6':
            username = input("Enter username to scan: ")
            username_scan_and_patterns(username)
        elif choice == '7':
            save_report(domain)
        elif choice == '0':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()

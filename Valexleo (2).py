import socket
import requests
import re
import sys
import time
import os
import subprocess
import platform
from pathlib import Path
from colorama import init, Fore, Style
import whois
from urllib.parse import urlparse
import ssl
import subprocess
import platform
import time
import socket
from colorama import Fore
import dns.query
import dns.zone
import dns.resolver
from colorama import Fore
import platform
import subprocess
import itertools, threading, time, sys
from tqdm import tqdm
import time
import time
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)

def loading_bar(text="İşlem Yükleniyor...", seconds=3):
    print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    
    for i in tqdm(range(100), bar_format="{l_bar}{bar}| {n_fmt}%"):
        color = colors[i % len(colors)]
        tqdm.write(color + "█" + Style.RESET_ALL, end="\r")
        time.sleep(seconds / 100)

    print(Fore.GREEN + "\n✔ İşlem tamamlandı!\n" + Style.RESET_ALL)
    








def konum_detayli(ip_adresi):
    url = f"https://ipwho.is/{ip_adresi}"
    try:
        response = requests.get(url)
        data = response.json()
        if data.get("success"):
            print("\n--- IP Konum Bilgisi ---")
            print(f"IP: {data['ip']}")
            print(f"Ülke: {data['country']}")
            print(f"İl (Bölge): {data['region']}")
            print(f"İlçe/Şehir: {data['city']}")
            print(f"Posta Kodu: {data.get('postal', 'Yok')}")
            print(f"Koordinatlar: {data['latitude']}, {data['longitude']}")
            print(f"Haritada Gör: https://www.google.com/maps?q={data['latitude']},{data['longitude']}\n")
        else:
            print("❌ Konum bilgisi alınamadı. IP doğru mu kontrol et.")
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")

def servis_tanima(ip):
    print("\n[+] Servis Tanımlama Başladı...\n")
    yaygin_portlar = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Alt"
    }

    for port in yaygin_portlar:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Port {port} açık ({yaygin_portlar[port]})")
            sock.close()
        except Exception as e:
            print(f"[-] Port {port} kontrol edilemedi: {e}")

    print("\n[✓] Servis Tanımlama Tamamlandı.")






def robots_txt_scan(domain_or_url):
    print(Fore.CYAN + f"\n[+] {domain_or_url} için robots.txt taraması başlatılıyor...\n")
    domain = clean_domain(domain_or_url)
    urls = [f"https://{domain}/robots.txt", f"http://{domain}/robots.txt"]

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for url in urls:
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200 and "Disallow" in response.text:
                print(Fore.GREEN + f"[✓] {url} dosyası bulundu!\n")
                for line in response.text.splitlines():
                    if line.strip().lower().startswith("disallow"):
                        print(Fore.YELLOW + f"[*] {line.strip()}")
                return
            elif response.status_code == 200:
                print(Fore.YELLOW + f"[!] {url} bulundu ancak özel içerik içermiyor.")
                return
        except requests.exceptions.RequestException:
            pass

    print(Fore.RED + "[!] robots.txt dosyası alınamadı veya site bu dosyayı barındırmıyor.")
    print(Fore.CYAN + "\n[!] Tarama tamamlandı.\n")



def exposed_files_scan(domain_or_url):
    print(Fore.CYAN + f"\n[+] {domain_or_url} adresinde yaygın açık dosyalar taranıyor...\n")
    domain = clean_domain(domain_or_url)
    base_urls = [f"http://{domain}", f"https://{domain}"]

    common_files = [
        ".env", ".git", ".git/config", ".htaccess", "backup.zip", "backup.sql",
        "db.sql", "config.php", "phpinfo.php", "admin.php", "test.php",
        "old.zip", "website-old.zip", "error.log", ".DS_Store"
    ]

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    found = False
    for base_url in base_urls:
        for file in common_files:
            url = f"{base_url}/{file}"
            try:
                response = requests.get(url, headers=headers, timeout=4, verify=False)
                if response.status_code == 200 and len(response.text.strip()) > 10:
                    print(Fore.GREEN + f"[!] BULUNDU: {url} (Status: {response.status_code}, Size: {len(response.text)} bytes)")
                    found = True
            except requests.exceptions.RequestException:
                pass

    if not found:
        print(Fore.RED + "[!] Açık yayında dosya bulunamadı.")

    print(Fore.CYAN + "\n[!] Tarama tamamlandı.\n")


def full_dir_scan(domain):
    print(Fore.CYAN + f"\n[+] {domain} için GELİŞMİŞ dizin/endpoint taraması başlatılıyor...\n")

    wordlist = [
        "admin", "login", "cpanel", "config", "dashboard", "webadmin", "phpmyadmin", "portal", "panel",
        "setup", "manage", "server-status", "backup", "upload", "register", "signin", "signup",
        ".git", ".env", "db", "monitor", "console", "logs", "errors", "test", "dev", "beta", "staging"
    ]

    domain = clean_domain(domain)
    base_url = f"https://{domain}"
    headers = {"User-Agent": "Mozilla/5.0"}

    found_any = False

    for path in wordlist:
        url = f"{base_url}/{path}"
        try:
            response = requests.get(url, timeout=5, headers=headers, verify=False)
            if response.status_code in [200, 301, 302]:
                print(Fore.GREEN + f"[FOUND] {url} — Status: {response.status_code}")
                found_any = True
            elif response.status_code == 403:
                print(Fore.YELLOW + f"[FORBIDDEN] {url} — Status: 403")
                found_any = True
        except:
            pass

    if not found_any:
        print(Fore.RED + "[!] Hiçbir endpoint bulunamadı.")
    print(Fore.CYAN + "\n[!] Gelişmiş dizin taraması tamamlandı.\n")



def dir_scan(domain):
    print(Fore.CYAN + f"\n[+] {domain} için dizin/endpoint taraması başlatılıyor...\n")
    
    wordlist = [
        "admin", "login", "dashboard", "config", "upload", "panel", "portal",
        "backup", "dev", "test", "server-status", ".git", ".env", "cpanel", "private"
    ]

    domain = clean_domain(domain)  # http(s) kısmını ayıkla
    base_url = f"https://{domain}"
    headers = {"User-Agent": "Mozilla/5.0"}

    for path in wordlist:
        url = f"{base_url}/{path}"
        try:
            response = requests.get(url, timeout=5, headers=headers, verify=False)
            if response.status_code in [200, 301, 302]:
                print(Fore.GREEN + f"[FOUND] {url} — Status: {response.status_code}")
            elif response.status_code == 403:
                print(Fore.YELLOW + f"[FORBIDDEN] {url} — Status: 403 (Erişim Engellendi)")
        except requests.exceptions.RequestException:
            continue

    print(Fore.CYAN + "\n[!] Dizin taraması tamamlandı.\n")


def check_http_headers(domain):
    print(Fore.CYAN + f"\n[+] {domain} için HTTP güvenlik başlıkları kontrol ediliyor...\n")
    
    headers_to_check = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        found = response.headers
        for header in headers_to_check:
            if header in found:
                print(Fore.GREEN + f"[OK] {header} → {found[header]}")
            else:
                print(Fore.RED + f"[MISSING] {header} başlığı eksik!")
    except Exception as e:
        print(Fore.RED + f"[!] Hata oluştu: {e}")
    print(Fore.CYAN + "\n[!] HTTP başlık analizi tamamlandı.\n")




def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
       
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def ping_ip(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "1000", ip] if platform.system().lower() == "windows" else ["ping", param, "1", "-W", "1", ip]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def scan_local_network():
    local_ip = get_local_ip()
    print(f"Yerel IP adresiniz: {local_ip}")
    base_ip = ".".join(local_ip.split(".")[:-1])
    print(f"Ağ bloğu: {base_ip}.0/24")
    active_ips = []
    print("Ağdaki aktif cihazlar taranıyor, lütfen bekleyin...")
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        if ping_ip(ip):
            active_ips.append(ip)
            print(f"[AKTİF] {ip}")
    if not active_ips:
        print("Ağda aktif cihaz bulunamadı.")
    return active_ips



def get_wifi_info():
    if platform.system() != "Windows":
        print(Fore.RED + "[!] Bu özellik sadece Windows üzerinde çalışır.")
        return

    print(Fore.CYAN + "\n[+] Bağlı olduğun Wi-Fi ağı bilgileri alınıyor...\n")
    try:
        output = subprocess.check_output("netsh wlan show interfaces", shell=True, encoding="utf-8", stderr=subprocess.DEVNULL)

        patterns = {
            "SSID": r"^\s*SSID\s*:\s(.+)",
            "BSSID": r"^\s*BSSID\s*:\s(.+)",
            "Sinyal": r"^\s*Signal\s*:\s(.+)",
            "Radyo Tipi": r"^\s*Radio type\s*:\s(.+)",
            "Şifreleme": r"^\s*Authentication\s*:\s(.+)",
            "Kanal": r"^\s*Channel\s*:\s(.+)"
        }

        for name, pattern in patterns.items():
            match = re.search(pattern, output, re.MULTILINE)
            if match:
                print(Fore.GREEN + f"{name}: {match.group(1)}")
            else:
                print(Fore.YELLOW + f"{name}: Bilgi alınamadı")

    except subprocess.CalledProcessError:
        print(Fore.RED + "[!] Wi-Fi bilgileri alınamadı. Bağlı bir ağ olmayabilir.")



def detect_security_level(domain_or_url):
    from urllib.parse import urlparse
    domain = clean_domain(domain_or_url)
    parsed = urlparse("https://" + domain)
    score = 0
    print(Fore.CYAN + f"\n[+] {domain} için güvenlik seviyesi analizi başlatılıyor...\n")

    try:
        
        if parsed.scheme == "https" or "443" in domain:
            score += 2
            print(Fore.GREEN + "[✓] HTTPS kullanılıyor. +2")
        else:
            print(Fore.RED + "[✗] HTTPS kullanılmıyor.")

        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        print(Fore.GREEN + "[✓] SSL sertifikası geçerli. +3")
                        score += 3
        except:
            print(Fore.RED + "[✗] SSL sertifikası alınamadı.")

        
        response = requests.get("https://" + domain, timeout=5)
        headers = response.headers
        header_checks = {
            "X-Content-Type-Options": 1,
            "X-Frame-Options": 2,
            "Content-Security-Policy": 3,
            "Strict-Transport-Security": 2
        }
        for header, val in header_checks.items():
            if header in headers:
                print(Fore.GREEN + f"[✓] {header} var. +{val}")
                score += val
            else:
                print(Fore.YELLOW + f"[!] {header} yok.")

        
        if "Server" in headers:
            print(Fore.RED + f"[✗] Server bilgisi açık: {headers['Server']}. -2")
            score -= 2

        
        if response.history:
            print(Fore.GREEN + "[✓] HTTP → HTTPS yönlendirmesi var. +1")
            score += 1

        try:
            robots = requests.get(f"https://{domain}/robots.txt", timeout=3)
            if robots.status_code == 200:
                print(Fore.RED + "[✗] robots.txt erişilebilir. -2")
                score -= 2
        except:
            pass

    except Exception as e:
        print(Fore.RED + f"[!] Bağlantı hatası: {e}")
        return

    print(Fore.CYAN + f"\nToplam Güvenlik Puanı: {score}")
    if score <= 3:
        print(Fore.RED + "[!] Güvenlik düzeyi: ZAYIF 🟥")
    elif score <= 7:
        print(Fore.YELLOW + "[!] Güvenlik düzeyi: ORTA 🟧")
    else:
        print(Fore.GREEN + "[✓] Güvenlik düzeyi: İYİ 🟩")








def dns_zone_transfer(domain):
    print(Fore.CYAN + f"\n[+] {domain} için DNS Zone Transfer başlatılıyor...\n")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_ip = str(ns.target).rstrip('.')
            print(Fore.YELLOW + f"[i] NS Sunucusu: {ns_ip}")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                names = zone.nodes.keys()
                for name in names:
                    print(Fore.GREEN + f"[+] Subdomain: {name}.{domain}")
            except Exception as e:
                print(Fore.RED + f"[!] {ns_ip} üzerinden AXFR başarısız: {e}")
    except Exception as e:
        print(Fore.RED + f"[!] NS kayıtları alınamadı: {e}")


def ping_test(ip):
    print(Fore.CYAN + f"\n[+] {ip} için ping testi başlatılıyor...\n")
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "4", ip]
    try:
        output = subprocess.check_output(command, universal_newlines=True)
        print(Fore.GREEN + output)
    except subprocess.CalledProcessError:
        print(Fore.RED + "[!] Ping testi başarısız oldu.")
    print(Fore.CYAN + "[!] Ping testi tamamlandı.\n")

def traceroute(ip):
    print(Fore.CYAN + f"\n[+] {ip} için traceroute başlatılıyor...\n")
    if platform.system().lower() == "windows":
        cmd = ["tracert", ip]
    else:
        cmd = ["traceroute", ip]
    try:
        output = subprocess.check_output(cmd, universal_newlines=True)
        print(Fore.GREEN + output)
    except Exception as e:
        print(Fore.RED + f"[!] Traceroute yapılamadı: {e}")
    print(Fore.CYAN + "[!] Traceroute tamamlandı.\n")

def simple_network_vuln_scan(ip):
    print(Fore.CYAN + f"\n[+] {ip} için ağ açığı taraması başlatılıyor...\n")
    risky_ports = {21: "FTP (Güvensiz)", 23: "Telnet (Güvensiz)", 80: "HTTP (Şifresiz)", 445: "SMB (Riskli)"}
    open_risky_ports = []
    for port in risky_ports.keys():
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            open_risky_ports.append(port)
            sock.close()
        except:
            pass

    if open_risky_ports:
        for port in open_risky_ports:
            print(Fore.RED + f"[UYARI] {port} portu açık: {risky_ports[port]}")
    else:
        print(Fore.GREEN + "[+] Riskli port açığı bulunamadı.")
    print(Fore.CYAN + "[!] Ağ açığı taraması tamamlandı.\n")


init(autoreset=True)

def is_valid_ip(ip):
    pattern = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    )
    if pattern.match(ip):
        parts = ip.split('.')
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                return False
        if ip.startswith("127.") or ip.startswith("0.") or ip == "255.255.255.255":
            return False
        return True
    else:
        return False

def print_progress_bar(iteration, total, prefix='', suffix='', length=40, fill='█'):
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def port_scan(ip):
    print(Fore.CYAN + f"\n[+] {ip} üzerinde port taraması başlatılıyor...\n")
    total_ports = 100

    print(Fore.YELLOW + "Tarama başlayacak, lütfen bekleyin...")
    for i in range(total_ports + 1):
        print_progress_bar(i, total_ports, prefix='Hazırlanıyor:', suffix='Tamamlandı', length=40)
        time.sleep(0.02)

    print(Fore.GREEN + "\n[!] Tarama başladı.\n")

    open_ports = 0
    for port in range(1, total_ports + 1):
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            print(Fore.GREEN + f"[OPEN] Port {port}")
            banner_grab(ip, port)
            sock.close()
            open_ports += 1
        except:
            pass

    if open_ports == 0:
        print(Fore.RED + "[!] Açık port bulunamadı.")
    print(Fore.CYAN + "\n[!] Port taraması tamamlandı.\n")

def banner_grab(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        if banner:
            print(Fore.MAGENTA + f"    [BANNER] {banner}")
        else:
            print(Fore.MAGENTA + f"    [BANNER] Banner alınamadı.")
        sock.close()
    except:
        print(Fore.MAGENTA + f"    [BANNER] Banner alınamadı.")

def subdomain_scan(domain):
    print(Fore.CYAN + f"\n[+] {domain} üzerinde subdomain taraması başlatılıyor...\n")
    subdomains = ["www", "admin", "test", "ftp", "mail", "dev", "api", "beta"]
    found_any = False
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            response = requests.get(url, timeout=2)
            print(Fore.GREEN + f"[FOUND] {url} — Status: {response.status_code}")
            found_any = True
        except:
            pass
    if not found_any:
        print(Fore.RED + "[!] Hiç subdomain bulunamadı.")
    print(Fore.CYAN + "\n[!] Subdomain taraması tamamlandı.\n")

def whois_lookup(domain):
    print(Fore.CYAN + f"\n[+] {domain} için WHOIS sorgusu yapılıyor...\n")
    try:
        w = whois.whois(domain)
        if isinstance(w, dict):
            for key, value in w.items():
                print(Fore.GREEN + f"{key}: {value}")
        else:
            print(Fore.GREEN + str(w))
    except Exception as e:
        print(Fore.RED + f"[!] Whois sorgusu yapılamadı: {e}")
    print(Fore.CYAN + "\n[!] Whois sorgusu tamamlandı.\n")

def ip_geolocation(ip):
    print(Fore.CYAN + f"\n[+] {ip} için Geolocation sorgusu yapılıyor...\n")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if response['status'] == 'success':
            print(Fore.GREEN + f"IP: {response.get('query', 'Bilinmiyor')}")
            print(Fore.GREEN + f"Ülke: {response.get('country', 'Bilinmiyor')}")
            print(Fore.GREEN + f"Bölge: {response.get('regionName', 'Bilinmiyor')}")
            print(Fore.GREEN + f"Şehir: {response.get('city', 'Bilinmiyor')}")
            print(Fore.GREEN + f"ISP: {response.get('isp', 'Bilinmiyor')}")
        else:
            print(Fore.RED + "[!] Konum bilgisi alınamadı.")
    except Exception as e:
        print(Fore.RED + f"[!] Hata: {e}")
    print(Fore.CYAN + "\n[!] Geolocation sorgusu tamamlandı.\n")

def get_my_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        ip = response.json().get("ip")
        if ip:
            print(Fore.RED + f"\n[!] Kendi IP adresiniz: {ip}\n")
            return ip
        else:
            print(Fore.RED + "\n[!] IP adresi alınamadı.\n")
            return None
    except Exception as e:
        print(Fore.RED + f"\n[!] IP adresi alınamadı: {e}\n")
        return None
    

def ssl_certificate_info(domain):
    print(Fore.CYAN + f"\n[+] {domain} için SSL sertifikası bilgileri alınıyor...\n")
    try:
        hostname = clean_domain(domain)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        print(Fore.GREEN + f"Sertifika Sahibi        : {cert.get('subject', '')}")
        print(Fore.GREEN + f"İmzalayan Otorite       : {cert.get('issuer', '')}")
        print(Fore.GREEN + f"Geçerlilik Başlangıcı  : {cert.get('notBefore', '')}")
        print(Fore.GREEN + f"Geçerlilik Bitişi      : {cert.get('notAfter', '')}")
        print(Fore.GREEN + f"Seri Numarası          : {cert.get('serialNumber', '')}")
    except Exception as e:
        print(Fore.RED + f"[!] SSL bilgisi alınamadı: {e}")
    print(Fore.CYAN + "\n[!] SSL sertifika kontrolü tamamlandı.\n")


def menu_display(title, target):
    print(Fore.YELLOW + "\n" + "_" * 40)
    print(Fore.YELLOW + f"Seçilen İşlem : {title}")
    print(Fore.YELLOW + f"Hedef         : {target}")
    print(Fore.YELLOW + "_" * 40 + "\n")

def ban_message():
    print(Fore.RED + "\n[!!!] GEÇERSİZ GİRİŞ TESPİT EDİLDİ! BANLANDIN! [!!!]\n")
    sys.exit()

# Downloads klasör yolu
def get_download_folder():
    if sys.platform == "win32":
        try:
            import winreg
            sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                location = winreg.QueryValueEx(key, downloads_guid)[0]
                return location
        except Exception:
            return str(Path.home() / "Downloads")
        else:
            return str(Path.home() / "Downloads")

# Dosya açma fonksiyonu
def open_file(filepath):
    try:
        if platform.system() == 'Windows':
            os.startfile(filepath)
        elif platform.system() == 'Darwin':
            subprocess.call(('open', filepath))
        else:
            subprocess.call(('xdg-open', filepath))
    except Exception as e:
        print(Fore.RED + f"Dosya açılamadı: {e}")

# Domain veya URL'den sadece domain kısmını ayıklama
def clean_domain(domain_or_url):
    parsed = urlparse(domain_or_url)
    if parsed.netloc:
        return parsed.netloc
    else:
        return domain_or_url.split('/')[0]

# Web sitesi kaynak kodu kaydetme (requests ile, selenium yok)
def save_website_source(domain_or_url):
    domain = clean_domain(domain_or_url)
    download_folder = get_download_folder()
    filename = os.path.join(download_folder, domain.replace(".", "_") + "_source.txt")

    urls = [f"https://{domain}", f"http://{domain}"]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/115.0 Safari/537.36",
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Connection": "keep-alive"
    }

    for url in urls:
        try:
            response = requests.get(url, timeout=10, headers=headers, verify=False)
            response.raise_for_status()
            with open(filename, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(Fore.GREEN + f"{url} sitesinin kaynak kodu '{filename}' dosyasına kaydedildi.")
            open_file(filename)
            return
        except requests.exceptions.RequestException as e:
            print(Fore.YELLOW + f"{url} adresine erişilemedi veya içerik alınamadı: {e}")

    print(Fore.RED + "[!] Web sitesi kaynak kodu alınamadı veya site dinamik içerik kullanıyor olabilir.")

if __name__ == "__main__":
    while True:
        print(Fore.CYAN + r"""
__     ______  _      ______  _____  _____  _____
\ \   / / __ \| |    |  ____|/ ____|/ ____|/ ____|
 \ \_/ / |  | | |    | |__  | (___ | |    | (___
  \   /| |  | | |    |  __|  \___ \| |     \___ \
   | | | |__| | |____| |____ ____) | |____ ____) |
   |_|  \____/|______|______|_____/ \_____|_____/

               VALEXDP RECON TOOL
        """ + Style.RESET_ALL)

        print(Fore.CYAN + "=" * 60)
        print(Fore.GREEN + "       🚨 VALEXDP RECON TOOL - ANA MENÜ 🚨")
        print(Fore.CYAN + "=" * 60)

        print(Fore.LIGHTBLUE_EX + "\n📡 AĞ & IP TARAMALARI")
        print(Fore.WHITE + "[1]  " + Fore.YELLOW + "IP Port Taraması")
        print(Fore.WHITE + "[2]  " + Fore.YELLOW + "Subdomain Taraması")
        print(Fore.WHITE + "[3]  " + Fore.YELLOW + "Whois Sorgulama")
        print(Fore.WHITE + "[4]  " + Fore.YELLOW + "IP Geolocation (Konum Bilgisi)")
        print(Fore.WHITE + "[5]  " + Fore.YELLOW + "Kendi IP Adresimi Öğren")
        print(Fore.WHITE + "[6]  " + Fore.YELLOW + "Web Sitesi Kaynak Kodunu Kaydet")

        print(Fore.LIGHTMAGENTA_EX + "\n🔐 GÜVENLİK ANALİZLERİ")
        print(Fore.WHITE + "[7]  " + Fore.RED + "SSL Sertifikası Bilgisi")
        print(Fore.WHITE + "[8]  " + Fore.RED + "Ping Testi")
        print(Fore.WHITE + "[9]  " + Fore.RED + "Traceroute")
        print(Fore.WHITE + "[10] " + Fore.RED + "Ağ Açığı Taraması")
        print(Fore.WHITE + "[11] " + Fore.RED + "DNS Zone Transfer (AXFR)")
        print(Fore.WHITE + "[12] " + Fore.RED + "Site Güvenlik Seviyesi Analizi (HTTP/HTTPS)")
        print(Fore.WHITE + "[15] " + Fore.RED + "HTTP Güvenlik Başlıkları Taraması")

        print(Fore.LIGHTGREEN_EX + "\n📶 AĞ CİHAZLARI & ORTAM")
        print(Fore.WHITE + "[13] " + Fore.CYAN + "Bağlı Olduğun Wi-Fi Bilgileri")
        print(Fore.WHITE + "[14] " + Fore.CYAN + "Ağdaki Aktif Cihazları Tara")

        print(Fore.LIGHTYELLOW_EX + "\n🗂️ DİZİN & DOSYA TARAMALARI")
        print(Fore.WHITE + "[16] " + Fore.MAGENTA + "Dizin/Endpoint Keşfi (DirScan)")
        print(Fore.WHITE + "[17] " + Fore.MAGENTA + "Gelişmiş Endpoint/Dizin Keşfi")
        print(Fore.WHITE + "[18] " + Fore.MAGENTA + "Yayınlanan Açık Dosyaları Tara (.env, .git vs)")
        print(Fore.WHITE + "[19] " + Fore.MAGENTA + "Robots.txt Taraması")

        print(Fore.LIGHTCYAN_EX + "\n🔎 EKSTRA TARAMALAR")
        print(Fore.WHITE + "[20] " + Fore.LIGHTRED_EX + "Port Tabanlı Servis Tanıma (Tahminleme)")
        print(Fore.WHITE + "[21] " + Fore.LIGHTRED_EX + "IP Adresinden Detaylı Lokasyon (İl, İlçe, Koordinat)")

        print(Fore.LIGHTWHITE_EX + "\nℹ️ TOOL")
        print(Fore.WHITE + "[22] " + Fore.LIGHTBLUE_EX + "Tool Bilgisi")

        print(Fore.LIGHTBLACK_EX + "\n[0]  Çıkış\n")



        


        choice = input(Fore.CYAN + "Seçimini yap (0-22): " + Style.RESET_ALL)

        if choice == "1":
            loading_bar(text="Yükleniyor")
            target_ip = input(Fore.CYAN + "Hedef IP gir: " + Style.RESET_ALL)
            if not is_valid_ip(target_ip):
                ban_message()
            menu_display("IP Taraması", target_ip)
            port_scan(target_ip)

        elif choice == "2":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("Subdomain Taraması", target_domain)
            subdomain_scan(target_domain)

        elif choice == "3":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("Whois Sorgulama", target_domain)
            whois_lookup(target_domain)

        elif choice == "4":
            loading_bar(text="Yükleniyor")
            target_ip = input(Fore.CYAN + "Hedef IP gir (örn: 8.8.8.8): " + Style.RESET_ALL)
            if not is_valid_ip(target_ip):
                ban_message()
            menu_display("IP Geolocation", target_ip)
            ip_geolocation(target_ip)

        elif choice == "5":
            loading_bar(text="Yükleniyor")
            ip = get_my_ip()
            if ip:
                menu_display("Kendi IP Adresi", ip)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "6":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain veya URL gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("Web Sitesi Kaynak Kodu Kaydetme (Requests)", target_domain)
            save_website_source(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "7":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain veya URL gir (örn: google.com): " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("SSL Sertifikası Bilgisi", target_domain)
            ssl_certificate_info(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "8":
            loading_bar(text="Yükleniyor")
            target_ip = input(Fore.CYAN + "Hedef IP gir: " + Style.RESET_ALL)
            if not is_valid_ip(target_ip):
                ban_message()
            menu_display("Ping Testi", target_ip)
            ping_test(target_ip)

        elif choice == "9":
            loading_bar(text="Yükleniyor")
            target_ip = input(Fore.CYAN + "Hedef IP gir: " + Style.RESET_ALL)
            if not is_valid_ip(target_ip):
                ban_message()
            menu_display("Traceroute", target_ip)
            traceroute(target_ip)

        elif choice == "10":
            loading_bar(text="Yükleniyor")
            target_ip = input(Fore.CYAN + "Hedef IP gir: " + Style.RESET_ALL)
            if not is_valid_ip(target_ip):
                ban_message()
            menu_display("Ağ Açığı Taraması", target_ip)
            simple_network_vuln_scan(target_ip)

        elif choice == "11":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("DNS Zone Transfer", target_domain)
            dns_zone_transfer(target_domain)

        elif choice == "12":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain veya URL gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("Güvenlik Düzeyi Analizi", target_domain)
            detect_security_level(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "13":
            loading_bar(text="Yükleniyor")
            menu_display("Wi-Fi Ağ Bilgileri", "Lokal Ağ")
            get_wifi_info()
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "14":
            loading_bar(text="Yükleniyor")
            active_devices = scan_local_network()
            input("Tarama tamamlandı. Devam etmek için bir tuşa basın...")


        elif choice == "15":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("HTTP Güvenlik Başlıkları", target_domain)
            check_http_headers(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "16":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("Dizin Taraması (DirScan)", target_domain)
            dir_scan(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)



        elif choice == "17":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("Gelişmiş Dizin/Endpoint Taraması", target_domain)
            full_dir_scan(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "18":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain veya URL gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("Yayınlanan Açık Dosya Taraması", target_domain)
            exposed_files_scan(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)



        elif choice == "19":
            loading_bar(text="Yükleniyor")
            target_domain = input(Fore.CYAN + "Hedef Domain veya URL gir: " + Style.RESET_ALL)
            if "." not in target_domain or len(target_domain) < 4:
                ban_message()
            menu_display("robots.txt Taraması", target_domain)
            robots_txt_scan(target_domain)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)

        elif choice == "20":
            loading_bar(text="Yükleniyor")
            ip = input("Hedef IP veya domain: ")
            servis_tanima(ip)



        elif choice == "0":
            print(Fore.GREEN + "Programdan çıkılıyor. İyi günler!")
            break



        elif choice == "21":
            loading_bar(text="Yükleniyor")
            hedef_ip = input(Fore.CYAN + "🎯 IP Adresi Girin: " + Style.RESET_ALL)
            konum_detayli(hedef_ip)
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)


        elif choice == "22":
            print(Fore.CYAN + "\nVALEXDP RECON TOOL - Bilgiler\n" + "-"*30)
            print(Fore.GREEN + "Yapımcı  : Valex")
            print(Fore.GREEN + "Versiyon : 1.0")
            print(Fore.GREEN + "Tarih    : 2025")
            print(Fore.GREEN + "İletişim : vxtooldp@gmail.com")
            print(Fore.GREEN + "GitHub   : https://github.com/codedByValex")
            print(Fore.GREEN + "Açıklama : Çok amaçlı ağ ve güvenlik analiz aracı.")
            print(Fore.CYAN + "-"*30 + "\n")
            input(Fore.YELLOW + "Devam etmek için bir tuşa basın..." + Style.RESET_ALL)


        else:
            ban_message()


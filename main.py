from flask import Flask, render_template, redirect, request, jsonify, session
from pathlib import Path
import sqlite3
import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
import hmac
import base64
from cryptography.fernet import Fernet
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
import threading
import time
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger("HALNyFucker")

logging.getLogger("urllib3.connection").setLevel(logging.ERROR)

app = Flask(__name__)

SECRET_KEY_FILE = Path(".secret_key")
if os.environ.get("SECRET_KEY"):
    app.secret_key = os.environ["SECRET_KEY"]
elif SECRET_KEY_FILE.exists():
    app.secret_key = SECRET_KEY_FILE.read_bytes()
else:
    key = os.urandom(32)
    SECRET_KEY_FILE.write_bytes(key)
    app.secret_key = key

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

FERNET_KEY_FILE = Path(".fernet_key")
if FERNET_KEY_FILE.exists():
    fernet = Fernet(FERNET_KEY_FILE.read_bytes())
else:
    fernet_key = Fernet.generate_key()
    FERNET_KEY_FILE.write_bytes(fernet_key)
    fernet = Fernet(fernet_key)

def encrypt_value(plaintext):
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt_value(ciphertext):
    return fernet.decrypt(ciphertext.encode()).decode()

DB_PATH = "baza.db"
ph = PasswordHasher()

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

def create_session():
    session_req = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session_req.mount('http://', adapter)
    session_req.mount('https://', adapter)
    return session_req

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS router_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_url TEXT NOT NULL,
            router_username TEXT NOT NULL,
            router_password TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT NOT NULL,
            external_port INTEGER NOT NULL,
            internal_address TEXT NOT NULL,
            internal_port INTEGER NOT NULL,
            description TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    try:
        cursor.execute("ALTER TABLE ports ADD COLUMN internal_address TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # kolumna juz istnieje
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_add_ports', '0')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_restart_upnp', '0')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('logodev_api_key', '')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('api_key', '')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('notify_discord_enabled', '0')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('notify_discord_webhook', '')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('notify_telegram_enabled', '0')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('notify_telegram_bot_token', '')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('notify_telegram_chat_id', '')")
    conn.commit()
    conn.close()

def verify_router_credentials(router_url, router_username, router_password):
    try:
        session_req = requests.Session()
        
        auth_url = f"{router_url}/cgi-bin/check_auth.json"
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{router_url}/cgi-bin/login.asp"
        }
        data = {
            "username": router_username,
            "password": router_password,
            "Language_Flag": "0",
            "selectLanguage": "English"
        }
        cookies = {
            "loginTimes": "0"
        }
        
        response = session_req.post(auth_url, data=data, headers=headers, cookies=cookies, timeout=10, verify=False)
        response_json = response.json()
        
        ecnt_token = response_json.get("ecntToken", "")
        
        is_valid = ecnt_token and ecnt_token != "000000000000000000000000000000000" and not all(c == '0' for c in ecnt_token)
        
        if not is_valid:
            return False, "Nieprawidłowy login lub hasło dla routera"
        
        return True, response_json
    except requests.exceptions.RequestException as e:
        return False, f"Błąd połączenia z routerem: {str(e)}"
    except ValueError:
        return False, "Nieprawidłowa odpowiedź z routera (nie jest JSON)"
    except Exception as e:
        return False, f"Błąd: {str(e)}"

USER_AGENT = "HALNyFucker (https://github.com/ZorinOnTop/HALNyFucker)"

def get_router_config():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT router_url, router_username, router_password FROM router_config LIMIT 1')
        row = cursor.fetchone()
        conn.close()
        if row:
            try:
                password = decrypt_value(row[2])
            except Exception:
                password = row[2]
            return {"url": row[0], "username": row[1], "password": password}
    except Exception:
        pass
    return None

def get_setting_value(key):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0] == '1'
    except Exception:
        pass
    return False

def router_login(router_url, router_username, router_password):
    import hashlib
    
    eboo_value = hashlib.md5(os.urandom(16)).hexdigest()[:8]
    
    session_req = requests.Session()
    
    auth_url = f"{router_url}/cgi-bin/check_auth.json"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{router_url}/cgi-bin/login.asp",
        "User-Agent": USER_AGENT
    }
    data = {
        "username": router_username,
        "password": router_password,
        "Language_Flag": "0",
        "selectLanguage": "English"
    }
    cookies = {
        "loginTimes": "0",
        "EBOOVALUE": eboo_value
    }
    
    response = session_req.post(auth_url, data=data, headers=headers, cookies=cookies, timeout=10, verify=False)
    response_json = response.json()
    
    ecnt_token = response_json.get("ecntToken", "")
    
    if not ecnt_token or all(c == '0' for c in ecnt_token):
        return None, None
    
    return ecnt_token, eboo_value

def calculate_eboovalue(form_data_str):
    pairs = form_data_str.split('&')
    pname = []
    pvalue = []
    
    for pair in pairs:
        name, value = pair.split('=', 1)
        found = False
        for i in range(len(pname)):
            if pname[i] == name:
                pvalue[i] += "\n" + value
                found = True
                break
        if not found:
            pname.append(name)
            pvalue.append(value)
    
    post_str = ""
    for i in range(len(pname)):
        post_str += pname[i] + pvalue[i]
    
    import binascii
    crc = binascii.crc32(post_str.encode('utf-8')) & 0xFFFFFFFF
    return format(crc, 'x')

def restart_upnp(router_url, router_username, router_password):
    import subprocess
    import tempfile
    import hashlib
    import json
    
    try:
        logger.info("[UPnP] Restartuję UPnP na routerze...")
        
        eboo_value = hashlib.md5(os.urandom(16)).hexdigest()[:8]
        
        cookie_jar = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='halnyfucker_')
        cookie_jar_path = cookie_jar.name
        cookie_jar.close()
        
        with open(cookie_jar_path, 'w') as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write(f"192.168.55.1\tFALSE\t/\tFALSE\t0\tEBOOVALUE\t{eboo_value}\n")
            f.write(f"192.168.55.1\tFALSE\t/\tFALSE\t0\tloginTimes\t0\n")
        
        try:
            ua = USER_AGENT
            
            login_cmd = [
                "curl", f"{router_url}/cgi-bin/check_auth.json",
                "-H", "X-Requested-With: XMLHttpRequest",
                "-H", f"Referer: {router_url}/cgi-bin/login.asp",
                "-H", f"User-Agent: {ua}",
                "-b", cookie_jar_path,
                "-c", cookie_jar_path,
                "--data-raw", f"username={router_username}&password={router_password}&Language_Flag=0&selectLanguage=English",
                "--insecure", "-s"
            ]
            
            result = subprocess.run(login_cmd, capture_output=True, text=True, timeout=15)
            
            try:
                login_response = json.loads(result.stdout)
                ecnt_token = login_response.get("ecntToken", "")
            except (json.JSONDecodeError, ValueError):
                logger.error("[UPnP] Błąd logowania do routera.")
                return False
            
            if not ecnt_token or all(c == '0' for c in ecnt_token):
                logger.error("[UPnP] Nieprawidłowe dane logowania routera.")
                return False
            
            logger.info(f"[UPnP] Zalogowano do routera.")
            
            with open(cookie_jar_path, 'a') as f:
                f.write(f"192.168.55.1\tFALSE\t/\tFALSE\t0\tecntToken\t{ecnt_token}\n")
            
            content_cmd = [
                "curl", f"{router_url}/cgi-bin/content.asp",
                "-H", f"Referer: {router_url}/cgi-bin/login.asp",
                "-H", f"User-Agent: {ua}",
                "-b", cookie_jar_path,
                "-c", cookie_jar_path,
                "--insecure", "-s"
            ]
            result = subprocess.run(content_cmd, capture_output=True, text=True, timeout=15)
            
            upnp_get_cmd = [
                "curl", f"{router_url}/cgi-bin/app-upnp.asp",
                "-H", f"Referer: {router_url}/cgi-bin/content.asp",
                "-H", f"User-Agent: {ua}",
                "-b", cookie_jar_path,
                "-c", cookie_jar_path,
                "--insecure", "-s"
            ]
            result = subprocess.run(upnp_get_cmd, capture_output=True, text=True, timeout=15)
            
            upnp_url = f"{router_url}/cgi-bin/app-upnp.asp"
            disable_data = "Upnp_Flag=1&AutoConfig_Flag=0&Enable_Flag=No&Type_Flag=IGD"
            disable_eboo = calculate_eboovalue(disable_data)
            
            disable_cmd = [
                "curl", upnp_url,
                "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "-H", "Accept-Language: pl;q=0.5",
                "-H", "Cache-Control: max-age=0",
                "-H", "Connection: keep-alive",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-b", f"EBOOVALUE={disable_eboo}; ecntToken={ecnt_token}",
                "-c", cookie_jar_path,
                "-H", f"Origin: {router_url}",
                "-H", f"Referer: {router_url}/cgi-bin/app-upnp.asp",
                "-H", "Sec-GPC: 1",
                "-H", "Upgrade-Insecure-Requests: 1",
                "-H", f"User-Agent: {ua}",
                "--data-raw", disable_data,
                "--insecure", "-s", "-w", "\n%{http_code}"
            ]
            
            logger.info("[UPnP] Wyłączam UPnP...")
            result = subprocess.run(disable_cmd, capture_output=True, text=True, timeout=15)
            
            time.sleep(3)
            
            enable_data = "Enable=on&mode=on&Upnp_Flag=1&AutoConfig_Flag=1&Enable_Flag=Yes&Type_Flag=IGD"
            enable_eboo = calculate_eboovalue(enable_data)
            
            enable_cmd = [
                "curl", upnp_url,
                "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "-H", "Accept-Language: pl;q=0.5",
                "-H", "Cache-Control: max-age=0",
                "-H", "Connection: keep-alive",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-b", f"EBOOVALUE={enable_eboo}; ecntToken={ecnt_token}",
                "-c", cookie_jar_path,
                "-H", f"Origin: {router_url}",
                "-H", f"Referer: {router_url}/cgi-bin/app-upnp.asp",
                "-H", "Sec-GPC: 1",
                "-H", "Upgrade-Insecure-Requests: 1",
                "-H", f"User-Agent: {ua}",
                "--data-raw", enable_data,
                "--insecure", "-s", "-w", "\n%{http_code}"
            ]
            
            logger.info("[UPnP] Włączam UPnP...")
            result = subprocess.run(enable_cmd, capture_output=True, text=True, timeout=15)
            
            success = "Bad Request" not in result.stdout and "302 Moved" not in result.stdout
            if not success:
                logger.error("[UPnP] Router odrzucił request.")
                return False
            
            logger.info("[UPnP] Czekam na uruchomienie UPnP...")
            time.sleep(15)
            
            if check_upnp_health(router_url):
                logger.info("[UPnP] Zrestartowany pomyślnie!")
                from urllib.parse import urlparse
                parsed = urlparse(router_url)
                rip = parsed.hostname
                mappings = get_upnp_port_mappings(rip)
                import_upnp_to_db(mappings)
                if get_setting_value('auto_add_ports'):
                    push_db_to_upnp(rip, mappings)
                return True
            else:
                time.sleep(15)
                if check_upnp_health(router_url):
                    logger.info("[UPnP] Zrestartowany pomyślnie!")
                    from urllib.parse import urlparse
                    parsed = urlparse(router_url)
                    rip = parsed.hostname
                    mappings = get_upnp_port_mappings(rip)
                    import_upnp_to_db(mappings)
                    if get_setting_value('auto_add_ports'):
                        push_db_to_upnp(rip, mappings)
                    return True
                else:
                    logger.error("[UPnP] Nie odpowiada po restarcie.")
                    return False
            
        finally:
            try:
                os.unlink(cookie_jar_path)
            except OSError:
                pass
                
    except Exception as e:
        logger.error(f"[UPnP] Wyjątek: {str(e)}")
        return False

def check_upnp_health(router_url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(router_url)
        router_ip = parsed.hostname
        
        check_url = f"http://{router_ip}:5555"
        response = requests.get(check_url, timeout=5, headers={"User-Agent": USER_AGENT})
        return response.status_code == 200
    except Exception:
        return False

def upnp_monitor_loop():
    while True:
        time.sleep(60)
        
        try:
            if not get_setting_value('auto_restart_upnp'):
                continue
            
            config = get_router_config()
            if not config:
                continue
            
            if not check_upnp_health(config["url"]):
                logger.warning("[UPnP] Nie odpowiada - restartuję...")
                send_notification("⚠️ UPnP nie odpowiada! Próbuję zrestartować...")
                success = restart_upnp(config["url"], config["username"], config["password"])
                if not success:
                    logger.error("[UPnP] Nie udało się zrestartować.")
                    send_notification("❌ Nie udało się zrestartować UPnP!")
                else:
                    send_notification("✅ UPnP zrestartowany pomyślnie.")
        except Exception as e:
            logger.error(f"[UPnP] Błąd monitora: {str(e)}")

def start_upnp_monitor():
    thread = threading.Thread(target=upnp_monitor_loop, daemon=True)
    thread.start()
    logger.info("UPnP monitor uruchomiony (sprawdza co 60s)")

def get_upnp_port_mappings(router_ip):
    import re
    
    url = f"http://{router_ip}:5555/upnp/control/WANIPConn1"
    headers = {
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"',
        "Content-Type": "text/xml",
        "User-Agent": USER_AGENT
    }
    
    mappings = []
    index = 0
    
    while True:
        body = f'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewPortMappingIndex>{index}</NewPortMappingIndex>
</u:GetGenericPortMappingEntry>
</s:Body>
</s:Envelope>'''
        
        try:
            response = requests.post(url, data=body, headers=headers, timeout=5)
            
            if response.status_code != 200:
                logger.info(f"[UPnP Fetch] Koniec - status {response.status_code}")
                break
            
            text = response.text
            
            if "errorCode" in text:
                logger.info(f"[UPnP Fetch] Koniec po {index} portach (errorCode)")
                break
            
            if "GetGenericPortMappingEntryResponse" not in text:
                logger.info(f"[UPnP Fetch] Koniec - brak odpowiedzi w XML")
                break
            
            def extract(tag):
                m = re.search(f'<{tag}>(.*?)</{tag}>', text)
                return m.group(1) if m else ""
            
            mapping = {
                "external_port": int(extract("NewExternalPort") or 0),
                "internal_port": int(extract("NewInternalPort") or 0),
                "internal_address": extract("NewInternalClient"),
                "protocol": extract("NewProtocol"),
                "description": extract("NewPortMappingDescription"),
                "enabled": extract("NewEnabled") == "1"
            }
            
            logger.info(f"[UPnP Fetch] #{index}: {mapping['protocol']} :{mapping['external_port']} -> {mapping['internal_address']}:{mapping['internal_port']} ({mapping['description']})")
            
            if mapping["external_port"] > 0:
                mappings.append(mapping)
            
            index += 1
        except requests.exceptions.ConnectionError:
            break
        except Exception as e:
            if "IncompleteRead" in str(e) or "HeaderParsing" in str(e) or "Connection broken" in str(e):
                logger.info(f"[UPnP Fetch] Koniec po {index} portach (router zamknął połączenie)")
            else:
                logger.warning(f"[UPnP Fetch] Błąd index {index}: {e}")
            break
    
    logger.info(f"[UPnP Fetch] Pobrano {len(mappings)} port mappings")
    return mappings

def import_upnp_to_db(current_mappings):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT protocol, external_port, internal_address, internal_port FROM ports')
        db_ports = [dict(row) for row in cursor.fetchall()]
        
        for mapping in current_mappings:
            if not mapping["enabled"]:
                continue
            
            found = False
            for port in db_ports:
                if port["protocol"] == "TCP/UDP":
                    match = (mapping["protocol"].upper() in ("TCP", "UDP") and
                             mapping["external_port"] == port["external_port"] and
                             mapping["internal_port"] == port["internal_port"] and
                             mapping["internal_address"] == port["internal_address"])
                else:
                    match = (mapping["protocol"].upper() == port["protocol"].upper() and
                             mapping["external_port"] == port["external_port"] and
                             mapping["internal_port"] == port["internal_port"] and
                             mapping["internal_address"] == port["internal_address"])
                if match:
                    found = True
                    break
            
            if not found:
                description = mapping["description"] or f"UPnP {mapping['protocol']} {mapping['external_port']}"
                cursor.execute('''
                    INSERT INTO ports (protocol, external_port, internal_address, internal_port, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (mapping["protocol"], mapping["external_port"], mapping["internal_address"], mapping["internal_port"], description))
                logger.info(f"[UPnP Sync] Zaimportowano: {mapping['protocol']} {mapping['external_port']} -> {mapping['internal_address']}:{mapping['internal_port']} ({description})")
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"[UPnP Sync] Błąd importu: {str(e)}")

def push_db_to_upnp(router_ip, current_mappings):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT protocol, external_port, internal_address, internal_port, description FROM ports')
        desired_ports = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        if not desired_ports:
            return
        
        for port in desired_ports:
            if port["protocol"] == "TCP/UDP":
                match_tcp = any(m["protocol"].upper() == "TCP" and m["external_port"] == port["external_port"] and m["internal_port"] == port["internal_port"] and m["internal_address"] == port["internal_address"] for m in current_mappings)
                match_udp = any(m["protocol"].upper() == "UDP" and m["external_port"] == port["external_port"] and m["internal_port"] == port["internal_port"] and m["internal_address"] == port["internal_address"] for m in current_mappings)
                found = match_tcp and match_udp
            else:
                found = any(
                    m["protocol"].upper() == port["protocol"].upper() and
                    m["external_port"] == port["external_port"] and
                    m["internal_port"] == port["internal_port"] and
                    m["internal_address"] == port["internal_address"]
                    for m in current_mappings
                )
            
            if not found:
                protocols = ["TCP", "UDP"] if port["protocol"] == "TCP/UDP" else [port["protocol"]]
                
                for proto in protocols:
                    success = add_upnp_port_mapping(
                        router_ip, proto,
                        port["external_port"], port["internal_address"],
                        port["internal_port"], port["description"]
                    )
                    if success:
                        logger.info(f"[UPnP Sync] Dodano do UPnP: {proto} {port['external_port']} -> {port['internal_address']}:{port['internal_port']}")
                    else:
                        logger.error(f"[UPnP Sync] Nie udało się dodać: {proto} {port['external_port']} - sprawdzam czy UPnP działa...")
                        config = get_router_config()
                        if config and not check_upnp_health(config["url"]):
                            logger.warning("[UPnP Sync] UPnP nie odpowiada! Uruchamiam restart...")
                            if get_setting_value('auto_restart_upnp'):
                                restart_upnp(config["url"], config["username"], config["password"])
                        return  # nie probuj dodawac wiecej portów
    except Exception as e:
        logger.error(f"[UPnP Sync] Błąd push: {str(e)}")

def add_upnp_port_mapping(router_ip, protocol, external_port, internal_address, internal_port, description):
    url = f"http://{router_ip}:5555/upnp/control/WANIPConn1"
    headers = {
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
        "Content-Type": "text/xml",
        "User-Agent": USER_AGENT
    }
    
    body = f'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>{protocol}</NewProtocol>
<NewInternalPort>{internal_port}</NewInternalPort>
<NewInternalClient>{internal_address}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{description}</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>'''
    
    try:
        response = requests.post(url, data=body, headers=headers, timeout=5)
        return response.status_code == 200 and "errorCode" not in response.text
    except Exception:
        return False

def delete_upnp_port_mapping(router_ip, protocol, external_port):
    url = f"http://{router_ip}:5555/upnp/control/WANIPConn1"
    headers = {
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"',
        "Content-Type": "text/xml",
        "User-Agent": USER_AGENT
    }
    
    body = f'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>{protocol}</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>'''
    
    try:
        response = requests.post(url, data=body, headers=headers, timeout=5)
        return response.status_code == 200 and "errorCode" not in response.text
    except Exception:
        return False

def upnp_sync_loop():
    time.sleep(10)
    try:
        logger.info("[UPnP Sync] Pierwsza synchronizacja portów...")
        config = get_router_config()
        if config:
            from urllib.parse import urlparse
            parsed = urlparse(config["url"])
            router_ip = parsed.hostname
            current_mappings = get_upnp_port_mappings(router_ip)
            import_upnp_to_db(current_mappings)
            if get_setting_value('auto_add_ports'):
                push_db_to_upnp(router_ip, current_mappings)
    except Exception as e:
        logger.error(f"[UPnP Sync] Błąd pierwszej synchronizacji: {str(e)}")
    
    while True:
        time.sleep(60)
        
        try:
            config = get_router_config()
            if not config:
                continue
            
            from urllib.parse import urlparse
            parsed = urlparse(config["url"])
            router_ip = parsed.hostname
            
            current_mappings = get_upnp_port_mappings(router_ip)
            
            import_upnp_to_db(current_mappings)
            
            if get_setting_value('auto_add_ports'):
                push_db_to_upnp(router_ip, current_mappings)
        except Exception as e:
            logger.error(f"[UPnP Sync] Błąd: {str(e)}")

def start_upnp_sync():
    thread = threading.Thread(target=upnp_sync_loop, daemon=True)
    thread.start()
    logger.info("UPnP sync uruchomiony (sprawdza co 60s)")

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "error": "Nie zalogowano"}), 401
            return redirect("/login", code=302)
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key', '')
        if not api_key:
            return jsonify({"success": False, "error": "Brak klucza API (header X-API-Key)"}), 401
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'api_key'")
        row = cursor.fetchone()
        conn.close()
        
        if not row or not row[0] or not hmac.compare_digest(row[0], api_key):
            return jsonify({"success": False, "error": "Nieprawidłowy klucz API"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

APP_VERSION = "1.0.0"
APP_START_TIME = time.time()

@app.route("/")
def home():
    if Path(".dont_remove_installed").exists():
        if 'user_id' in session:
            return redirect("/dashboard", code=302)
        return redirect("/login", code=302)
    else:
        return redirect("/install", code=302)
    
@app.route("/login", methods=["GET"])
def login():
    if not Path(".dont_remove_installed").exists():
        return redirect("/install", code=302)
    if 'user_id' in session:
        return redirect("/dashboard", code=302)
    return render_template("login.html")

@app.route("/install", methods=["GET"])
def install():
    if Path(".dont_remove_installed").exists():
        return render_template("install_error.html")
    else:
        return render_template("install.html")

@app.route("/dashboard")
@login_required
def dashboard():
    settings = get_settings()
    logodev_api_key = getattr(settings, 'logodev_api_key', '')
    return render_template("dashboard.html", username=session.get('username', 'użytkownik'), logodev_api_key=logodev_api_key)

@app.route("/api-docs")
@login_required
def api_docs():
    return render_template("api_docs.html", username=session.get('username', 'użytkownik'))

@app.route("/notifications")
@login_required
def notifications_page():
    settings = get_settings()
    return render_template("notifications.html", username=session.get('username', 'użytkownik'), settings=settings)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login", code=302)

@app.route("/api/install", methods=["POST"])
def api_install():
    if Path(".dont_remove_installed").exists():
        return jsonify({"success": False, "error": "System już zainstalowany"}), 400
    
    try:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        router_url = request.form.get("router_url", "").strip()
        router_username = request.form.get("router_username", "").strip()
        router_password = request.form.get("router_password", "").strip()
        
        if not all([username, password, router_url, router_username, router_password]):
            return jsonify({"success": False, "error": "Wszystkie pola są wymagane"}), 400
        
        if not router_url.startswith("http://192.168.") and not router_url.startswith("http://10.") and not router_url.startswith("http://172."):
            return jsonify({"success": False, "error": "URL routera musi być adresem lokalnym (192.168.x.x, 10.x.x.x, 172.x.x.x)"}), 400
        
        password_hash = ph.hash(password)
        
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        ''', (username, password_hash))
        
        cursor.execute('SELECT id FROM router_config LIMIT 1')
        encrypted_router_password = encrypt_value(router_password)
        if cursor.fetchone():
            cursor.execute('''
                UPDATE router_config 
                SET router_url = ?, router_username = ?, router_password = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1
            ''', (router_url, router_username, encrypted_router_password))
        else:
            cursor.execute('''
                INSERT INTO router_config (router_url, router_username, router_password)
                VALUES (?, ?, ?)
            ''', (router_url, router_username, encrypted_router_password))
        
        conn.commit()
        conn.close()
        
        Path(".dont_remove_installed").touch()
        
        return jsonify({"success": True, "message": "Instalacja udana"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Ta nazwa użytkownika już istnieje"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Błąd: {str(e)}"}), 500

@app.route("/api/login", methods=["POST"])
@limiter.limit("3 per minute")
def api_login():
    if not Path(".dont_remove_installed").exists():
        return jsonify({"success": False, "error": "System nie zainstalowany"}), 400
    
    try:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        remember = request.form.get("remember", "") == "on"
        
        if not all([username, password]):
            return jsonify({"success": False, "error": "Nazwa użytkownika i hasło są wymagane"}), 400
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({"success": False, "error": "Nieprawidłowa nazwa użytkownika lub hasło"}), 401
        
        user_id, password_hash = user
        
        try:
            ph.verify(password_hash, password)
        except VerifyMismatchError:
            conn.close()
            return jsonify({"success": False, "error": "Nieprawidłowa nazwa użytkownika lub hasło"}), 401
        
        cursor.execute('SELECT router_url, router_username, router_password FROM router_config LIMIT 1')
        router_config = cursor.fetchone()
        conn.close()
        
        if not router_config:
            return jsonify({"success": False, "error": "Konfiguracja routera nie znaleziona"}), 400
        
        session['user_id'] = user_id
        session['username'] = username
        
        if remember:
            session.permanent = True
        
        return jsonify({"success": True, "message": "Zalogowano pomyślnie"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Błąd: {str(e)}"}), 500

def get_settings():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM settings')
    rows = cursor.fetchall()
    conn.close()
    
    class Settings:
        pass
    
    s = Settings()
    bool_keys = ('auto_add_ports', 'auto_restart_upnp', 'notify_discord_enabled', 'notify_telegram_enabled')
    for key, value in rows:
        if key in bool_keys:
            setattr(s, key, value == '1')
        else:
            setattr(s, key, value)
    return s

@app.route("/settings")
@login_required
def settings_page():
    settings = get_settings()
    return render_template("settings.html", username=session.get('username', 'użytkownik'), settings=settings)

@app.route("/api/settings", methods=["POST"])
@login_required
def api_update_setting():
    try:
        key = request.form.get("key", "").strip()
        value = request.form.get("value", "").strip()

        allowed_keys = ("auto_add_ports", "auto_restart_upnp", "logodev_api_key", "api_key",
                        "notify_discord_enabled", "notify_discord_webhook",
                        "notify_telegram_enabled", "notify_telegram_bot_token", "notify_telegram_chat_id")
        if key not in allowed_keys:
            return jsonify({"success": False, "error": "Nieprawidłowe ustawienie"}), 400

        bool_keys = ("auto_add_ports", "auto_restart_upnp", "notify_discord_enabled", "notify_telegram_enabled")
        if key in bool_keys and value not in ("0", "1"):
            return jsonify({"success": False, "error": "Nieprawidłowa wartość"}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Zapisano"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Błąd: {str(e)}"}), 500

@app.route("/api/ports", methods=["GET"])
@login_required
def api_get_ports():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT id, protocol, external_port, internal_address, internal_port, description FROM ports ORDER BY id')
        ports = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({"success": True, "ports": ports}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Błąd: {str(e)}"}), 500

@app.route("/api/ports", methods=["POST"])
@login_required
def api_add_port():
    try:
        protocol = request.form.get("protocol", "").strip()
        external_port = request.form.get("external_port", "").strip()
        internal_address = request.form.get("internal_address", "").strip()
        internal_port = request.form.get("internal_port", "").strip()
        description = request.form.get("description", "").strip()

        if not all([protocol, external_port, internal_address, internal_port, description]):
            return jsonify({"success": False, "error": "Wszystkie pola są wymagane"}), 400

        if protocol not in ("TCP", "UDP", "TCP/UDP"):
            return jsonify({"success": False, "error": "Nieprawidłowy protokół"}), 400

        try:
            external_port = int(external_port)
            internal_port = int(internal_port)
        except ValueError:
            return jsonify({"success": False, "error": "Porty muszą być liczbami"}), 400

        if not (1 <= external_port <= 65535) or not (1 <= internal_port <= 65535):
            return jsonify({"success": False, "error": "Port musi być w zakresie 1-65535"}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ports (protocol, external_port, internal_address, internal_port, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (protocol, external_port, internal_address, internal_port, description))
        conn.commit()
        conn.close()

        config = get_router_config()
        if config:
            from urllib.parse import urlparse
            parsed = urlparse(config["url"])
            router_ip = parsed.hostname
            protocols = ["TCP", "UDP"] if protocol == "TCP/UDP" else [protocol]
            for proto in protocols:
                add_upnp_port_mapping(router_ip, proto, external_port, internal_address, internal_port, description)

        return jsonify({"success": True, "message": "Port dodany"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Błąd: {str(e)}"}), 500

@app.route("/api/ports/<int:port_id>", methods=["DELETE"])
@login_required
def api_delete_port(port_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT protocol, external_port, internal_address, internal_port FROM ports WHERE id = ?', (port_id,))
        port = cursor.fetchone()
        
        if not port:
            conn.close()
            return jsonify({"success": False, "error": "Port nie znaleziony"}), 404
        
        port = dict(port)
        cursor.execute('DELETE FROM ports WHERE id = ?', (port_id,))
        conn.commit()
        conn.close()
        
        config = get_router_config()
        if config:
            from urllib.parse import urlparse
            parsed = urlparse(config["url"])
            router_ip = parsed.hostname
            protocols = ["TCP", "UDP"] if port["protocol"] == "TCP/UDP" else [port["protocol"]]
            for proto in protocols:
                delete_upnp_port_mapping(router_ip, proto, port["external_port"])
        
        return jsonify({"success": True, "message": "Port usunięty"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Błąd: {str(e)}"}), 500

def send_notification(message):
    send_discord_notification(message)
    send_telegram_notification(message)

def send_discord_notification(message):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'notify_discord_enabled'")
        enabled = cursor.fetchone()
        if not enabled or enabled[0] != '1':
            conn.close()
            return False
        
        cursor.execute("SELECT value FROM settings WHERE key = 'notify_discord_webhook'")
        webhook_row = cursor.fetchone()
        conn.close()
        
        if not webhook_row or not webhook_row[0]:
            return False
        
        webhook_url = webhook_row[0]
        payload = {
            "content": f"@everyone\n🔔 **HALNyFucker** - {message}",
            "username": "HALNyFucker"
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10, headers={"User-Agent": USER_AGENT})
        return response.status_code in (200, 204)
    except Exception as e:
        logger.error(f"[Notify] Discord błąd: {e}")
        return False

def send_telegram_notification(message):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'notify_telegram_enabled'")
        enabled = cursor.fetchone()
        if not enabled or enabled[0] != '1':
            conn.close()
            return False
        
        cursor.execute("SELECT value FROM settings WHERE key = 'notify_telegram_bot_token'")
        token_row = cursor.fetchone()
        cursor.execute("SELECT value FROM settings WHERE key = 'notify_telegram_chat_id'")
        chat_id_row = cursor.fetchone()
        conn.close()
        
        if not token_row or not token_row[0] or not chat_id_row or not chat_id_row[0]:
            return False
        
        bot_token = token_row[0]
        chat_id = chat_id_row[0]
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": f"🔔 *HALNyFucker*\n\n{message}",
            "parse_mode": "Markdown"
        }
        
        response = requests.post(url, json=payload, timeout=10, headers={"User-Agent": USER_AGENT})
        return response.status_code == 200
    except Exception as e:
        logger.error(f"[Notify] Telegram błąd: {e}")
        return False

@app.route("/api/notifications/test", methods=["POST"])
@login_required
def api_test_notification():
    data = request.get_json(silent=True)
    provider = data.get("provider", "") if data else ""
    
    message = "To jest testowe powiadomienie z HALNyFuckera! 🎉"
    
    if provider == "discord":
        success = send_discord_notification(message)
        if not success:
            return jsonify({"success": False, "error": "Nie udało się wysłać. Sprawdź czy webhook jest poprawny i Discord jest włączony."}), 400
    elif provider == "telegram":
        success = send_telegram_notification(message)
        if not success:
            return jsonify({"success": False, "error": "Nie udało się wysłać. Sprawdź token bota i chat ID."}), 400
    else:
        return jsonify({"success": False, "error": "Nieprawidłowy provider (discord/telegram)"}), 400
    
    return jsonify({"success": True}), 200

@app.route("/api/generate_api_key", methods=["POST"])
@login_required
def api_generate_key():
    import secrets
    new_key = f"hf_{secrets.token_hex(24)}"
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('api_key', ?)", (new_key,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "api_key": new_key}), 200


@app.route("/api/v1/status", methods=["GET"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_status():
    config = get_router_config()
    router_ip = None
    upnp_online = False
    
    if config:
        from urllib.parse import urlparse
        parsed = urlparse(config["url"])
        router_ip = parsed.hostname
        upnp_online = check_upnp_health(config["url"])
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ports")
    port_count = cursor.fetchone()[0]
    conn.close()
    
    return jsonify({
        "success": True,
        "version": APP_VERSION,
        "uptime_seconds": int(time.time() - APP_START_TIME),
        "upnp_online": upnp_online,
        "port_count": port_count,
        "router_ip": router_ip
    }), 200

@app.route("/api/v1/ports", methods=["GET"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_get_ports():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, protocol, external_port, internal_address, internal_port, description FROM ports ORDER BY id')
    ports = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "ports": ports}), 200

@app.route("/api/v1/ports", methods=["POST"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_add_port():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Body musi być JSON"}), 400
    
    protocol = data.get("protocol", "").strip()
    external_port = data.get("external_port")
    internal_address = data.get("internal_address", "").strip()
    internal_port = data.get("internal_port")
    description = data.get("description", "").strip()
    
    if not all([protocol, external_port, internal_address, internal_port, description]):
        return jsonify({"success": False, "error": "Wymagane pola: protocol, external_port, internal_address, internal_port, description"}), 400
    
    if protocol not in ("TCP", "UDP", "TCP/UDP"):
        return jsonify({"success": False, "error": "protocol musi być TCP, UDP lub TCP/UDP"}), 400
    
    try:
        external_port = int(external_port)
        internal_port = int(internal_port)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Porty muszą być liczbami"}), 400
    
    if not (1 <= external_port <= 65535) or not (1 <= internal_port <= 65535):
        return jsonify({"success": False, "error": "Port musi być w zakresie 1-65535"}), 400
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ports (protocol, external_port, internal_address, internal_port, description)
        VALUES (?, ?, ?, ?, ?)
    ''', (protocol, external_port, internal_address, internal_port, description))
    port_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    config = get_router_config()
    if config:
        from urllib.parse import urlparse
        parsed = urlparse(config["url"])
        router_ip = parsed.hostname
        protocols = ["TCP", "UDP"] if protocol == "TCP/UDP" else [protocol]
        for proto in protocols:
            add_upnp_port_mapping(router_ip, proto, external_port, internal_address, internal_port, description)
    
    return jsonify({"success": True, "id": port_id, "message": "Port dodany"}), 201

@app.route("/api/v1/ports/<int:port_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_delete_port(port_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT protocol, external_port, internal_address, internal_port FROM ports WHERE id = ?', (port_id,))
    port = cursor.fetchone()
    
    if not port:
        conn.close()
        return jsonify({"success": False, "error": "Port nie znaleziony"}), 404
    
    port = dict(port)
    cursor.execute('DELETE FROM ports WHERE id = ?', (port_id,))
    conn.commit()
    conn.close()
    
    config = get_router_config()
    if config:
        from urllib.parse import urlparse
        parsed = urlparse(config["url"])
        router_ip = parsed.hostname
        protocols = ["TCP", "UDP"] if port["protocol"] == "TCP/UDP" else [port["protocol"]]
        for proto in protocols:
            delete_upnp_port_mapping(router_ip, proto, port["external_port"])
    
    return jsonify({"success": True, "message": "Port usunięty"}), 200

@app.route("/api/v1/upnp/status", methods=["GET"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_upnp_status():
    config = get_router_config()
    if not config:
        return jsonify({"success": True, "online": False, "error": "Brak konfiguracji routera"}), 200
    
    online = check_upnp_health(config["url"])
    return jsonify({"success": True, "online": online}), 200

@app.route("/api/v1/upnp/mappings", methods=["GET"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_upnp_mappings():
    config = get_router_config()
    if not config:
        return jsonify({"success": False, "error": "Brak konfiguracji routera"}), 400
    
    from urllib.parse import urlparse
    parsed = urlparse(config["url"])
    router_ip = parsed.hostname
    
    mappings = get_upnp_port_mappings(router_ip)
    return jsonify({"success": True, "mappings": mappings}), 200

@app.route("/api/v1/upnp/restart", methods=["POST"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_upnp_restart():
    config = get_router_config()
    if not config:
        return jsonify({"success": False, "error": "Brak konfiguracji routera"}), 400
    
    success = restart_upnp(config["url"], config["username"], config["password"])
    return jsonify({"success": success, "message": "UPnP zrestartowany" if success else "Nie udało się zrestartować UPnP"}), 200 if success else 500

@app.route("/api/v1/settings", methods=["GET"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_get_settings():
    settings = get_settings()
    return jsonify({
        "success": True,
        "settings": {
            "auto_add_ports": getattr(settings, 'auto_add_ports', False),
            "auto_restart_upnp": getattr(settings, 'auto_restart_upnp', False),
            "logodev_api_key": getattr(settings, 'logodev_api_key', '') or None
        }
    }), 200

@app.route("/api/v1/settings", methods=["PUT"])
@limiter.limit("30 per minute")
@api_key_required
def api_v1_update_settings():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Body musi być JSON"}), 400
    
    key = data.get("key", "").strip()
    value = data.get("value", "")
    
    allowed_keys = ("auto_add_ports", "auto_restart_upnp", "logodev_api_key")
    if key not in allowed_keys:
        return jsonify({"success": False, "error": f"Nieprawidłowy klucz. Dozwolone: {', '.join(allowed_keys)}"}), 400
    
    bool_keys = ("auto_add_ports", "auto_restart_upnp")
    if key in bool_keys:
        value = "1" if value in (True, "1", 1) else "0"
    else:
        value = str(value)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Zapisano"}), 200

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"success": False, "error": "Zbyt wiele prób logowania. Spróbuj ponownie za minutę."}), 429

if __name__ == "__main__":
    init_db()
    start_upnp_monitor()
    start_upnp_sync()
    app.run(host='0.0.0.0', port=42569)

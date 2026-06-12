#!/usr/bin/env python3
# RKP_Parser_Full.py — окончательная версия с urlsource.txt, LTE/WIFI сортировкой, полной проверкой

import asyncio
import aiohttp
import aiofiles
import re
import os
import time
import json
import subprocess
import tempfile
import requests
import urllib.parse
import sys
import socket
import random
import base64
import yaml
import threading
import shutil
import zipfile
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

# ========= Файлы и папки =========
SOURCES_FILE = "urlsource.txt"
MYURL_FILE = "myurl.txt"
OUTPUT_FILE = "url.txt"
CLEAN_FILE = "url_clean.txt"
CLEAN_NAMES_FILE = "url_clean_names.txt"
TCP_FILE = "url_tcp.txt"
WORK_FILE = "url_work.txt"
NAMED_FILE = "url_named.txt"
ENCODED_FILE = "url_encoded.txt"
FORCED_FILE = "forced.txt"
SOURCES_LOG_FILE = "sources_log.txt"
BLACKLIST_FILE = "blacklist_sources.txt"
SOURCE_PATTERNS_FILE = "source_patterns.txt"
WHITELIST_FILE = "lists/whitelist.txt"
CIDR_WHITELIST_FILE = "lists/cidrwhitelist.txt"

OUTPUT_DIR = "sub"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs("lists", exist_ok=True)

# ========= Настройки =========
THREADS_DOWNLOAD = 30
TCP_CHECK_THREADS = 50
XRAY_CHECK_THREADS = 30
TCP_TIMEOUT = 10
XRAY_TIMEOUT = 12
TEST_URLS = ["https://www.gstatic.com/generate_204"]
LOCAL_PORT_START = 10000
CORE_STARTUP_TIMEOUT = 1.0
CORE_KILL_DELAY = 0.2
MAX_WORKERS = XRAY_CHECK_THREADS

# ========= Ядра =========
CORES_DIR = Path("./cores")
CORES_DIR.mkdir(exist_ok=True)
XRAY_PATH = CORES_DIR / "xray"
HYSTERIA2_PATH = CORES_DIR / "hysteria2-linux-amd64"

def download_core(url, dest):
    if dest.exists():
        return True
    print(f"Скачивание {dest.name}...")
    try:
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        dest.chmod(0o755)
        return True
    except Exception as e:
        print(f"Ошибка: {e}")
        return False

def setup_cores():
    if not XRAY_PATH.exists():
        zip_url = "https://github.com/XTLS/Xray-core/releases/download/v25.3.6/Xray-linux-64.zip"
        zip_path = CORES_DIR / "xray.zip"
        if download_core(zip_url, zip_path):
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(CORES_DIR)
            os.remove(zip_path)
            extracted = CORES_DIR / "xray"
            if extracted.exists():
                extracted.rename(XRAY_PATH)
    if not HYSTERIA2_PATH.exists():
        h2_url = "https://github.com/apernet/hysteria/releases/download/v2.6.1/hysteria2-linux-amd64"
        download_core(h2_url, HYSTERIA2_PATH)
    return XRAY_PATH.exists() and HYSTERIA2_PATH.exists()

setup_cores()

# ========= Регулярки =========
VLESS_REGEX = re.compile(r"vless://[^\s]+", re.IGNORECASE)
TROJAN_REGEX = re.compile(r"trojan://[^\s]+", re.IGNORECASE)
VMESS_REGEX = re.compile(r"vmess://[^\s]+", re.IGNORECASE)
HY2_REGEX = re.compile(r"(?:hysteria2|hy2)://[^\s]+", re.IGNORECASE)
UUID_REGEX = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
BASE64_REGEX = re.compile(r'^[A-Za-z0-9+/]+=*$')

# ========= Вспомогательные функции =========
def log_source_error(url):
    with open(SOURCES_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{url} | ОШИБКА\n")

def load_blacklist():
    s = set()
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    s.add(line)
    return s
BLACKLIST = load_blacklist()
def is_blacklisted(url): return url in BLACKLIST

def load_source_patterns():
    patterns = []
    if os.path.exists(SOURCE_PATTERNS_FILE):
        with open(SOURCE_PATTERNS_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.append(re.compile(line, re.IGNORECASE))
    else:
        default = [r"raw\.githubusercontent\.com", r"\.txt$", r"sub\.", r"/sub/", r"/api/sub", r"v2ray", r"clash", r"xray", r"config"]
        with open(SOURCE_PATTERNS_FILE, 'w') as f:
            for p in default:
                f.write(p + '\n')
        patterns = [re.compile(p, re.IGNORECASE) for p in default]
    return patterns
SOURCE_PATTERNS = load_source_patterns()

def load_whitelist():
    domains = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE) as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith('#'):
                    domains.add(d)
    return domains

def load_cidr_whitelist():
    cidrs = []
    if os.path.exists(CIDR_WHITELIST_FILE):
        with open(CIDR_WHITELIST_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        cidrs.append(ipaddress.ip_network(line, strict=False))
                    except:
                        pass
    return cidrs

WHITELIST = load_whitelist()
CIDR_WHITELIST = load_cidr_whitelist()

def validate_vless(u): return u.startswith("vless://") and UUID_REGEX.search(u) and "@" in u and ":" in u
def validate_trojan(u): return u.startswith("trojan://") and "@" in u and ":" in u
def validate_vmess(u): return u.startswith("vmess://") and len(u) > 8
def validate_hysteria2(u): return u.startswith(("hysteria2://", "hy2://")) and "@" in u

def extract_sni(url):
    sni = None
    m = re.search(r'[?&]sni=([^&]+)', url, re.I)
    if not m:
        m = re.search(r'[?&]host=([^&]+)', url, re.I)
    if m:
        sni = urllib.parse.unquote(m.group(1))
    if not sni and url.startswith("vmess://"):
        try:
            b64 = url[8:].split('#')[0]
            obj = json.loads(base64.b64decode(b64).decode())
            sni = obj.get('sni') or obj.get('add')
        except:
            pass
    return sni if sni else "Без SNI"

def get_proto_net(url):
    if url.startswith("vless://"):
        proto = "vless"
        net = "tcp"
        m = re.search(r'[?&]type=([^&]+)', url, re.I)
        if m:
            net = m.group(1).lower()
    elif url.startswith("trojan://"):
        proto = "trojan"
        net = "tcp"
        m = re.search(r'[?&]type=([^&]+)', url, re.I)
        if m:
            net = m.group(1).lower()
    elif url.startswith("vmess://"):
        proto = "vmess"
        net = "tcp"
        try:
            b64 = url[8:].split('#')[0]
            obj = json.loads(base64.b64decode(b64).decode())
            net = obj.get('net', 'tcp')
        except:
            pass
    elif url.startswith(("hysteria2://", "hy2://")):
        proto = "hysteria2"
        net = "udp"
    else:
        proto = net = "unknown"
    return proto, net

def check_sni_against_whitelist(sni):
    if not sni or sni == "Без SNI":
        return False
    sni_l = sni.lower()
    if sni_l in WHITELIST:
        return True
    try:
        ip = ipaddress.ip_address(sni_l)
        for cidr in CIDR_WHITELIST:
            if ip in cidr:
                return True
    except:
        pass
    return False

def normalize_url_for_dedup(url):
    base = url.split('#')[0]
    if '?' in base:
        path, query = base.split('?', 1)
        params = {}
        for p in query.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k] = v
        sorted_params = sorted(params.items())
        new_q = '&'.join(f"{k}={v}" for k, v in sorted_params)
        return f"{path}?{new_q}"
    return base

def clean_url(url):
    url = url.strip().replace('\ufeff', '').replace('\u200b', '')
    url = url.replace('\n', '').replace('\r', '')
    import html
    url = html.unescape(url)
    url = urllib.parse.unquote(url)
    return url

def safe_quote(s): return urllib.parse.quote(s, safe='')

def build_query(params):
    parts = []
    for k, v in params.items():
        if v in (None, ''): continue
        if isinstance(v, bool):
            v = 'true' if v else 'false'
        parts.append(f"{k}={safe_quote(str(v))}")
    return '&'.join(parts)

# ========= Конвертеры (JSON, YAML, Base64) =========
def outbound_to_vless(out):
    settings = out.get('settings', {})
    vnext = settings.get('vnext', [])
    if not vnext: return None
    addr = vnext[0].get('address')
    port = vnext[0].get('port')
    users = vnext[0].get('users', [])
    if not users: return None
    uuid = users[0].get('id')
    enc = users[0].get('encryption', 'none')
    flow = users[0].get('flow', '')
    stream = out.get('streamSettings', {})
    network = stream.get('network', 'tcp')
    sec = stream.get('security', '')
    reality = stream.get('realitySettings', {})
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    params = {'encryption': enc, 'type': network}
    if flow: params['flow'] = flow
    if sec == 'reality':
        params['security'] = 'reality'
        if reality.get('serverName'): params['sni'] = reality['serverName']
        if reality.get('publicKey'): params['pbk'] = reality['publicKey']
        if reality.get('shortId'): params['sid'] = reality['shortId']
        if reality.get('fingerprint'): params['fp'] = reality['fingerprint']
    elif sec == 'tls':
        params['security'] = 'tls'
        if tls.get('serverName'): params['sni'] = tls['serverName']
        if tls.get('allowInsecure'): params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if tls.get('fingerprint'): params['fp'] = tls['fingerprint']
        if tls.get('alpn'): params['alpn'] = ','.join(tls['alpn'])
    if network == 'ws' and ws:
        if ws.get('path'): params['path'] = safe_quote(ws['path'])
        if ws.get('headers', {}).get('Host'): params['host'] = ws['headers']['Host']
    elif network == 'grpc' and grpc:
        if grpc.get('serviceName'): params['serviceName'] = safe_quote(grpc['serviceName'])
    params = {k:v for k,v in params.items() if v}
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    return f"vless://{uuid}@{addr}:{port}?{query}{remark}"

def outbound_to_trojan(out):
    servers = out.get('settings', {}).get('servers', [])
    if not servers: return None
    s = servers[0]
    addr = s.get('address'); port = s.get('port'); pwd = s.get('password')
    if not all([addr, port, pwd]): return None
    stream = out.get('streamSettings', {})
    sec = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    params = {}
    if sec == 'tls':
        if tls.get('serverName'): params['sni'] = tls['serverName']
        if tls.get('allowInsecure'): params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if tls.get('fingerprint'): params['fp'] = tls['fingerprint']
        if tls.get('alpn'): params['alpn'] = ','.join(tls['alpn'])
    network = stream.get('network', 'tcp')
    if network != 'tcp':
        params['type'] = network
        if network == 'ws' and ws:
            if ws.get('path'): params['path'] = safe_quote(ws['path'])
            if ws.get('headers', {}).get('Host'): params['host'] = ws['headers']['Host']
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    base = f"trojan://{pwd}@{addr}:{port}"
    if query: base += f"?{query}"
    return base + remark

def outbound_to_vmess(out):
    settings = out.get('settings', {})
    vnext = settings.get('vnext', [])
    if not vnext: return None
    addr = vnext[0].get('address')
    port = vnext[0].get('port')
    users = vnext[0].get('users', [])
    if not users: return None
    uuid = users[0].get('id')
    sec = users[0].get('security', 'auto')
    alterId = users[0].get('alterId', 0)
    stream = out.get('streamSettings', {})
    network = stream.get('network', 'tcp')
    tls = stream.get('security', '')
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    obj = {
        "v": "2", "ps": "", "add": addr, "port": port, "id": uuid,
        "aid": alterId, "scy": sec, "net": network, "type": "none",
        "host": "", "path": "", "tls": tls if tls in ('tls','') else "",
        "sni": "", "alpn": "", "fp": "", "allowInsecure": "0"
    }
    if network == 'ws' and ws:
        obj['host'] = ws.get('headers', {}).get('Host', '')
        obj['path'] = ws.get('path', '')
    elif network == 'grpc' and grpc:
        obj['path'] = grpc.get('serviceName', '')
    if tls == 'tls' and stream.get('tlsSettings'):
        tlsS = stream['tlsSettings']
        obj['sni'] = tlsS.get('serverName', '')
        obj['fp'] = tlsS.get('fingerprint', '')
        obj['allowInsecure'] = '1' if tlsS.get('allowInsecure') else '0'
    b64 = base64.b64encode(json.dumps(obj, separators=(',',':')).encode()).decode()
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    return f"vmess://{b64}{remark}"

def outbound_to_hy2(out):
    servers = out.get('settings', {}).get('servers', [])
    if not servers: return None
    s = servers[0]
    addr = s.get('address'); port = s.get('port'); auth = s.get('auth', '')
    if not addr or not port: return None
    auth = str(auth) if auth else ''
    stream = out.get('streamSettings', {})
    sec = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    params = {}
    if sec == 'tls':
        if tls.get('serverName'): params['sni'] = tls['serverName']
        if tls.get('allowInsecure'): params['insecure'] = '1' if tls['allowInsecure'] else '0'
        if tls.get('alpn'): params['alpn'] = ','.join(tls['alpn'])
    transport = stream.get('transport', {})
    if transport.get('hopConfig', {}).get('obfs') == 'salamander':
        params['obfs'] = 'salamander'
        params['obfs-password'] = transport['hopConfig'].get('password', '')
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    auth_part = f"{auth}@" if auth else ''
    return f"hy2://{auth_part}{addr}:{port}?{query}{remark}"

def convert_json_to_urls(content):
    urls = []
    try:
        decoder = json.JSONDecoder()
        idx = 0
        content = content.strip()
        while idx < len(content):
            obj, end = decoder.raw_decode(content, idx)
            idx = end
            while idx < len(content) and content[idx] in ' \t\n\r': idx += 1
            outbounds = None
            if isinstance(obj, dict):
                outbounds = obj.get('outbounds')
                if outbounds is None and 'config' in obj:
                    outbounds = obj['config'].get('outbounds')
            elif isinstance(obj, list):
                outbounds = obj
            if outbounds and isinstance(outbounds, list):
                for out in outbounds:
                    if not isinstance(out, dict): continue
                    proto = out.get('protocol')
                    if proto == 'vless':
                        u = outbound_to_vless(out)
                        if u: urls.append(u)
                    elif proto == 'trojan':
                        u = outbound_to_trojan(out)
                        if u: urls.append(u)
                    elif proto == 'vmess':
                        u = outbound_to_vmess(out)
                        if u: urls.append(u)
                    elif proto in ('hysteria2', 'hy2'):
                        u = outbound_to_hy2(out)
                        if u: urls.append(u)
    except:
        pass
    return urls

def convert_yaml_to_urls(content):
    try:
        data = yaml.safe_load(content)
        if not data or 'proxies' not in data: return []
        urls = []
        for p in data['proxies']:
            ptype = p.get('type')
            if ptype == 'vless':
                name = p.get('name','')
                server = p.get('server'); port = p.get('port'); uuid = p.get('uuid')
                if not all([server, port, uuid]): continue
                params = {'encryption':'none', 'type':p.get('network','tcp')}
                if p.get('flow'): params['flow'] = p['flow']
                if p.get('tls'): params['security'] = 'tls'
                if p.get('servername'): params['sni'] = p['servername']
                if p.get('client-fingerprint'): params['fp'] = p['client-fingerprint']
                network = p.get('network','tcp')
                if network == 'ws' and p.get('ws-opts'):
                    ws = p['ws-opts']
                    if ws.get('path'): params['path'] = safe_quote(ws['path'])
                    if ws.get('headers',{}).get('Host'): params['host'] = ws['headers']['Host']
                elif network == 'grpc' and p.get('grpc-opts'):
                    params['serviceName'] = p['grpc-opts'].get('grpc-service-name','')
                query = build_query({k:v for k,v in params.items() if v})
                remark = f"#{safe_quote(name)}" if name else ''
                urls.append(f"vless://{uuid}@{server}:{port}?{query}{remark}")
            elif ptype == 'trojan':
                name = p.get('name',''); server = p.get('server'); port = p.get('port'); pwd = p.get('password')
                if not all([server, port, pwd]): continue
                params = {}
                if p.get('servername'): params['sni'] = p['servername']
                if p.get('tls'): params['security'] = 'tls'
                if p.get('client-fingerprint'): params['fp'] = p['client-fingerprint']
                query = build_query(params)
                remark = f"#{safe_quote(name)}" if name else ''
                base = f"trojan://{pwd}@{server}:{port}"
                if query: base += f"?{query}"
                urls.append(base+remark)
            elif ptype == 'vmess':
                name = p.get('name',''); server = p.get('server'); port = p.get('port'); uuid = p.get('uuid')
                if not all([server, port, uuid]): continue
                obj = {
                    "v":"2","ps":name,"add":server,"port":port,"id":uuid,
                    "aid":p.get('alterId',0),"scy":p.get('security','auto'),
                    "net":p.get('network','tcp'),"type":"none",
                    "host":p.get('host',''),"path":p.get('path',''),
                    "tls":"tls" if p.get('tls') else "",
                    "sni":p.get('servername','')
                }
                b64 = base64.b64encode(json.dumps(obj, separators=(',',':')).encode()).decode()
                urls.append(f"vmess://{b64}")
            elif ptype in ('hysteria2','hy2'):
                name = p.get('name',''); server = p.get('server'); port = p.get('port'); auth = p.get('auth','')
                if not all([server, port]): continue
                params = {}
                if p.get('servername'): params['sni'] = p['servername']
                if p.get('tls'): params['insecure'] = '0'
                query = build_query(params)
                remark = f"#{safe_quote(name)}" if name else ''
                auth_part = f"{auth}@" if auth else ''
                urls.append(f"hy2://{auth_part}{server}:{port}?{query}{remark}")
        return urls
    except:
        return []

def decode_base64_content(content):
    try:
        content = content.strip()
        if not BASE64_REGEX.match(content.replace('\n','').replace('\r','')):
            return None
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        matches = []
        for reg in (VLESS_REGEX, TROJAN_REGEX, VMESS_REGEX, HY2_REGEX):
            matches.extend(reg.findall(decoded))
        if matches:
            return decoded, matches
        return None
    except:
        return None

# ========= Загрузка HTTP источников =========
async def fetch(session, url, sem):
    async with sem:
        try:
            async with session.get(url, timeout=30, ssl=False) as resp:
                if resp.status == 200:
                    return await resp.text()
        except: pass
    return None

async def process_url(session, url, sem, stats):
    content = await fetch(session, url, sem)
    async with stats['lock']:
        stats['processed'] += 1
    if not content:
        log_source_error(url)
        await update_progress(stats)
        return
    vless = VLESS_REGEX.findall(content)
    trojan = TROJAN_REGEX.findall(content)
    vmess = VMESS_REGEX.findall(content)
    hy2 = HY2_REGEX.findall(content)
    if not (vless or trojan or vmess or hy2):
        json_urls = convert_json_to_urls(content)
        for u in json_urls:
            if u.startswith("vless://"): vless.append(u)
            elif u.startswith("trojan://"): trojan.append(u)
            elif u.startswith("vmess://"): vmess.append(u)
            elif u.startswith(("hysteria2://","hy2://")): hy2.append(u)
        yaml_urls = convert_yaml_to_urls(content)
        for u in yaml_urls:
            if u.startswith("vless://"): vless.append(u)
            elif u.startswith("trojan://"): trojan.append(u)
            elif u.startswith("vmess://"): vmess.append(u)
            elif u.startswith(("hysteria2://","hy2://")): hy2.append(u)
        b64 = decode_base64_content(content)
        if b64:
            _, matches = b64
            for m in matches:
                if m.startswith("vless://"): vless.append(m)
                elif m.startswith("trojan://"): trojan.append(m)
                elif m.startswith("vmess://"): vmess.append(m)
                elif m.startswith(("hysteria2://","hy2://")): hy2.append(m)
    total = len(vless)+len(trojan)+len(vmess)+len(hy2)
    if total > 0:
        async with stats['lock']:
            stats['vless'] += len(vless)
            stats['trojan'] += len(trojan)
            stats['vmess'] += len(vmess)
            stats['hy2'] += len(hy2)
        async with stats['file_lock']:
            async with aiofiles.open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                for line in vless+trojan+vmess+hy2:
                    await f.write(line + "\n")
    await update_progress(stats)

async def update_progress(stats):
    async with stats['lock']:
        p = stats['processed']; t = stats['total_sources']
        v = stats['vless']; tr = stats['trojan']; vm = stats['vmess']; h = stats['hy2']
        bar_len = 40
        prog = p/t if t>0 else 0
        filled = int(bar_len*prog)
        bar = '█'*filled + '░'*(bar_len-filled)
        percent = round(prog*100)
        sys.stdout.write(f"\rЗагружено: |{bar}| {percent}% {p}/{t} | Конфигов: {v+tr+vm+h} (VLESS:{v} TROJAN:{tr} VMESS:{vm} HY2:{h})")
        sys.stdout.flush()

async def download_http_sources(urls):
    filtered = [u for u in urls if not is_blacklisted(u)]
    print(f"\nСкачиваю {len(filtered)} HTTP источников...")
    sem = asyncio.Semaphore(THREADS_DOWNLOAD)
    stats = {
        'processed':0, 'total_sources':len(filtered),
        'vless':0,'trojan':0,'vmess':0,'hy2':0,
        'lock':asyncio.Lock(), 'file_lock':asyncio.Lock()
    }
    async with aiohttp.ClientSession() as session:
        tasks = [process_url(session, url, sem, stats) for url in filtered]
        await asyncio.gather(*tasks)
    print()

async def add_my_configs():
    if not os.path.exists(MYURL_FILE): return
    with open(MYURL_FILE) as f:
        lines = [l.strip() for l in f if l.strip()]
    vless = [l for l in lines if validate_vless(l)]
    trojan = [l for l in lines if validate_trojan(l)]
    vmess = [l for l in lines if validate_vmess(l)]
    hy2 = [l for l in lines if validate_hysteria2(l)]
    async with aiofiles.open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for l in vless+trojan+vmess+hy2:
            await f.write(l + "\n")
    print(f"Добавлено из myurl.txt: VLESS={len(vless)}, Trojan={len(trojan)}, VMess={len(vmess)}, HY2={len(hy2)}")

# ========= Очистка и правка параметров =========
async def clean_all_configs():
    print("\n=== ОЧИСТКА ДУБЛИКАТОВ ===")
    if not os.path.exists(OUTPUT_FILE): return
    with open(OUTPUT_FILE) as f:
        lines = [l.strip() for l in f if l.strip()]
    unique = {}
    for line in lines:
        if line.startswith("vless://") and not validate_vless(line): continue
        if line.startswith("trojan://") and not validate_trojan(line): continue
        if line.startswith("vmess://") and not validate_vmess(line): continue
        if line.startswith(("hysteria2://","hy2://")) and not validate_hysteria2(line): continue
        norm = normalize_url_for_dedup(line)
        if norm not in unique:
            unique[norm] = line
    cleaned = list(unique.values())
    async with aiofiles.open(CLEAN_FILE, "w", encoding="utf-8") as f:
        for url in cleaned:
            await f.write(url + "\n")
    print(f"Было {len(lines)}, стало {len(cleaned)}")

async def clean_names():
    print("\n=== ОЧИСТКА НАЗВАНИЙ ===")
    if not os.path.exists(CLEAN_FILE): return
    with open(CLEAN_FILE) as f:
        configs = [l.strip() for l in f if l.strip()]
    cleaned = [url.split('#')[0] + '#' for url in configs]
    async with aiofiles.open(CLEAN_NAMES_FILE, "w", encoding="utf-8") as f:
        for url in cleaned:
            await f.write(url + "\n")
    print(f"Очищено {len(cleaned)}")

def decode_multilevel(s):
    if not s: return s
    prev = None
    cur = s
    while '%25' in cur and cur != prev:
        prev = cur
        try: cur = urllib.parse.unquote(cur)
        except: break
    if '%' in cur and cur != prev:
        try: cur = urllib.parse.unquote(cur)
        except: pass
    return cur

def fix_vless_params(url):
    if not url.startswith("vless://"): return url
    try:
        frag = ""
        base = url
        if '#' in base:
            base, frag = base.split('#',1)
        if '?' not in base: return url
        before, query = base.split('?',1)
        params = {}
        for p in query.split('&'):
            if '=' in p:
                k,v = p.split('=',1)
                params[k] = v
        changed = False
        if 'spx' in params:
            dec = decode_multilevel(params['spx'])
            if dec != params['spx']:
                params['spx'] = dec
                changed = True
        if 'extra' in params:
            dec = decode_multilevel(params['extra'])
            if dec.startswith('{') and dec.endswith('}'):
                try:
                    j = json.loads(dec)
                    fixed = json.dumps(j, separators=(',',':'))
                    if fixed != dec:
                        dec = fixed
                        changed = True
                except: pass
            if dec != params['extra']:
                params['extra'] = dec
                changed = True
        if not changed: return url
        new_parts = []
        for p in query.split('&'):
            if '=' in p:
                k,v = p.split('=',1)
                if k in params:
                    new_parts.append(f"{k}={params[k]}")
                else:
                    new_parts.append(p)
            else:
                new_parts.append(p)
        new_q = '&'.join(new_parts)
        new_base = f"{before}?{new_q}"
        if frag: new_base += f"#{frag}"
        return new_base
    except: return url

async def fix_all_vless_params(configs):
    print("\n=== ИСПРАВЛЕНИЕ spx/extra ===")
    fixed = 0
    new = []
    for url in configs:
        if url.startswith("vless://"):
            new_url = fix_vless_params(url)
            if new_url != url: fixed += 1
            new.append(new_url)
        else:
            new.append(url)
    async with aiofiles.open(CLEAN_NAMES_FILE, "w", encoding="utf-8") as f:
        for url in new:
            await f.write(url + "\n")
    print(f"Исправлено: {fixed}")
    return new

# ========= TCP предфильтрация (VLESS и VMess) =========
def tcp_check(url):
    try:
        if url.startswith("vless://"):
            content = url[8:]
            if '@' not in content: return False
            host_port = content.split('@',1)[1].split('?')[0].split('#')[0]
            if ':' in host_port:
                host, port_str = host_port.split(':',1)
                port = int(port_str) if port_str.isdigit() else 443
            else:
                host, port = host_port, 443
        elif url.startswith("vmess://"):
            b64 = url[8:].split('#')[0]
            obj = json.loads(base64.b64decode(b64).decode())
            host = obj.get('add', '')
            port = int(obj.get('port', 443))
        else:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        res = sock.connect_ex((host, port))
        sock.close()
        return res == 0
    except:
        return False

async def tcp_prefilter(configs):
    print("\n=== TCP ПРЕДФИЛЬТРАЦИЯ (VLESS+VMess) ===")
    online = [u for u in configs if not (u.startswith("vless://") or u.startswith("vmess://"))]
    to_check = [u for u in configs if u.startswith("vless://") or u.startswith("vmess://")]
    start = time.time()
    with ThreadPoolExecutor(max_workers=TCP_CHECK_THREADS) as ex:
        futures = {ex.submit(tcp_check, u): u for u in to_check}
        proc = 0
        for f in as_completed(futures):
            proc += 1
            if f.result():
                online.append(futures[f])
            if proc % 10 == 0:
                sys.stdout.write(f"\r[TCP] {proc}/{len(to_check)} проверено")
                sys.stdout.flush()
    sys.stdout.write('\n')
    online = list(set(online))
    elapsed = time.time() - start
    print(f"\nПредфильтрация: {len(online)}/{len(configs)} за {elapsed:.1f}s")
    async with aiofiles.open(TCP_FILE, "w", encoding="utf-8") as f:
        for url in online:
            await f.write(url + "\n")
    return online

# ========= Полная проверка Xray/Hysteria2 =========
def is_port_in_use(p):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', p)) == 0
    except:
        return False

def wait_core(port, max_wait):
    start = time.time()
    while time.time() - start < max_wait:
        if is_port_in_use(port):
            return True
        time.sleep(0.1)
    return False

def run_xray(cfg):
    return subprocess.Popen([str(XRAY_PATH), "run", "-c", cfg],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def kill_proc(p):
    if not p: return
    try:
        p.terminate()
        time.sleep(0.3)
        p.kill()
    except: pass

def parse_vless_full(u):
    try:
        u = clean_url(u)
        if not u.startswith("vless://"): return None
        main = u; tag = "vless"
        if '#' in u:
            main, tag = u.split('#',1)
            tag = urllib.parse.unquote(tag).strip()
        m = re.search(r'vless://([^@]+)@([^:]+):(\d+)', main)
        if not m: return None
        uuid, addr, port = m.group(1), m.group(2), int(m.group(3))
        params = {}
        if '?' in main:
            params = parse_qs(main.split('?',1)[1])
        def get(k, defv=""): return params.get(k,[defv])[0].strip() or defv
        net = get("type","tcp").lower()
        if net not in ("tcp","ws","grpc","h2","kcp","quic","httpupgrade","xhttp"): net = "tcp"
        sec = get("security","none").lower()
        if sec not in ("tls","reality","none"): sec = "none"
        pbk = get("pbk","")
        if pbk and sec == "tls": sec = "reality"
        return {
            "protocol":"vless","uuid":uuid,"address":addr,"port":port,"type":net,"security":sec,
            "path":urllib.parse.unquote(get("path","")),"host":get("host",""),"sni":get("sni",""),
            "fp":get("fp","chrome"),"alpn":get("alpn",""),"serviceName":get("serviceName",""),
            "flow":get("flow",""),"pbk":pbk,"sid":get("sid",""),"allowInsecure":get("allowInsecure","true").lower() in ("true","1","yes"),
            "tag":tag
        }
    except: return None

def parse_trojan_full(u):
    try:
        u = u.strip().replace('\ufeff','').replace('\u200b','')
        if not u.startswith("trojan://"): return None
        prot = u.replace('%23','___HASH___')
        if '#' in prot:
            clean, tag = prot.split('#',1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            clean = prot; tag = "trojan"
        parsed = urlparse(clean)
        pwd = (parsed.username or "trojan").replace('___HASH___','#')
        if not parsed.hostname or not parsed.port: return None
        qs = parse_qs(parsed.query)
        def get(k, d=""): return qs.get(k,[d])[0].strip() or d
        net = get("type","tcp").lower()
        if net not in ("tcp","ws","grpc","h2","kcp","quic","httpupgrade","xhttp"): net = "tcp"
        sec = get("security","tls").lower()
        if sec not in ("tls","none"): sec = "tls"
        return {
            "protocol":"trojan","password":pwd,"address":parsed.hostname,"port":int(parsed.port),
            "type":net,"security":sec,"path":urllib.parse.unquote(get("path","")),"host":get("host",""),
            "sni":get("sni",""),"fp":get("fp","chrome"),"alpn":get("alpn",""),"serviceName":get("serviceName",""),
            "allowInsecure":get("allowInsecure","true").lower() in ("true","1","yes"),"tag":tag
        }
    except: return None

def parse_vmess_full(u):
    try:
        if not u.startswith("vmess://"): return None
        b64 = u[8:].split('#')[0]
        obj = json.loads(base64.b64decode(b64).decode())
        addr = obj.get('add'); port = int(obj.get('port',0)); uuid = obj.get('id')
        if not addr or not port or not uuid: return None
        return {
            "protocol":"vmess","uuid":uuid,"address":addr,"port":port,
            "type":obj.get('net','tcp'),"security":"tls" if obj.get('tls')=='tls' else "none",
            "path":obj.get('path',''),"host":obj.get('host',''),"sni":obj.get('sni',''),
            "fp":obj.get('fp','chrome'),"alpn":obj.get('alpn',''),"serviceName":"",
            "allowInsecure":obj.get('allowInsecure','0')=='1',"tag":obj.get('ps','vmess'),
            "alterId":obj.get('aid',0),"encryption":obj.get('scy','auto')
        }
    except: return None

def build_stream(conf):
    net = conf.get("type","tcp").lower()
    sec = conf.get("security","none").lower()
    stream = {"network":net, "security":sec}
    if sec == "tls":
        tls = {"serverName":conf.get("sni") or conf.get("host") or "",
               "allowInsecure":conf.get("allowInsecure",True),
               "fingerprint":conf.get("fp","chrome")}
        alpn = [a.strip() for a in conf.get("alpn","").split(",") if a.strip()] if conf.get("alpn") else None
        if alpn: tls["alpn"] = alpn
        stream["tlsSettings"] = tls
    elif sec == "reality":
        pbk = conf.get("pbk","")
        if not pbk: return None
        reality = {"publicKey":pbk, "shortId":conf.get("sid",""),
                   "serverName":conf.get("sni") or conf.get("host") or "",
                   "fingerprint":conf.get("fp","chrome"), "spiderX":"/"}
        alpn = [a.strip() for a in conf.get("alpn","").split(",") if a.strip()] if conf.get("alpn") else None
        if alpn: reality["alpn"] = alpn
        stream["realitySettings"] = reality
    if net in ("ws","websocket"):
        stream["wsSettings"] = {"path":conf.get("path","/"), "headers":{"Host":conf.get("host","")}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName":conf.get("serviceName","")}
    elif net in ("xhttp","splithttp"):
        stream["xhttpSettings"] = {"path":conf.get("path","/"), "host":conf.get("host","")}
    return stream

def get_outbound(proxy_url, tag):
    if proxy_url.startswith("vless://"): conf = parse_vless_full(proxy_url)
    elif proxy_url.startswith("trojan://"): conf = parse_trojan_full(proxy_url)
    elif proxy_url.startswith("vmess://"): conf = parse_vmess_full(proxy_url)
    else: return None
    if not conf or not conf.get("address") or not (1 <= conf.get("port",0) <= 65535): return None
    out = {"tag":tag}
    if conf["protocol"] == "vless":
        out["protocol"] = "vless"
        out["settings"] = {"vnext":[{"address":conf["address"],"port":conf["port"],
                                     "users":[{"id":conf["uuid"],"encryption":"none","flow":conf.get("flow","")}]}]}
        stream = build_stream(conf)
        if stream: out["streamSettings"] = stream
    elif conf["protocol"] == "trojan":
        out["protocol"] = "trojan"
        out["settings"] = {"servers":[{"address":conf["address"],"port":conf["port"],"password":conf["password"]}]}
        stream = build_stream(conf)
        if stream: out["streamSettings"] = stream
    elif conf["protocol"] == "vmess":
        out["protocol"] = "vmess"
        out["settings"] = {"vnext":[{"address":conf["address"],"port":conf["port"],
                                     "users":[{"id":conf["uuid"],"security":conf.get("encryption","auto"),"alterId":conf.get("alterId",0)}]}]}
        stream = build_stream(conf)
        if stream: out["streamSettings"] = stream
    else: return None
    return out

def create_config(proxy_url, local_port, work_dir):
    tag_out = f"out_{local_port}"
    out = get_outbound(proxy_url, tag_out)
    if not out: return None, "outbound error"
    inbound = {"port":local_port,"listen":"127.0.0.1","protocol":"socks","tag":f"in_{local_port}","settings":{"udp":False}}
    routing = {"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":[f"in_{local_port}"],"outboundTag":tag_out}]}
    cfg = {"log":{"loglevel":"warning"},"inbounds":[inbound],"outbounds":[out],"routing":routing}
    path = os.path.join(work_dir, f"config_{local_port}.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    return path, None

def check_http(local_port, timeout):
    for url in TEST_URLS:
        proxies = {'http':f'socks5://127.0.0.1:{local_port}','https':f'socks5://127.0.0.1:{local_port}'}
        try:
            start = time.time()
            r = requests.get(url, proxies=proxies, timeout=timeout, verify=False)
            if r.status_code < 400:
                return round((time.time()-start)*1000), None
        except: continue
    return False, "No response"

def check_xray(proxy_url, port, work_dir):
    cfg_path, err = create_config(proxy_url, port, work_dir)
    if not cfg_path: return None, err
    proc = run_xray(cfg_path)
    if not proc: return None, "Xray start fail"
    if not wait_core(port, CORE_STARTUP_TIMEOUT):
        kill_proc(proc); return None, "Xray not ready"
    time.sleep(0.5)
    ping, err = check_http(port, XRAY_TIMEOUT)
    kill_proc(proc)
    time.sleep(0.2)
    try: os.remove(cfg_path)
    except: pass
    if ping: return proxy_url, ping
    return None, err

def check_hysteria2(proxy_url, tmp_dir):
    try:
        parsed = urlparse(proxy_url)
        if parsed.scheme not in ('hysteria2','hy2'): return None, "bad scheme"
        netloc = parsed.netloc
        auth = None
        if '@' in netloc:
            auth_part, netloc = netloc.split('@',1)
            if ':' in auth_part:
                u,p = auth_part.split(':',1)
                auth = {'username':urllib.parse.unquote(u), 'password':urllib.parse.unquote(p)}
            else:
                auth = urllib.parse.unquote(auth_part)
        if ':' in netloc:
            host, port_str = netloc.split(':',1)
            port = int(port_str)
        else:
            host, port = netloc, 443
        params = {k.lower():v[0] for k,v in parse_qs(parsed.query).items()}
        if isinstance(auth,str) and '%' in auth: auth = urllib.parse.unquote(auth)
        insecure = params.get('insecure','true').lower() in ('true','1','yes')
        socks_port = random.randint(20000,60000)
        cfg = {
            'server':f"{host}:{port}",
            'auth':auth if auth is not None else "auto",
            'tls':{'sni':params.get('sni',host), 'insecure':insecure},
            'socks5':{'listen':f'127.0.0.1:{socks_port}'},
            'quic':{'initStreamReceiveWindow':8388608,'maxStreamReceiveWindow':8388608,
                    'initConnReceiveWindow':20971520,'maxConnReceiveWindow':20971520,
                    'maxIdleTimeout':'30s','maxIncomingStreams':1024}
        }
        alpn = params.get('alpn','h3')
        cfg['tls']['alpn'] = [a.strip() for a in alpn.split(',')]
        obfs_pass = params.get('obfs-password')
        if obfs_pass:
            cfg['transport'] = {'udp':{'obfs':{'type':'salamander','password':obfs_pass}}}
        cfg_file = os.path.join(tmp_dir, f"hy2_{random.randint(10000,99999)}.yaml")
        with open(cfg_file, 'w') as f:
            yaml.dump(cfg, f, default_flow_style=False)
        proc = subprocess.Popen([str(HYSTERIA2_PATH), 'client', '-c', cfg_file],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        if proc.poll() is not None:
            proc = subprocess.Popen([str(HYSTERIA2_PATH), '-c', cfg_file],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(5)
            if proc.poll() is not None:
                return None, "hysteria2 client fail"
        port_ready = False
        for _ in range(40):
            time.sleep(0.3)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex(('127.0.0.1', socks_port)) == 0:
                s.close(); port_ready = True; break
            s.close()
        if not port_ready:
            return None, f"socks port {socks_port} not open"
        for url in TEST_URLS:
            proxies = {'http':f'socks5://127.0.0.1:{socks_port}','https':f'socks5://127.0.0.1:{socks_port}'}
            try:
                start = time.time()
                r = requests.get(url, proxies=proxies, timeout=XRAY_TIMEOUT, verify=False)
                if r.status_code < 400:
                    ping = int((time.time()-start)*1000)
                    return proxy_url, ping
            except: continue
        return None, "no test url passed"
    except Exception as e:
        return None, str(e)
    finally:
        if 'proc' in locals() and proc:
            proc.terminate(); time.sleep(0.5); proc.kill()
        try: os.remove(cfg_file)
        except: pass

port_lock = threading.Lock()
current_port = LOCAL_PORT_START

def check_one(proxy_url):
    global current_port
    with port_lock:
        port = current_port
        current_port += 1
        if current_port > 60000: current_port = LOCAL_PORT_START
    tmp = tempfile.mkdtemp(prefix="check_")
    try:
        if proxy_url.startswith(("hysteria2://","hy2://")):
            res = check_hysteria2(proxy_url, tmp)
        else:
            res = check_xray(proxy_url, port, tmp)
        if res and res[0]:
            return res[0]
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

async def check_all(configs):
    print(f"\n=== ПОЛНАЯ ПРОВЕРКА (Xray + Hysteria2) ===")
    if not configs: return []
    total = len(configs)
    print(f"Проверяем {total} конфигов (таймаут {XRAY_TIMEOUT}с, потоков {MAX_WORKERS})")
    start = time.time()
    stats_lock = threading.Lock()
    checked = 0; alive = 0; alive_proto = {"VLESS":0,"TROJAN":0,"VMESS":0,"HY2":0}
    stop = threading.Event()
    def printer():
        while not stop.is_set():
            time.sleep(1)
            with stats_lock:
                c = checked; a = alive
                elapsed = time.time()-start
                speed = c/elapsed if elapsed>0 else 0
                sys.stdout.write(f"\r[CHECK] {c}/{total} | Работает: {a} | VLESS:{alive_proto['VLESS']} TROJAN:{alive_proto['TROJAN']} VMESS:{alive_proto['VMESS']} HY2:{alive_proto['HY2']} | {speed:.1f}/сек    ")
                sys.stdout.flush()
        sys.stdout.write('\n')
    t = threading.Thread(target=printer, daemon=True); t.start()
    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_one, url): url for url in configs}
        for f in as_completed(futures):
            with stats_lock:
                checked += 1
            try:
                w = f.result()
                if w:
                    working.append(w)
                    with stats_lock:
                        alive += 1
                        if w.startswith("vless://"): alive_proto["VLESS"] += 1
                        elif w.startswith("trojan://"): alive_proto["TROJAN"] += 1
                        elif w.startswith("vmess://"): alive_proto["VMESS"] += 1
                        elif w.startswith(("hysteria2://","hy2://")): alive_proto["HY2"] += 1
            except: pass
    stop.set(); t.join(timeout=2)
    elapsed = time.time()-start
    print(f"\nПроверка завершена: {len(working)}/{total} за {elapsed:.1f}с")
    return working

# ========= Финальное переименование и сортировка =========
def rename_config(url):
    sni = extract_sni(url)
    proto, net = get_proto_net(url)
    name = f"{sni}|{proto}|{net}|#LSO©-#LinSpisokObhod©"
    base = url.split('#')[0]
    enc = urllib.parse.quote(name, safe='')
    return f"{base}#{enc}"

async def save_classified(working):
    lte = []
    wifi = []
    for url in working:
        sni = extract_sni(url)
        if check_sni_against_whitelist(sni):
            lte.append(url)
        else:
            wifi.append(url)
    async def write_file(p, data):
        async with aiofiles.open(p, "w", encoding="utf-8") as f:
            for line in data:
                await f.write(line + "\n")
    await write_file(os.path.join(OUTPUT_DIR, "LTE.txt"), lte)
    await write_file(os.path.join(OUTPUT_DIR, "WIFI.txt"), wifi)
    print(f"\n=== РАСПРЕДЕЛЕНИЕ ===")
    print(f"LTE (прошли whitelist/cidrwhitelist): {len(lte)}")
    print(f"WIFI (остальные): {len(wifi)}")
    print(f"Сохранено в {OUTPUT_DIR}/LTE.txt и {OUTPUT_DIR}/WIFI.txt")

# ========= Основной цикл =========
async def main():
    print("=== СТАРТ ПАРСЕРА ===")
    if os.path.exists(OUTPUT_FILE): os.remove(OUTPUT_FILE)
    if os.path.exists(WORK_FILE):
        with open(WORK_FILE) as f:
            old = [l.strip() for l in f if l.strip()]
        async with aiofiles.open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            for u in old:
                await f.write(u + "\n")
        print(f"Импортировано {len(old)} конфигов из {WORK_FILE}")

    if not os.path.exists(SOURCES_FILE):
        print(f"Файл {SOURCES_FILE} не найден, пропускаем")
        http = []
    else:
        with open(SOURCES_FILE) as f:
            http = [s.strip() for s in f if s.strip().startswith(('http://','https://'))]
    if http: await download_http_sources(http)
    await add_my_configs()
    if not os.path.exists(OUTPUT_FILE):
        print("Нет конфигов, завершение")
        return

    await clean_all_configs()
    await clean_names()
    with open(CLEAN_NAMES_FILE) as f:
        all_cfg = [l.strip() for l in f if l.strip()]
    all_cfg = await fix_all_vless_params(all_cfg)
    if not all_cfg: return

    online = await tcp_prefilter(all_cfg)
    if not online: return

    working = await check_all(online)
    if not working: return

    renamed = [rename_config(u) for u in working]
    async with aiofiles.open(NAMED_FILE, "w", encoding="utf-8") as f:
        for u in renamed:
            await f.write(u + "\n")
    async with aiofiles.open(WORK_FILE, "w", encoding="utf-8") as f:
        for u in renamed:
            await f.write(u + "\n")

    await save_classified(renamed)

if __name__ == "__main__":
    asyncio.run(main())

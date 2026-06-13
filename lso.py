#!/usr/bin/env python3
# RKP_Parser_Full.py — только TCP, многопоточная загрузка, заголовки в ALL/LTE/WIFI

import asyncio
import aiohttp
import aiofiles
import re
import os
import time
import json
import urllib.parse
import sys
import socket
import random
import base64
import yaml
import ipaddress
from datetime import datetime
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
THREADS_DOWNLOAD = 1000        # количество одновременных загрузок источников
TCP_CHECK_THREADS = 10         # потоков для TCP проверки
TCP_TIMEOUT = 30               # таймаут TCP connect в секундах

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

# ========= Многопоточная загрузка источников =========
async def fetch(session, url):
    try:
        async with session.get(url, timeout=30, ssl=False) as resp:
            if resp.status == 200:
                return await resp.text()
    except:
        pass
    return None

async def process_url(session, url, sem, stats):
    async with sem:
        content = await fetch(session, url)
        async with stats['lock']:
            stats['processed'] += 1
        if not content:
            log_source_error(url)
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

async def download_http_sources(urls):
    filtered = [u for u in urls if not is_blacklisted(u)]
    print(f"\nСкачиваю {len(filtered)} HTTP источников (потоков: {THREADS_DOWNLOAD})...")
    sem = asyncio.Semaphore(THREADS_DOWNLOAD)
    stats = {
        'processed':0, 'total_sources':len(filtered),
        'vless':0,'trojan':0,'vmess':0,'hy2':0,
        'lock':asyncio.Lock(), 'file_lock':asyncio.Lock()
    }
    async with aiohttp.ClientSession() as session:
        tasks = [process_url(session, url, sem, stats) for url in filtered]
        await asyncio.gather(*tasks)
    print(f"\nОбработано {stats['processed']} источников, найдено конфигов: {stats['vless']+stats['trojan']+stats['vmess']+stats['hy2']}")

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

# ========= TCP проверка (многопоточная) =========
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
    print(f"\n=== TCP ПРОВЕРКА (VLESS+VMess, потоков: {TCP_CHECK_THREADS}, таймаут: {TCP_TIMEOUT}с) ===")
    online = [u for u in configs if not (u.startswith("vless://") or u.startswith("vmess://"))]
    to_check = [u for u in configs if u.startswith("vless://") or u.startswith("vmess://")]
    if not to_check:
        print("Нет конфигов VLESS/VMess для проверки")
        return online
    start = time.time()
    with ThreadPoolExecutor(max_workers=TCP_CHECK_THREADS) as executor:
        futures = {executor.submit(tcp_check, url): url for url in to_check}
        processed = 0
        for future in as_completed(futures):
            processed += 1
            if future.result():
                online.append(futures[future])
            if processed % max(1, len(to_check)//10) == 0:
                sys.stdout.write(f"\r[TCP] {processed}/{len(to_check)} проверено")
                sys.stdout.flush()
    sys.stdout.write(f"\r[TCP] {len(to_check)}/{len(to_check)} проверено\n")
    online = list(set(online))
    elapsed = time.time() - start
    print(f"\nTCP проверка завершена: {len(online)}/{len(configs)} за {elapsed:.1f}s")
    async with aiofiles.open(TCP_FILE, "w", encoding="utf-8") as f:
        for url in online:
            await f.write(url + "\n")
    return online

# ========= Переименование и сохранение с заголовками =========
def rename_config(url):
    sni = extract_sni(url)
    proto, net = get_proto_net(url)
    name = f"{sni}|{proto}|{net}|#LSO©-#LinSpisokObhod©"
    base = url.split('#')[0]
    enc = urllib.parse.quote(name, safe='')
    return f"{base}#{enc}"

async def save_classified(working):
    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    header_all = f"""#profile-title: #LSO-#LinSpisokObhod
#profile-update-interval: 1
#support-url: https://t.me/LinSpisokObhod
#announce: LinSpisokObhod подписка all.txt. Здесь находится конфиги WIFI.txt и LTE.txt Время: {update_time}
#subscription-userinfo: upload=0; download=0; total=0; expire=0

"""
    header_lte = f"""#profile-title: #LSO-#LinSpisokObhod
#profile-update-interval: 1
#support-url: https://t.me/LinSpisokObhod
#announce: LinSpisokObhod подписка LTE.txt. Здесь находится конфиги которые может подойдут для повседневного использования. Время: {update_time}
#subscription-userinfo: upload=0; download=0; total=0; expire=0

"""
    header_wifi = f"""#profile-title: #LSO-#LinSpisokObhod
#profile-update-interval: 1
#support-url: https://t.me/LinSpisokObhod
#announce: LinSpisokObhod подписка WIFI.txt. Здесь находится конфиги которые может подойдут для вайфай но может и для мобильного интернета Время: {update_time}
#subscription-userinfo: upload=0; download=0; total=0; expire=0

"""
    
    lte = []
    wifi = []
    for url in working:
        sni = extract_sni(url)
        if check_sni_against_whitelist(sni):
            lte.append(url)
        else:
            wifi.append(url)
    
    async def write_file(path, header, data):
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(header)
            for line in data:
                await f.write(line + "\n")
    
    await write_file(os.path.join(OUTPUT_DIR, "ALL.txt"), header_all, working)
    await write_file(os.path.join(OUTPUT_DIR, "LTE.txt"), header_lte, lte)
    await write_file(os.path.join(OUTPUT_DIR, "WIFI.txt"), header_wifi, wifi)
    
    print(f"\n=== РАСПРЕДЕЛЕНИЕ ===")
    print(f"LTE (прошли whitelist/cidrwhitelist): {len(lte)}")
    print(f"WIFI (остальные): {len(wifi)}")
    print(f"Всего рабочих: {len(working)}")
    print(f"Сохранено в {OUTPUT_DIR}/LTE.txt, {OUTPUT_DIR}/WIFI.txt, {OUTPUT_DIR}/ALL.txt")

# ========= Основной цикл =========
async def main():
    print("=== СТАРТ ПАРСЕРА (только TCP, многопоточная загрузка) ===")
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

    renamed = [rename_config(u) for u in online]
    async with aiofiles.open(NAMED_FILE, "w", encoding="utf-8") as f:
        for u in renamed:
            await f.write(u + "\n")
    async with aiofiles.open(WORK_FILE, "w", encoding="utf-8") as f:
        for u in renamed:
            await f.write(u + "\n")

    await save_classified(renamed)

if __name__ == "__main__":
    asyncio.run(main())

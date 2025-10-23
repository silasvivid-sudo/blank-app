#!/usr/bin/env python3
import streamlit as st
import os
import sys
import json
import base64
import time
import re
import subprocess
import requests
import platform
import logging
import socket

# 配置日志输出到控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Environment variables
UPLOAD_URL = os.environ.get('UPLOAD_URL', '')
PROJECT_URL = os.environ.get('PROJECT_URL', 'https://blank-app-2pgjkfzgsf8drhkjmdsz6e.streamlit.app/')
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'True').lower() == 'True'
FILE_PATH = os.environ.get('FILE_PATH', './.npm')
SUB_PATH = os.environ.get('SUB_PATH', 'sub')
UUID = os.environ.get('UUID', '28713155-6f6d-4a2d-a6cd-5d9d9f28a36e')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')
DOMAIN = os.environ.get('DOMAIN', '')
GOGO_AUTH = os.environ.get('GOGO_AUTH', '')
HTTP_PORT = 8000  # HTTP 健康检查端口
GOGO_PORT = 8001  # Mixed 代理端口
CFIP = os.environ.get('CFIP', 'cf.090227.xyz')
CFPORT = int(os.environ.get('CFPORT', 443))
NAME = os.environ.get('NAME', 'Streamlit')

# Paths
os.makedirs(FILE_PATH, exist_ok=True)
subPath = os.path.join(FILE_PATH, 'sub.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
configPath = os.path.join(FILE_PATH, 'config.json')
servicesInitialized = os.path.exists(subPath)

def check_port(port, host='127.0.0.1', timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def deleteNodes():
    try:
        if not UPLOAD_URL or not os.path.exists(subPath):
            return
        with open(subPath, 'r', encoding='utf-8') as f:
            fileContent = f.read()
        decoded = base64.b64decode(fileContent).decode('utf-8')
        nodes = [line for line in decoded.split('\n') if re.match(r'(vless|vmess|trojan|hysteria2|tuic):\/\/', line)]
        if not nodes:
            return
        response = requests.post(f"{UPLOAD_URL}/api/delete-nodes", json={"nodes": nodes})
        logging.info(f"Delete nodes response: {response.status_code}")
    except Exception as e:
        logging.info(f"Error in deleteNodes: {e}")

def cleanupOldFiles():
    pathsToDelete = ['cfd', 'sb', 'sub.txt', 'boot.log', 'tunnel.yml', 'tunnel.json']
    for file in pathsToDelete:
        filePath = os.path.join(FILE_PATH, file)
        if os.path.exists(filePath):
            os.unlink(filePath)
            logging.info(f"Cleaned up {filePath}")

# ✅ 双端口配置
config = {
    "log": {"level": "info"},
    "inbounds": [
        # HTTP 健康检查 - CFD 转发到此端口
        {
            "type": "http",
            "tag": "http-in",
            "listen": "::",
            "listen_port": HTTP_PORT,
            "sniff": True
        },
        # Mixed 代理协议
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "::",
            "listen_port": GOGO_PORT,
            "sniff": True,
            "domain_strategy": "ipv4_only"
        },
        # 协议入站
        {
            "type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": 3001,
            "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}], "tls": {"enabled": False}
        },
        {
            "type": "vless", "tag": "vless-ws-in", "listen": "127.0.0.1", "listen_port": 3002,
            "users": [{"uuid": UUID}],
            "transport": {"type": "ws", "path": "/vless-argo"}, "sniff": True
        },
        {
            "type": "vmess", "tag": "vmess-ws-in", "listen": "127.0.0.1", "listen_port": 3003,
            "users": [{"uuid": UUID}],
            "transport": {"type": "ws", "path": "/vmess-argo"}, "sniff": True
        },
        {
            "type": "trojan", "tag": "trojan-ws-in", "listen": "127.0.0.1", "listen_port": 3004,
            "users": [{"password": UUID}],
            "transport": {"type": "ws", "path": "/trojan-argo"}, "sniff": True
        }
    ],
    "outbounds": [
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"}
    ],
    "route": {
        "rules": [
            {"inbound": ["http-in"], "outbound": "direct"},
            {"inbound": ["mixed-in", "vless-in", "vless-ws-in", "vmess-ws-in", "trojan-ws-in"], "outbound": "direct"}
        ]
    },
    "dns": {"servers": [{"address": "8.8.8.8", "detour": "direct"}]}
}

with open(configPath, 'w') as f:
    json.dump(config, f, indent=2)

def getSystemArchitecture():
    arch = platform.machine().lower()
    return 'arm' if 'arm' in arch or 'aarch64' in arch else 'amd'

def downloadFile(fileName, fileUrl):
    file_path = os.path.join(FILE_PATH, fileName)
    resp = requests.get(fileUrl, stream=True)
    resp.raise_for_status()
    with open(file_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
    logging.info(f"Download {fileName} successfully")

def downloadFilesAndRun():
    architecture = getSystemArchitecture()
    filesToDownload = [
        {"fileName": "sb", "fileUrl": f"https://{architecture}64.ssss.nyc.mn/sb"},
        {"fileName": "cfd", "fileUrl": f"https://{architecture}64.ssss.nyc.mn/2go"}
    ]
    
    for fileInfo in filesToDownload:
        downloadFile(fileInfo['fileName'], fileInfo['fileUrl'])
    
    # Authorize files
    for file in ['sb', 'cfd']:
        path = os.path.join(FILE_PATH, file)
        if os.path.exists(path):
            os.chmod(path, 0o775)
            logging.info(f"Empowerment success for {path}: 775")
    
    # ✅ 启动 CFD - Quick Tunnel 转发到 HTTP 8000
    cfd_path = os.path.join(FILE_PATH, 'cfd')
    if os.path.exists(cfd_path):
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', GOGO_AUTH):
            # Token 模式
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {GOGO_AUTH}"
        elif 'TunnelSecret' in GOGO_AUTH:
            # Named Tunnel - 关键修复在 argoType()
            args = f"tunnel --edge-ip-version auto --config {os.path.join(FILE_PATH, 'tunnel.yml')} run"
        else:
            # Quick Tunnel - ✅ 转发到 HTTP 8000
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {bootLogPath} --loglevel info --url http://localhost:{HTTP_PORT}"
        
        cfd_cmd = [cfd_path] + args.split()
        cfd_process = subprocess.Popen(cfd_cmd, stdout=sys.stdout, stderr=sys.stderr, text=True)
        logging.info(f"CFD process started with PID: {cfd_process.pid}")
        logging.info(f'CFD forwarding to HTTP port {HTTP_PORT}...')
        time.sleep(8)
    
    # 启动 sing-box
    logging.info('Starting sing-box')
    sb_process = subprocess.Popen(
        [os.path.join(FILE_PATH, 'sb'), 'run', '-c', configPath],
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )
    logging.info(f"Sing-box process started with PID: {sb_process.pid}")
    
    # 验证双端口
    time.sleep(3)
    if check_port(HTTP_PORT):
        logging.info(f"✅ HTTP port {HTTP_PORT} READY!")
    if check_port(GOGO_PORT):
        logging.info(f"✅ Mixed port {GOGO_PORT} READY!")
    logging.info('sing-box fully operational!')

# ✅ 终极修复：argoType() 中的端口错误
def argoType():
    if not GOGO_AUTH or not DOMAIN:
        logging.info("Using quick tunnels")
        return
    
    if 'TunnelSecret' in GOGO_AUTH:
        # ✅ 关键修复：写入 tunnel.json
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(GOGO_AUTH)
        
        # ✅ 关键修复：端口改为 8000（HTTP）
        tunnel_id = GOGO_AUTH.split('"')[11]
        tunnel_yaml = f"""tunnel: {tunnel_id}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2
ingress:
  - hostname: {DOMAIN}
    service: http://localhost:{HTTP_PORT}  # ✅ 修复：8000 而非 8001
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(tunnel_yaml)
        logging.info(f"✅ Named tunnel configured: {DOMAIN} -> localhost:{HTTP_PORT}")

def extractDomains():
    if GOGO_AUTH and DOMAIN:
        logging.info(f'DOMAIN: {DOMAIN}')
        generateLinks(DOMAIN)
        return
    
    try:
        with open(bootLogPath, 'r', encoding='utf-8') as f:
            content = f.read()
        match = re.search(r'https?://([^ ]*trycloudflare\.com)', content)
        if match:
            argoDomain = match.group(1)
            logging.info(f'ArgoDomain: {argoDomain}')
            generateLinks(argoDomain)
    except Exception as e:
        logging.info(f'Error reading boot.log: {e}')

def generateLinks(argoDomain):
    global ISP
    ISP = 'CF-Node'
    try:
        resp = requests.get('https://speed.cloudflare.com/meta', timeout=5)
        data = resp.json()
        ISP = f"{data.get('country')}-{data.get('asOrganization', '').replace(' ', '_')}"
        logging.info(f"ISP: {ISP}")
    except:
        pass
    
    VMESS = {
        "v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": CFPORT, "id": UUID,
        "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": argoDomain,
        "path": "/vmess-argo?ed=2560", "tls": "tls", "sni": argoDomain, "fp": "chrome"
    }
    
    subTxt = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argoDomain}&fp=chrome&type=ws&host={argoDomain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}
vmess://{base64.b64encode(json.dumps(VMESS).encode()).decode()}
trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argoDomain}&fp=chrome&type=ws&host={argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
"""
    
    with open(subPath, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(subTxt.encode()).decode())
    logging.info(f"{subPath} saved with ISP: {ISP}")

def main():
    logging.info("🚀 开始运行...")
    global servicesInitialized
    try:
        if not servicesInitialized:
            argoType()  # ✅ 修复 tunnel.yml 端口
            deleteNodes()
            cleanupOldFiles()
            downloadFilesAndRun()
            extractDomains()
            servicesInitialized = True
        
        if os.path.exists(subPath):
            with open(subPath, 'r', encoding='utf-8') as f:
                st.write(f.read())
        else:
            st.write("⏳ 生成订阅中...")
    except Exception as err:
        logging.error(f"Error: {err}", exc_info=True)

if __name__ == "__main__":
    main()
    sys.stdout.flush()

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
GOGO_PORT = int(os.environ.get('GOGO_PORT', 8001))
CFIP = os.environ.get('CFIP', 'cf.090227.xyz')
CFPORT = int(os.environ.get('CFPORT', 443))
NAME = os.environ.get('NAME', 'Streamlit')
# Paths
os.makedirs(FILE_PATH, exist_ok=True)
logging.info(f"{FILE_PATH} is created" if not os.path.exists(FILE_PATH) else f"{FILE_PATH} already exists")
npmPath = os.path.join(FILE_PATH, 'npm')
phpPath = os.path.join(FILE_PATH, 'php')
sbPath = os.path.join(FILE_PATH, 'sb')
webPath = os.path.join(FILE_PATH, 'cfd')
subPath = os.path.join(FILE_PATH, 'sub.txt')
listPath = os.path.join(FILE_PATH, 'list.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
configPath = os.path.join(FILE_PATH, 'config.json')
servicesInitialized = os.path.exists(subPath)
def deleteNodes():
    try:
        if not UPLOAD_URL:
            return
        if not os.path.exists(subPath):
            return
        with open(subPath, 'r', encoding='utf-8') as f:
            fileContent = f.read()
        decoded = base64.b64decode(fileContent).decode('utf-8')
        nodes = [line for line in decoded.split('\n') if re.match(r'(vless|vmess|trojan|hysteria2|tuic):\/\/', line)]
        if not nodes:
            return
        response = requests.post(f"{UPLOAD_URL}/api/delete-nodes", json={"nodes": nodes})
        logging.info(f"Delete nodes response: {response.status_code} - {response.text}")
    except Exception as e:
        logging.info(f"Error in deleteNodes: {e}")
def cleanupOldFiles():
    pathsToDelete = ['web', 'cfd', 'npm', 'php', 'sb', 'sub.txt', 'boot.log']
    for file in pathsToDelete:
        filePath = os.path.join(FILE_PATH, file)
        if os.path.exists(filePath):
            os.unlink(filePath)
            logging.info(f"Cleaned up {filePath}")
# Generate sb config
config = {
    "log": {
        "level": "info"  # ✅ 显示启动/连接日志
    },
    "inbounds": [
        {
            "type": "mixed",
            "listen": "::",
            "listen_port": GOGO_PORT,
            "sniff": True,
            "domain_strategy": "ipv4_only"
        },
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "127.0.0.1",
            "listen_port": 3001,
            "users": [
                {
                    "uuid": UUID,
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": False
            }
        },
        {
            "type": "vless",
            "tag": "vless-ws-in",
            "listen": "127.0.0.1",
            "listen_port": 3002,
            "users": [
                {
                    "uuid": UUID
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/vless-argo"
            },
            "sniff": True
        },
        {
            "type": "vmess",
            "tag": "vmess-ws-in",
            "listen": "127.0.0.1",
            "listen_port": 3003,
            "users": [
                {
                    "uuid": UUID,
                    "alter_id": 0
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/vmess-argo"
            },
            "sniff": True
        },
        {
            "type": "trojan",
            "tag": "trojan-ws-in",
            "listen": "127.0.0.1",
            "listen_port": 3004,
            "users": [
                {
                    "password": UUID
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/trojan-argo"
            },
            "sniff": True
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [
            {
                "inbound": ["vless-in", "vless-ws-in", "vmess-ws-in", "trojan-ws-in"],
                "outbound": "direct"
            }
        ]
    },
    "dns": {
        "servers": [
            {
                "address": "8.8.8.8",
                "detour": "direct"
            }
        ]
    }
}
with open(os.path.join(FILE_PATH, 'config.json'), 'w') as f:
    json.dump(config, f, indent=2)
def getSystemArchitecture():
    arch = platform.machine().lower()
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'
def downloadFile(fileName, fileUrl):
    file_path = os.path.join(FILE_PATH, fileName)
    resp = requests.get(fileUrl, stream=True)
    resp.raise_for_status()
    with open(file_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
    logging.info(f"Download {fileName} successfully")
    return fileName
def downloadFilesAndRun():
    architecture = getSystemArchitecture()
    filesToDownload = getFilesForArchitecture(architecture)
    if not filesToDownload:
        logging.info("Can't find a file for the current architecture")
        return
    for fileInfo in filesToDownload:
        try:
            downloadFile(fileInfo['fileName'], fileInfo['fileUrl'])
        except Exception as e:
            logging.info(f"Error downloading {fileInfo['fileName']}: {e}")
            return
    # Authorize files
    def authorizeFiles(filePaths):
        for relativeFilePath in filePaths:
            absoluteFilePath = os.path.join(FILE_PATH, filePaths)
            if os.path.exists(absoluteFilePath):
                os.chmod(absoluteFilePath, 0o775)
                logging.info(f"Empowerment success for {absoluteFilePath}: 775")
    filesToAuthorize = ['./npm', './sb', './cfd'] if NEZHA_PORT else ['./php', './sb', './cfd']
    authorizeFiles(filesToAuthorize)
    # Run cfd (cloudflared)
    cfd_path = os.path.join(FILE_PATH, 'cfd')
    if os.path.exists(cfd_path):
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', GOGO_AUTH):
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {GOGO_AUTH}"
        elif 'TunnelSecret' in GOGO_AUTH:
            args = f"tunnel --edge-ip-version auto --config {os.path.join(FILE_PATH, 'tunnel.yml')} run"
        else:
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {os.path.join(FILE_PATH, 'boot.log')} --loglevel info --url http://localhost:{GOGO_PORT}"
        cfd_cmd = [cfd_path] + args.split()
        cfd_process = subprocess.Popen(
            cfd_cmd,
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True
        )
        logging.info(f"CFD process started with PID: {cfd_process.pid}")
        logging.info('cfd is running')
        time.sleep(2)
    # Run sb - ✅ 修复：添加 -c config.json
    logging.info('Starting sb')
    sb_process = subprocess.Popen(
        [os.path.join(FILE_PATH, 'sb'), '-c', os.path.join(FILE_PATH, 'config.json')],  # ✅ 正确命令
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )
    logging.info(f"Sb process started with PID: {sb_process.pid}")
    logging.info('sb is running')
    time.sleep(5)
def getFilesForArchitecture(architecture):
    if architecture == 'arm':
        baseFiles = [
            {"fileName": "sb", "fileUrl": "https://arm64.ssss.nyc.mn/sb"},
            {"fileName": "cfd", "fileUrl": "https://arm64.ssss.nyc.mn/2go"}
        ]
    else:
        baseFiles = [
            {"fileName": "sb", "fileUrl": "https://amd64.ssss.nyc.mn/sb"},
            {"fileName": "cfd", "fileUrl": "https://amd64.ssss.nyc.mn/2go"}
        ]
    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT:
            npmUrl = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/agent"
            baseFiles.insert(0, {"fileName": "npm", "fileUrl": npmUrl})
        else:
            phpUrl = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/v1"
            baseFiles.insert(0, {"fileName": "php", "fileUrl": phpUrl})
    return baseFiles
def argoType():
    if not GOGO_AUTH or not DOMAIN:
        logging.info("DOMAIN or GOGO_AUTH variable is empty, use quick tunnels")
        return
    if 'TunnelSecret' in GOGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(GOGO_AUTH)
        tunnel_id = GOGO_AUTH.split('"')[11]
        tunnel_yaml = f"""tunnel: {tunnel_id}
  credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
  protocol: http2
 
  ingress:
    - hostname: {DOMAIN}
      service: http://localhost:{GOGO_PORT}
      originRequest:
        noTLSVerify: true
    - service: http_status:404
  """
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(tunnel_yaml)
    else:
        logging.info("GOGO_AUTH mismatch TunnelSecret,use token connect to tunnel")
def extractDomains():
    argoDomain = None
    if GOGO_AUTH and DOMAIN:
        argoDomain = DOMAIN
        logging.info(f'DOMAIN: {argoDomain}')
        generateLinks(argoDomain)
        return

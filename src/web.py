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
import tarfile
import shutil

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
PROJECT_URL = os.environ.get('PROJECT_URL', '')
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
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
NAME = os.environ.get('NAME', 'Sing-box')

# Paths
os.makedirs(FILE_PATH, exist_ok=True)
logging.info(f"{FILE_PATH} is created" if not os.path.exists(FILE_PATH) else f"{FILE_PATH} already exists")

phpPath = os.path.join(FILE_PATH, 'php')
singboxPath = os.path.join(FILE_PATH, 'sing-box')
cloudflaredPath = os.path.join(FILE_PATH, 'cloudflared')
subPath = os.path.join(FILE_PATH, 'sub.txt')
listPath = os.path.join(FILE_PATH, 'list.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
singboxConfigPath = os.path.join(FILE_PATH, 'sing-box.json')

servicesInitialized = os.path.exists(subPath)

def generate_singbox_config():
    """生成 sing-box 配置文件 - 支持 HTTP fallback + VLESS/VMess/Trojan"""
    config = {
        "log": {
            "level": "info"
        },
        "inbounds": [
            # ✅ HTTP fallback (Cloudflared 健康检查 - 监听 8001)
            {
                "type": "http",
                "tag": "http-in",
                "listen": "::",
                "listen_port": GOGO_PORT,
                "sniff": True
            },
            # ✅ VLESS WS (监听 127.0.0.1:8001)
            {
                "type": "vless",
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "listen_port": GOGO_PORT,
                "users": [
                    {
                        "uuid": UUID,
                        "flow": ""
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/vless-argo"
                },
                "tls": {
                    "enabled": False
                },
                "sniff": True,
                "sniff_override_destination": True
            },
            # ✅ VMess WS (监听 127.0.0.1:8001)
            {
                "type": "vmess",
                "tag": "vmess-in",
                "listen": "127.0.0.1",
                "listen_port": GOGO_PORT,
                "users": [
                    {
                        "id": UUID,
                        "alterId": 0
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/vmess-argo"
                },
                "sniff": True
            },
            # ✅ Trojan WS (监听 127.0.0.1:8001)
            {
                "type": "trojan",
                "tag": "trojan-in",
                "listen": "127.0.0.1",
                "listen_port": GOGO_PORT,
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
                # 代理流量直连
                {
                    "inbound": ["vless-in", "vmess-in", "trojan-in"],
                    "outbound": "direct"
                },
                # HTTP 健康检查丢弃
                {
                    "inbound": "http-in",
                    "outbound": "block"
                }
            ]
        }
    }
    return config

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
    pathsToDelete = [
        'sing-box',
        'cloudflared',
        'php',
        'sub.txt',
        'boot.log',
        'sing-box.json',
        'tunnel.yml',
        'tunnel.json'
    ]
    for file in pathsToDelete:
        filePath = os.path.join(FILE_PATH, file)
        if os.path.exists(filePath):
            os.unlink(filePath)
            logging.info(f"Cleaned up {filePath}")

def getSystemArchitecture():
    arch = platform.machine().lower()
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm64'
    return 'amd64'

def downloadAndExtractSingbox(architecture):
    """下载并解压 sing-box"""
    version = "1.12.11"
    tarball_name = f"sing-box-{version}-linux-{architecture}.tar.gz"
    tarball_url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{tarball_name}"
    tarball_path = os.path.join(FILE_PATH, tarball_name)
    extract_dir = os.path.join(FILE_PATH, "sing-box-temp")
   
    try:
        logging.info(f"Downloading sing-box {version} for {architecture}...")
       
        resp = requests.get(tarball_url, stream=True)
        resp.raise_for_status()
       
        with open(tarball_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Downloaded {tarball_name}")
       
        os.makedirs(extract_dir, exist_ok=True)
       
        with tarfile.open(tarball_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        logging.info(f"Extracted to {extract_dir}")
       
        for root, dirs, files in os.walk(extract_dir):
            if 'sing-box' in files:
                source_path = os.path.join(root, 'sing-box')
                shutil.move(source_path, singboxPath)
                os.chmod(singboxPath, 0o775)
                logging.info(f"Moved sing-box to {singboxPath} and set permissions")
                break
       
        shutil.rmtree(extract_dir)
        os.unlink(tarball_path)
        logging.info("Cleaned up temporary files")
       
        return True
       
    except Exception as e:
        logging.error(f"Error downloading/extracting sing-box: {e}")
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        if os.path.exists(tarball_path):
            os.unlink(tarball_path)
        return False

def downloadCloudflared(architecture):
    """下载官方 cloudflared 可执行文件"""
    version = "2025.10.0"
    filename = f"cloudflared-linux-{architecture}"
    url = f"https://github.com/cloudflare/cloudflared/releases/download/{version}/{filename}"
   
    try:
        logging.info(f"Downloading cloudflared {version} for {architecture}...")
        resp = requests.get(url, stream=True)
        resp.raise_for_status()
       
        with open(cloudflaredPath, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Downloaded {filename}")
       
        # 设置执行权限
        os.chmod(cloudflaredPath, 0o775)
        logging.info(f"Set permissions for {cloudflaredPath}: 775")
       
        return True
       
    except Exception as e:
        logging.error(f"Error downloading cloudflared: {e}")
        if os.path.exists(cloudflaredPath):
            os.unlink(cloudflaredPath)
        return False

def downloadFile(fileName, fileUrl):
    """下载单个文件（用于 php, npm）"""
    file_path = os.path.join(FILE_PATH, fileName)
    resp = requests.get(fileUrl, stream=True)
    resp.raise_for_status()
    with open(file_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
    os.chmod(file_path, 0o775) # 设置权限
    logging.info(f"Download {fileName} successfully")
    return fileName

def downloadFilesAndRun():
    """下载文件并启动服务 - 先 sing-box，后 cloudflared"""
    architecture = getSystemArchitecture()
   
    # 1. 下载并解压 sing-box
    if not downloadAndExtractSingbox(architecture):
        logging.error("Failed to download sing-box, aborting")
        return
   
    # 2. 下载 cloudflared
    if not downloadCloudflared(architecture):
        logging.error("Failed to download cloudflared, aborting")
        return
   
    # 3. 下载其他文件 (php/npm)
    otherFiles = []
    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT:
            npmUrl = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm64' else "https://amd64.ssss.nyc.mn/agent"
            otherFiles.append({"fileName": "npm", "fileUrl": npmUrl})
        else:
            phpUrl = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm64' else "https://amd64.ssss.nyc.mn/v1"
            otherFiles.append({"fileName": "php", "fileUrl": phpUrl})
   
    for fileInfo in otherFiles:
        try:
            downloadFile(fileInfo['fileName'], fileInfo['fileUrl'])
        except Exception as e:
            logging.info(f"Error downloading {fileInfo['fileName']}: {e}")
            return
   
    # 4. 生成 sing-box 配置
    config = generate_singbox_config()
    with open(singboxConfigPath, 'w') as f:
        json.dump(config, f, indent=2)
    logging.info("Sing-box config generated")
   
    # ✅ 5. 先启动 sing-box (等待 3 秒)
    logging.info('Starting sing-box...')
    singbox_process = subprocess.Popen(
        [singboxPath, 'run', '-c', singboxConfigPath],
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )
    logging.info(f"Sing-box process started with PID: {singbox_process.pid}")
    time.sleep(3)  # 等待 sing-box 完全启动
   
    # ✅ 6. 再启动 cloudflared
    if os.path.exists(cloudflaredPath):
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', GOGO_AUTH):
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {GOGO_AUTH}"
        elif 'TunnelSecret' in GOGO_AUTH:
            args = f"tunnel --edge-ip-version auto --config {os.path.join(FILE_PATH, 'tunnel.yml')} run"
        else:
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {bootLogPath} --loglevel info --url http://localhost:{GOGO_PORT}"
      
        cloudflared_cmd = [cloudflaredPath] + args.split()
        cloudflared_process = subprocess.Popen(
            cloudflared_cmd,
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True
        )
        logging.info(f"Cloudflared process started with PID: {cloudflared_process.pid}")
        logging.info('cloudflared is running')
        time.sleep(2)

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
    try:
        time.sleep(5)  # 等待 cloudflared 日志生成
        with open(bootLogPath, 'r', encoding='utf-8') as f:
            fileContent = f.read()
        lines = fileContent.split('\n')
        argoDomains = []
        for line in lines:
            match = re.search(r'https?://([^ ]*trycloudflare\.com)/?', line)
            if match:
                argoDomains.append(match.group(1))
        if argoDomains:
            argoDomain = argoDomains[0]
            logging.info(f'ArgoDomain: {argoDomain}')
            generateLinks(argoDomain)
        else:
            logging.info('ArgoDomain not found')
    except Exception as error:
        logging.info(f'Error reading boot.log: {error}')

def generateLinks(argoDomain):
    global ISP
    ISP = 'Unknown'
    try:
        resp = requests.get('https://speed.cloudflare.com/meta', timeout=5, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        logging.info(f"Speed.cloudflare meta response: {resp.status_code}")
        data = resp.json()
        if data.get('country') and data.get('asOrganization'):
            ISP = f"{data['country']}-{data['asOrganization']}".replace(' ', '_')
        else:
            ISP = data.get('country') or data.get('asOrganization') or 'CF-Node'
        logging.info(f"ISP from API: {ISP}")
    except Exception as e:
        logging.info(f"Error fetching meta via requests: {e}")
        ISP = os.environ.get('ISP_NAME', f"{NAME}-Node")
   
    # 生成 3 协议订阅链接
    vless_link = f"vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argoDomain}&fp=chrome&type=ws&host={argoDomain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}"
    
    vmess_obj = {
        "v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": str(CFPORT),
        "id": UUID, "aid": "0", "scy": "none", "net": "ws", "type": "none",
        "host": argoDomain, "path": "/vmess-argo?ed=2560", "tls": "tls",
        "sni": argoDomain, "alpn": "", "fp": "chrome"
    }
    vmess_link = f"vmess://{base64.b64encode(json.dumps(vmess_obj).encode('utf-8')).decode('utf-8')}"
    
    trojan_link = f"trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argoDomain}&fp=chrome&type=ws&host={argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}"
    
    subTxt = f"{vless_link}\n\n{vmess_link}\n\n{trojan_link}"
    
    with open(subPath, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(subTxt.encode('utf-8')).decode('utf-8'))
    logging.info(f"{FILE_PATH}/sub.txt saved successfully with ISP: {ISP}")
    uplodNodes()

def uplodNodes():
    if UPLOAD_URL and PROJECT_URL:
        subscriptionUrl = f"{PROJECT_URL}/{SUB_PATH}"
        jsonData = {"subscription": [subscriptionUrl]}
        try:
            resp = requests.post(f"{UPLOAD_URL}/api/add-subscriptions", json=jsonData)
            logging.info(f"Upload subscription response: {resp.status_code}")
            if resp.status_code == 200:
                logging.info('Subscription uploaded successfully')
        except Exception as error:
            logging.info(f"Upload error: {error}")
    else:
        logging.info('Skipping upload nodes')

def cleanFiles():
    time.sleep(90)
    filesToDelete = [
        bootLogPath,
        singboxConfigPath,
        singboxPath,
        cloudflaredPath,
        phpPath
    ]
    if NEZHA_PORT:
        npmPath = os.path.join(FILE_PATH, 'npm')
        filesToDelete.append(npmPath)
    elif NEZHA_SERVER and NEZHA_KEY:
        filesToDelete.append(phpPath)
   
    extra_files = ['tunnel.yml', 'tunnel.json']
    for extra in extra_files:
        extra_path = os.path.join(FILE_PATH, extra)
        if os.path.exists(extra_path):
            filesToDelete.append(extra_path)
   
    cmd = f"rm -rf {' '.join(filesToDelete)}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    logging.info(f"Clean files output: stdout={result.stdout}, stderr={result.stderr}")

def AddVisitTask():
    if not AUTO_ACCESS or not PROJECT_URL:
        logging.info("Skipping adding automatic access task")
        return
    try:
        resp = requests.post('https://oooo.serv00.net/add-url', json={"url": PROJECT_URL})
        logging.info(f"Add visit task response: {resp.status_code} - {resp.text}")
        logging.info("automatic access task added successfully")
    except Exception as error:
        logging.info(f"添加URL失败: {error}")

def main():
    logging.info("开始运行 Sing-box + Cloudflared 部署...")
    global servicesInitialized
    try:
        if not servicesInitialized:
            argoType()
            logging.info('初始化服务...')
            deleteNodes()
            cleanupOldFiles()
            downloadFilesAndRun()
            extractDomains()
            AddVisitTask()
            servicesInitialized = True
       
        # 显示订阅文件
        logging.info("读取订阅文件:")
        if os.path.exists(subPath):
            with open(subPath, 'r', encoding='utf-8') as f:
                subContent = f.read()
                st.code(subContent, language="text")
        else:
            st.write("⏳ 订阅文件生成中...")
            
    except Exception as err:
        logging.info(f"error: {err}", exc_info=True)

if __name__ == "__main__":
    main()
    sys.stdout.flush()

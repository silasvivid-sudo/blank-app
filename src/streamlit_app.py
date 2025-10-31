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
import threading
import random
import string

# 配置日志（仅输出到控制台的关键信息）
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Environment variables
UPLOAD_URL = os.environ.get('UPLOAD_URL', '')
PROJECT_URL = os.environ.get('PROJECT_URL', '')
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
FILE_PATH = os.environ.get('FILE_PATH', '/tmp/.cache')
SUB_PATH = os.environ.get('SUB_PATH', 'sub')
UUID = os.environ.get('ID', '1f6f5a40-80d0-4dbf-974d-4d53ff18d639')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')
ARGO_DOMAIN = os.environ.get('HOST', '')
ARGO_AUTH = os.environ.get('DATA', '')
ARGO_PORT = int(os.environ.get('PORT', 8001))
CFIP = os.environ.get('GOODIP', '194.53.53.7')
CFPORT = int(os.environ.get('GOODPORT', 443))
NAME = os.environ.get('NAME', '')

# Paths
os.makedirs(FILE_PATH, exist_ok=True)

# 全局路径（将在 main 中动态生成）
web_file_name = None
bot_file_name = None
webPath = None
botPath = None
subPath = os.path.join(FILE_PATH, 'sub.txt')
listPath = os.path.join(FILE_PATH, 'list.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
configPath = os.path.join(FILE_PATH, 'config.json')
npmPath = os.path.join(FILE_PATH, 'npm')
phpPath = os.path.join(FILE_PATH, 'php')

# ====================== 随机文件名生成 ======================
def generate_random_name(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ====================== 90秒后清理文件 ======================
def cleanFiles():
    time.sleep(90)
    filesToDelete = [bootLogPath, configPath, subPath, listPath]
    for path in [webPath, botPath, npmPath, phpPath]:
        if path and os.path.exists(path):
            filesToDelete.append(path)
    for ext in ['tunnel.json', 'tunnel.yml']:
        f = os.path.join(FILE_PATH, ext)
        if os.path.exists(f):
            filesToDelete.append(f)

    if filesToDelete:
        cmd = f"rm -f {' '.join(filesToDelete)}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info("Temporary files cleaned")

    logging.info('App is running')
    logging.info('Thank you for using this script, enjoy!')

# ====================== 其他函数 ======================
def deleteNodes():
    if not UPLOAD_URL or not os.path.exists(subPath):
        return
    try:
        with open(subPath, 'r', encoding='utf-8') as f:
            content = f.read()
        decoded = base64.b64decode(content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') if re.match(r'(vless|vmess|trojan|hysteria2|tuic):\/\/', line)]
        if nodes:
            requests.post(f"{UPLOAD_URL}/api/delete-nodes", json={"nodes": nodes}, timeout=10)
    except Exception as e:
        logging.info(f"deleteNodes error: {e}")

def cleanupOldFiles():
    safe_keep = {web_file_name, bot_file_name, 'sub.txt', 'boot.log', 'config.json', 'tunnel.json', 'tunnel.yml', 'npm', 'php'}
    for name in os.listdir(FILE_PATH):
        if name in safe_keep:
            continue
        fp = os.path.join(FILE_PATH, name)
        if os.path.isfile(fp) and os.access(fp, os.X_OK):
            try:
                os.unlink(fp)
                logging.info(f"Cleaned old executable: {name}")
            except:
                pass

# 生成 xray 配置
config = {
    "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
    "inbounds": [
        {
            "port": ARGO_PORT, "protocol": "vless",
            "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none",
                         "fallbacks": [{"dest": 3001}, {"path": "/vless-argo", "dest": 3002},
                                       {"path": "/vmess-argo", "dest": 3003}, {"path": "/trojan-argo", "dest": 3004}]},
            "streamSettings": {"network": "tcp"}
        },
        {"port": 3001, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"},
         "streamSettings": {"network": "tcp", "security": "none"}},
        {"port": 3002, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID, "level": 0}], "decryption": "none"},
         "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vless-argo"}},
         "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
        {"port": 3003, "listen": "127.0.0.1", "protocol": "vmess", "settings": {"clients": [{"id": UUID, "alterId": 0}]},
         "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-argo"}},
         "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
        {"port": 3004, "listen": "127.0.0.1", "protocol": "trojan", "settings": {"clients": [{"password": UUID}]},
         "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/trojan-argo"}},
         "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
    ],
    "dns": {"servers": ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"]},
    "routing": {"rules": [{"type": "field", "domain": ["v.com"], "outboundTag": "force-to-ip"}]},
    "outbounds": [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
        {"tag": "force-to-ip", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:0"}}
    ]
}
with open(configPath, 'w') as f:
    json.dump(config, f, indent=2)

def getSystemArchitecture():
    return 'arm' if 'arm' in platform.machine().lower() or 'aarch64' in platform.machine().lower() else 'amd'

def downloadFile(name, url):
    path = os.path.join(FILE_PATH, name)
    try:
        r = requests.get(url, stream=True, timeout=15)
        r.raise_for_status()
        with open(path, 'wb') as f:
            for c in r.iter_content(8192):
                f.write(c)
        os.chmod(path, 0o775)
        logging.info(f"Downloaded {name}")
    except Exception as e:
        logging.info(f"Download failed {name}: {e}")
        raise

def downloadFilesAndRun():
    global webPath, botPath, npmPath, phpPath
    arch = getSystemArchitecture()
    files = [
        {"fileName": web_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/web"},
        {"fileName": bot_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/2go"}
    ]
    agent_name = None
    if NEZHA_SERVER and NEZHA_KEY:
        agent = "agent" if NEZHA_PORT else "v1"
        agent_name = "npm" if NEZHA_PORT else "php"
        agent_path = os.path.join(FILE_PATH, agent_name)
        if agent_name == "npm":
            npmPath = agent_path
        else:
            phpPath = agent_path
        files.insert(0, {"fileName": agent_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/{agent}"})

    for f in files:
        downloadFile(f['fileName'], f['fileUrl'])

    # 静默启动 xray
    subprocess.Popen(
        [webPath, '-c', configPath],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    logging.info(f"{web_file_name} started")
    time.sleep(5)

    cfd_cmd = [botPath]
    if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", ARGO_AUTH]
    elif 'TunnelSecret' in ARGO_AUTH:
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--config", os.path.join(FILE_PATH, 'tunnel.yml'), "run"]
    else:
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
                    "--logfile", bootLogPath, "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"]

    # 静默启动 cloudflared
    subprocess.Popen(
        cfd_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    logging.info(f"{bot_file_name} started")
    time.sleep(2)

def argoType():
    if not ARGO_AUTH or not ARGO_DOMAIN:
        return
    if 'TunnelSecret' in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        try:
            tunnel_id = ARGO_AUTH.split('"')[11]
        except:
            tunnel_id = "unknown"
        yaml_content = f"""tunnel: {tunnel_id}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2
ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(yaml_content)

def extractARGO_DOMAINs():
    if ARGO_AUTH and ARGO_DOMAIN:
        generateLinks(ARGO_DOMAIN)
        return
    try:
        with open(bootLogPath, 'r', encoding='utf-8') as f:
            lines = f.read().split('\n')
        domains = [m.group(1) for line in lines if (m := re.search(r'https?://([^ ]*trycloudflare\.com)', line))]
        if domains:
            generateLinks(domains[0])
        else:
            raise ValueError("No domain")
    except:
        if os.path.exists(bootLogPath):
            os.unlink(bootLogPath)
        subprocess.run('pkill -f "[b]ot"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        cmd = f"nohup {botPath} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {bootLogPath} --loglevel info --url http://localhost:{ARGO_PORT} &"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        extractARGO_DOMAINs()

def generateLinks(argo_domain):
    ISP = 'Unknown'
    try:
        data = requests.get('https://speed.cloudflare.com/meta', timeout=5).json()
        ISP = f"{data.get('country','')}-{data.get('asOrganization','')}".replace(' ', '_') or 'CF-Node'
    except:
        try:
            ISP = subprocess.check_output(
                'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
                shell=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ).decode().strip() or 'CF-Node'
        except:
            ISP = f"{NAME}-Node"

    VMESS = {
        "v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": CFPORT, "id": UUID,
        "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": argo_domain,
        "path": "/vmess-argo?ed=2560", "tls": "tls", "sni": argo_domain, "alpn": "", "fp": "chrome"
    }
    raw = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}

vmess://{base64.b64encode(json.dumps(VMESS).encode()).decode()}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
"""
    b64_content = base64.b64encode(raw.encode('utf-8')).decode('utf-8')
    with open(subPath, 'w', encoding='utf-8') as f:
        f.write(b64_content)
    logging.info(f"Subscription saved (ISP: {ISP})")
    uplodNodes()

def uplodNodes():
    if UPLOAD_URL and PROJECT_URL:
        url = f"{PROJECT_URL}/{SUB_PATH}"
        try:
            requests.post(f"{UPLOAD_URL}/api/add-subscriptions", json={"subscription": [url]}, timeout=10)
            logging.info("Subscription URL uploaded")
        except Exception as e:
            logging.info(f"Upload sub URL error: {e}")
    elif UPLOAD_URL and os.path.exists(listPath):
        with open(listPath, 'r', encoding='utf-8') as f:
            content = f.read()
        nodes = [line for line in content.split('\n') if re.match(r'(vless|vmess|trojan|hysteria2|tuic):\/\/', line)]
        if nodes:
            try:
                requests.post(f"{UPLOAD_URL}/api/add-nodes", json={"nodes": nodes}, timeout=10)
                logging.info("Nodes uploaded")
            except Exception as e:
                logging.info(f"Upload nodes error: {e}")

def AddVisitTask():
    if AUTO_ACCESS and PROJECT_URL:
        try:
            requests.post('https://oooo.serv00.net/add-url', json={"url": PROJECT_URL}, timeout=5)
        except:
            pass

# ====================== Streamlit 界面 ======================
def check_id(user_input: str) -> bool:
    return user_input.strip() == UUID.strip()

def read_b64_subscription() -> str:
    if not os.path.exists(subPath):
        return ""
    try:
        with open(subPath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except:
        return ""

def main():
    global web_file_name, bot_file_name, webPath, botPath

    # 动态生成随机文件名
    web_file_name = generate_random_name(5)
    bot_file_name = generate_random_name(5)
    webPath = os.path.join(FILE_PATH, web_file_name)
    botPath = os.path.join(FILE_PATH, bot_file_name)

    st.set_page_config(page_title="订阅查看器", layout="centered")
    st.title("订阅信息查看器")
    st.markdown("---")

    if "id_verified" not in st.session_state:
        st.session_state.id_verified = False

    # ========== 1. sub.txt 不存在 → 自动初始化 ==========
    if not os.path.exists(subPath):
        with st.spinner("正在自动初始化服务，请稍候..."):
            try:
                argoType()
                deleteNodes()
                cleanupOldFiles()
                downloadFilesAndRun()
                extractARGO_DOMAINs()
                AddVisitTask()

                clean_thread = threading.Thread(target=cleanFiles, daemon=True)
                clean_thread.start()

                st.success("初始化完成！订阅已生成")
                st.info("页面刷新后请输入 UUID 查看")
                time.sleep(2)
                st.rerun()
            except Exception as e:
                st.error(f"初始化失败: {e}")
                logging.error(f"Auto init error: {e}", exc_info=True)
        return

    # ========== 2. sub.txt 存在 → 显示输入框 ==========
    if not st.session_state.id_verified:
        user_id = st.text_input(
            "请输入 UUID 以查看订阅",
            placeholder="例如: 1f6f5a40-80d0-4dbf-974d-4d53ff18d639",
            type="password",
            key="id_input"
        )
        if user_id and check_id(user_id):
            st.session_state.id_verified = True
            st.success("验证成功！")
            st.rerun()
        elif user_id:
            st.error("UUID 错误")
        else:
            st.info("请输入正确的 UUID 查看 base64 订阅")
        return

    # ========== 3. 显示 base64 内容 ==========
    b64_content = read_b64_subscription()
    if not b64_content:
        st.error("订阅内容为空")
        return

    st.subheader("订阅内容（Base64）")
    st.text_area("点击全选 → 复制", b64_content, height=150, key="b64_text")
    st.download_button(
        label="下载 sub.txt（推荐）",
        data=b64_content,
        file_name="sub.txt",
        mime="text/plain"
    )
    st.success("**已复制或下载！直接在 v2rayN → 订阅 → 从剪贴板/文件导入**")

if __name__ == "__main__":
    main()
    sys.stdout.flush()

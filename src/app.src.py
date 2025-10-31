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

# ====================== 配置 & 日志 ======================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# 环境变量
UPLOAD_URL = os.environ.get('UPLOAD_URL', '')
PROJECT_URL = os.environ.get('PROJECT_URL', '')
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
FILE_PATH = os.environ.get('FILE_PATH', '/tmp/.cache')
SUB_PATH = os.environ.get('SUB_PATH', 'sub')
UUID = os.environ.get('ID', '1f6f5a40-80d0-4dbf-974d-4d53ff18d639')
PASSWD = os.environ.get('PASSWD', 'admin123')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
NEZHA_KEY = os.environ.get('NEZHA_KEY', '')
ARGO_DOMAIN = os.environ.get('HOST', '')
ARGO_AUTH = os.environ.get('DATA', '')
ARGO_PORT = int(os.environ.get('PORT', 8001))
CFIP = os.environ.get('GOODIP', '194.53.53.7')
CFPORT = int(os.environ.get('GOODPORT', 443))
NAME = os.environ.get('NAME', '')

os.makedirs(FILE_PATH, exist_ok=True)

# 路径
subPath = os.path.join(FILE_PATH, 'sub.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
configPath = os.path.join(FILE_PATH, 'config.json')
npmPath = os.path.join(FILE_PATH, 'npm')
phpPath = os.path.join(FILE_PATH, 'php')
lockFile = os.path.join(FILE_PATH, 'service.lock')  # 永久保留


# ====================== 工具函数 ======================
def generate_random_name(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def check_passwd(user_input: str) -> bool:
    return user_input.strip() == PASSWD.strip()


# ====================== 永久内存缓存订阅 =======================
@st.cache_data(show_spinner=False)
def get_global_subscription(_domain: str) -> str:
    logging.info(f"Generating content for domain: {_domain}")
    ISP = 'Unknown'
    try:
        meta = requests.get('https://speed.cloudflare.com/meta', timeout=5).json()
        ISP = f"{meta.get('country','')}-{meta.get('asOrganization','')}".replace(' ', '_') or 'CF-Node'
    except:
        ISP = f"{NAME}-Node" if NAME else 'CF-Node'

    VMESS = {
        "v": "2", "ps": f"{NAME}-{ISP}", "add": CFIP, "port": CFPORT, "id": UUID,
        "aid": "0", "scy": "none", "net": "ws", "type": "none", "host": _domain,
        "path": "/vmess-argo?ed=2560", "tls": "tls", "sni": _domain, "alpn": "", "fp": "chrome"
    }
    raw = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={_domain}&fp=chrome&type=ws&host={_domain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}

vmess://{base64.b64encode(json.dumps(VMESS).encode()).decode()}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={_domain}&fp=chrome&type=ws&host={_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{NAME}-{ISP}
"""
    b64_content = base64.b64encode(raw.encode('utf-8')).decode('utf-8')

    # 临时写入 sub.txt（仅用于上传）
    try:
        with open(subPath, 'w', encoding='utf-8') as f:
            f.write(b64_content)
        if UPLOAD_URL and PROJECT_URL:
            try:
                requests.post(
                    f"{UPLOAD_URL}/api/add-subscriptions",
                    json={"subscription": [f"{PROJECT_URL}/{SUB_PATH}"]},
                    timeout=10
                )
                logging.info("Subscription URL uploaded")
            except Exception as e:
                logging.warning(f"Upload failed: {e}")
    except Exception as e:
        logging.warning(f"Failed to write sub.txt: {e}")

    return b64_content


# ====================== 全局服务启动（只看 lockFile）======================
@st.cache_resource(show_spinner="Starting global proxy service...")
def start_proxy_service_once():
    # === 关键：只看 lockFile 是否存在 ===
    if os.path.exists(lockFile):
        logging.info("Service already initialized (lockFile exists)")
        domain = ARGO_DOMAIN
        if not domain and os.path.exists(bootLogPath):
            try:
                with open(bootLogPath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if m := re.search(r'https?://([^ ]*trycloudflare\.com)', content):
                        domain = m.group(1)
            except:
                pass
        return domain or "unknown.trycloudflare.com"

    # === 初始化流程 ===
    web_file_name = generate_random_name(5)
    bot_file_name = generate_random_name(5)
    webPath = os.path.join(FILE_PATH, web_file_name)
    botPath = os.path.join(FILE_PATH, bot_file_name)

    # 1. 生成 xray 配置
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

    # 2. 下载文件
    arch = 'arm' if 'arm' in platform.machine().lower() or 'aarch64' in platform.machine().lower() else 'amd'
    files = [
        {"fileName": web_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/web"},
        {"fileName": bot_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/2go"}
    ]
    if NEZHA_SERVER and NEZHA_KEY:
        agent = "agent" if NEZHA_PORT else "v1"
        agent_name = "npm" if NEZHA_PORT else "php"
        agent_path = os.path.join(FILE_PATH, agent_name)
        if agent_name == "npm":
            globals()['npmPath'] = agent_path
        else:
            globals()['phpPath'] = agent_path
        files.insert(0, {"fileName": agent_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/{agent}"})

    for f in files:
        path = os.path.join(FILE_PATH, f['fileName'])
        r = requests.get(f['fileUrl'], stream=True, timeout=15)
        r.raise_for_status()
        with open(path, 'wb') as wf:
            for c in r.iter_content(8192):
                wf.write(c)
        os.chmod(path, 0o775)

    # 3. 启动 xray
    subprocess.Popen([webPath, '-c', configPath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)

    # 4. 启动 cloudflared
    cfd_cmd = [botPath]
    if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", ARGO_AUTH]
    elif 'TunnelSecret' in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        try:
            tunnel_id = json.loads(ARGO_AUTH).get("TunnelID") or ARGO_AUTH.split('"')[11]
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
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--config", os.path.join(FILE_PATH, 'tunnel.yml'), "run"]
    else:
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
                    "--logfile", bootLogPath, "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"]

    subprocess.Popen(cfd_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)

    # 5. 提取域名
    domain = ARGO_DOMAIN or _extract_argo_domain_from_log()

    # 6. 生成订阅
    get_global_subscription(domain)

    # 7. 创建 lockFile（永久保留）
    with open(lockFile, 'w') as f:
        f.write(str(int(time.time())))

    # 8. 访问任务
    if AUTO_ACCESS and PROJECT_URL:
        try:
            requests.post('https://oooo.serv00.net/add-url', json={"url": PROJECT_URL}, timeout=5)
        except:
            pass

    logging.info("GLOBAL SERVICE INITIALIZED (lockFile created - PERMANENT)")
    return domain


def _extract_argo_domain_from_log():
    for _ in range(15):
        if os.path.exists(bootLogPath):
            try:
                with open(bootLogPath, 'r', encoding='utf-8') as f:
                    for line in f.readlines():
                        if m := re.search(r'https?://([^ ]*trycloudflare\.com)', line):
                            return m.group(1)
            except:
                pass
        time.sleep(2)
    return "unknown.trycloudflare.com"


# ====================== 自动清理（90秒后，**不删 lockFile**）======================
def schedule_cleanup():
    def _cleanup():
        time.sleep(90)
        files = [bootLogPath, configPath, subPath]  # 不删 lockFile
        for path in [p for p in [globals().get('webPath'), globals().get('botPath'), npmPath, phpPath] if p and os.path.exists(p)]:
            files.append(path)
        for ext in ['tunnel.json', 'tunnel.yml']:
            f = os.path.join(FILE_PATH, ext)
            if os.path.exists(f):
                files.append(f)
        if files:
            subprocess.run(f"rm -f {' '.join(files)}", shell=True, stdout=subprocess.DEVNULL)
        logging.info("Temporary files cleaned (lockFile kept)")
    threading.Thread(target=_cleanup, daemon=True).start()


# ====================== 主界面 ======================
def main():
    st.set_page_config(page_title="Proxy Viewer", layout="centered")
    st.title("Proxy Node Viewer")
    st.markdown("---")

    # 初始化 session_state
    if "passwd_verified" not in st.session_state:
        st.session_state.passwd_verified = False
    if "argo_domain" not in st.session_state:
        st.session_state.argo_domain = None

    # === 1. 判断是否已初始化：只看 lockFile 是否存在 ===
    if not os.path.exists(lockFile):
        with st.spinner("Initializing global service (first user triggers)..."):
            try:
                domain = start_proxy_service_once()
                st.session_state.argo_domain = domain
                schedule_cleanup()  # 清理临时文件（不删 lockFile）
                st.success("Service initialized!")
                st.info("Refresh and enter password")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Init failed: {e}")
                logging.error(f"Service error: {e}", exc_info=True)
        return
    else:
        # lockFile 存在 → 服务已初始化
        if st.session_state.argo_domain is None:
            domain = ARGO_DOMAIN
            if not domain and os.path.exists(bootLogPath):
                try:
                    with open(bootLogPath, 'r') as f:
                        if m := re.search(r'https?://([^ ]*trycloudflare\.com)', f.read()):
                            domain = m.group(1)
                except:
                    pass
            st.session_state.argo_domain = domain or "unknown.trycloudflare.com"

    # === 2. 密码验证 ===
    if not st.session_state.passwd_verified:
        pwd = st.text_input("Enter password", type="password", placeholder="Default: admin123")
        if pwd:
            if check_passwd(pwd):
                st.session_state.passwd_verified = True
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Incorrect password")
        else:
            st.info("Please enter the correct password")
        return

    # === 3. 显示订阅（内存缓存）===
    b64_content = get_global_subscription(st.session_state.argo_domain)

    st.subheader("Subscription (Base64)")
    st.text_area("Click to select all", b64_content, height=150)
    st.download_button("Download sub.txt", b64_content, "sub.txt", "text/plain")
    st.success("Done!")

    if st.button("Force Refresh Cache (Admin)"):
        get_global_subscription.clear()
        st.success("Refreshing...")
        st.rerun()


if __name__ == "__main__":
    main()
    sys.stdout.flush()

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
UUID = os.environ.get('ID', '1f6f5a40-80d0-4dbf-974d-4d53ff18d639')  # 仍用于节点配置
PASSWD = os.environ.get('PASSWD', 'admin123')  # 新增：UI 登录密码
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


# ====================== 工具函数 ======================
def generate_random_name(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# 密码验证（用于 UI 登录）
def check_passwd(user_input: str) -> bool:
    return user_input.strip() == PASSWD.strip()


# ====================== 永久全局缓存订阅（直到重启）======================
@st.cache_data(show_spinner=False)
def get_global_subscription(_domain: str) -> str:
    logging.info(f"Generating GLOBAL subscription for domain: {_domain}")

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

    # 写入文件
    with open(subPath, 'w', encoding='utf-8') as f:
        f.write(b64_content)

    # 上传订阅链接
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

    logging.info(f"Subscription CACHED permanently (ISP: {ISP})")
    return b64_content


# ====================== 核心：服务启动（只一次）======================
@st.cache_resource(show_spinner="Starting proxy service...")
def start_proxy_service():
    web_file_name = generate_random_name(5)
    bot_file_name = generate_random_name(5)
    webPath = os.path.join(FILE_PATH, web_file_name)
    botPath = os.path.join(FILE_PATH, bot_file_name)

    # 1. 生成 xray 配置（仍使用 UUID）
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
        tunnel_id = ARGO_AUTH.split('"')[11] if len(ARGO_AUTH.split('"')) > 11 else "unknown"
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

    # 6. 触发永久缓存订阅
    get_global_subscription(domain)

    # 7. 访问任务
    if AUTO_ACCESS and PROJECT_URL:
        try:
            requests.post('https://oooo.serv00.net/add-url', json={"url": PROJECT_URL}, timeout=5)
        except:
            pass

    return domain, webPath, botPath


def _extract_argo_domain_from_log():
    for _ in range(15):
        if os.path.exists(bootLogPath):
            with open(bootLogPath, 'r', encoding='utf-8') as f:
                for line in f.readlines():
                    if m := re.search(r'https?://([^ ]*trycloudflare\.com)', line):
                        return m.group(1)
        time.sleep(2)
    raise ValueError("Failed to extract Argo domain from log")


# ====================== 自动清理（90秒后）======================
def schedule_cleanup():
    def _cleanup():
        time.sleep(90)
        files = [bootLogPath, configPath, subPath]
        for path in [p for p in [globals().get('webPath'), globals().get('botPath'), npmPath, phpPath] if p and os.path.exists(p)]:
            files.append(path)
        for ext in ['tunnel.json', 'tunnel.yml']:
            f = os.path.join(FILE_PATH, ext)
            if os.path.exists(f):
                files.append(f)
        if files:
            subprocess.run(f"rm -f {' '.join(files)}", shell=True, stdout=subprocess.DEVNULL)
        logging.info("Temporary files cleaned")
    threading.Thread(target=_cleanup, daemon=True).start()


# ====================== 主界面 ======================
def main():
    st.set_page_config(page_title="Viewer", layout="centered")
    st.title("Proxy Node Viewer")
    st.markdown("---")

    # 初始化 session_state
    for key in ["passwd_verified", "service_started", "cleanup_scheduled", "sub_cached"]:
        if key not in st.session_state:
            st.session_state[key] = False

    # === 1. 启动服务（只一次）===
    if not st.session_state.service_started:
        if not os.path.exists(subPath):
            with st.spinner("Initializing service (only once)..."):
                try:
                    domain, webPath, botPath = start_proxy_service()
                    st.session_state.service_started = True
                    st.session_state.argo_domain = domain
                    st.session_state.sub_cached = True

                    if not st.session_state.cleanup_scheduled:
                        schedule_cleanup()
                        st.session_state.cleanup_scheduled = True

                    st.success("Service started successfully!")
                    st.info("Refresh and enter password to view")
                    time.sleep(1)
                    st.rerun()
                except Exception as e:
                    st.error(f"Init failed: {e}")
                    logging.error(f"Service start error: {e}", exc_info=True)
            return
        else:
            st.session_state.service_started = True
            st.session_state.sub_cached = True

    # === 2. 密码验证（取代 UUID）===
    if not st.session_state.passwd_verified:
        user_passwd = st.text_input(
            "Enter password to view subscription",
            placeholder="Default: admin123 (set via PASSWD env)",
            type="password"
        )
        if user_passwd:
            if check_passwd(user_passwd):
                st.session_state.passwd_verified = True
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Incorrect password")
        else:
            st.info("Please enter the correct password")
        return

    # === 3. 显示订阅（从永久缓存读取）===
    if not st.session_state.sub_cached:
        st.warning("Subscription generating...")
        st.rerun()

    b64_content = get_global_subscription(st.session_state.argo_domain)

    st.subheader("Subscription Content (Base64)")
    st.text_area("Click to select all to Copy", b64_content, height=150)
    st.download_button(
        label="Download sub.txt (Recommended)",
        data=b64_content,
        file_name="sub.txt",
        mime="text/plain"
    )
    st.success("**Copied or downloaded! Import directly in v2rayN to From clipboard/file**")

    # === 管理员：强制刷新缓存 ===
    if st.button("Force Refresh Cache (Admin Only)"):
        get_global_subscription.clear()
        st.session_state.sub_cached = False
        st.success("Cache cleared, regenerating...")
        st.rerun()


if __name__ == "__main__":
    main()
    sys.stdout.flush()

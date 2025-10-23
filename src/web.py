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
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
singboxConfigPath = os.path.join(FILE_PATH, 'sing-box.json')

servicesInitialized = os.path.exists(subPath)

def generate_singbox_config():
    """生成 sing-box 配置文件 - ✅ VMess 修正"""
    config = {
        "log": {
            "level": "info"
        },
        "inbounds": [
            # HTTP fallback
            {
                "type": "http",
                "tag": "http-in",
                "listen": "::",
                "listen_port": GOGO_PORT,
                "sniff": True
            },
            # VLESS WS
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
            # VMess WS - ✅ 修正：id → uuid
            {
                "type": "vmess",
                "tag": "vmess-in",
                "listen": "127.0.0.1",
                "listen_port": GOGO_PORT,
                "users": [
                    {
                        "uuid": UUID,  # ✅ 正确！
                        "alterId": 0
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/vmess-argo"
                },
                "sniff": True
            },
            # Trojan WS
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
                {
                    "inbound": ["vless-in", "vmess-in", "trojan-in"],
                    "outbound": "direct"
                },
                {
                    "inbound": "http-in",
                    "outbound": "block"
                }
            ]
        }
    }
    return config

# ... 其他函数保持不变（deleteNodes, cleanupOldFiles, getSystemArchitecture, downloadAndExtractSingbox, downloadCloudflared, downloadFile, downloadFilesAndRun, argoType, extractDomains, generateLinks, uplodNodes, cleanFiles, AddVisitTask）

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

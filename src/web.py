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
        for relativeFilePath in filePaths:  # ✅ 修复：filePaths → filePath
            absoluteFilePath = os.path.join(FILE_PATH, relativeFilePath)  # ✅ 修复
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
    
    # Run sb - ✅ 最终正确命令
    logging.info('Starting sb')
    sb_process = subprocess.Popen(
        [os.path.join(FILE_PATH, 'sb'), 'run', '-c', os.path.join(FILE_PATH, 'config.json')],  # ✅ 正确！
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )
    logging.info(f"Sb process started with PID: {sb_process.pid}")
    logging.info('sb is running')
    time.sleep(5)

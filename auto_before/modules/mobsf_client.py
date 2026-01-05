import requests
import os
import time

# MobSF API를 다루는 클라이언트 클래스

class MobSFClient:
    def __init__(self, url, api_key):
        self.url = url
        self.headers = {"Authorization": api_key}

    # APK 업로드
    def upload(self, file_path):
        if not os.path.exists(file_path):
            print(f"[-] File not found: {file_path}")
            return None
            
        print(f"[*] Uploading: {os.path.basename(file_path)}")
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file, 'application/octet-stream')}
                res = requests.post(f"{self.url}/api/v1/upload", files=files, headers=self.headers)
                if res.status_code == 200:
                    return res.json()
                else:
                    print(f"[-] Upload failed with status {res.status_code}: {res.text}")
                    return None
        except Exception as e:
            print(f"[-] Upload Error: {e}")
        return None

    # 정적 분석 요청
    def scan_static(self, file_hash):
        print(f"[*] Static Scan: {file_hash}")
        try:
            res = requests.post(f"{self.url}/api/v1/scan", data={"hash": file_hash}, headers=self.headers)
            if res.status_code == 200:
                return res.json()
            else:
                print(f"[-] Static scan failed with status {res.status_code}: {res.text}")
                return None
        except Exception as e:
            print(f"[-] Static Scan Error: {e}")
            return None

    # 동적 분석 환경 시작
    def start_dynamic(self, file_hash):
        print("[*] Starting Dynamic Analysis Environment...")
        try:
            res = requests.post(f"{self.url}/api/v1/dynamic/start_analysis", data={"hash": file_hash}, headers=self.headers)
            if res.status_code == 200:
                print("[+] Environment Ready.")
                time.sleep(2)
                return True
            else:
                print(f"[-] Dynamic Start Failed with status {res.status_code}: {res.text}")
                return False
        except Exception as e:
            print(f"[-] Dynamic Start Error: {e}")
            return False

    # Frida 스크립트 주입
    # script_content : main.py 와 같은 경로에 존재하는 frida_script.js 파일의 내용
    def run_frida(self, file_hash, script_content):
        print("[*] Injecting Frida Scripts...")
        payload = {
        "hash": file_hash,
        "default_hooks": "api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass",
        "auxiliary_hooks": "",
        "frida_code": script_content,
        "frida_action": "spawn"
        }
        try:
            res = requests.post(f"{self.url}/api/v1/frida/instrument", data=payload, headers=self.headers)
            if res.status_code == 200:
                print("[+] Frida Script Injected.")
                time.sleep(5)
                return True
            else:
                print(f"[-] Frida Injection Failed with status {res.status_code}: {res.text}")
                return False
        except Exception as e:
            print(f"[-] Frida Injection Error: {e}")
            return False


    # 분석 종료 및 레포트 생성
    def stop_and_report(self, file_hash):
        print("[*] Stopping Analysis & Fetching Report...")
        try:
            requests.post(f"{self.url}/api/v1/dynamic/stop_analysis", data={"hash": file_hash}, headers=self.headers)
            time.sleep(3)
            res = requests.post(f"{self.url}/api/v1/dynamic/report_json", data={"hash": file_hash}, headers=self.headers)
            if res.status_code == 200:
                return res.json()
            else:
                print(f"[-] Report Generation Failed with status {res.status_code}: {res.text}")
                return None
        except Exception as e:
            print(f"[-] Report Generation Error: {e}")
            return None
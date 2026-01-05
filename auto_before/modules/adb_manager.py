import subprocess
import time
import os

class ADBManager:
    def __init__(self):
        self.device_id = None

    def wait_for_device(self, timeout=60):
        start = time.time()
        while time.time() - start < timeout:
            try:
                # [수정] 강제 재시작 없이 현재 상태만 조용히 체크
                res = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
                
                # 연결된 기기가 있는지 확인
                if "\tdevice" in res.stdout:
                    lines = res.stdout.strip().splitlines()
                    for line in lines:
                        if "\tdevice" in line:
                            self.device_id = line.split("\t")[0]
                            return True
            except Exception:
                pass
            
            time.sleep(1) # 1초 대기 (CPU 과부하 방지)
            
        return False

    def detect_device(self):
        # [수정] 무조건적인 start-server 제거. 연결 체크만 수행.
        return self.wait_for_device(timeout=10)


    def execute_command(self, cmd, timeout=60):
        if not self.device_id: return None
        full_cmd = f"adb -s {self.device_id} {cmd}"
        try:
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', timeout=timeout)
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except:
            return None

    def get_installed_packages(self):
        # wait_for_device 호출 시 불필요한 재시작을 안 하므로 안전함
        if not self.wait_for_device(timeout=10): 
            return set()
        out = self.execute_command(f"shell pm list packages -3")
        pkgs = set()
        if out:
            for line in out.splitlines():
                if line.startswith("package:"):
                    pkgs.add(line.split("package:")[1].strip())
        return pkgs
    
    def pull_apk(self, package_name, dest_dir):
         # (기존 코드 그대로)
        path_out = self.execute_command(f"shell pm path {package_name}")
        if not path_out: return None
        apk_path = None
        for line in path_out.splitlines():
            clean = line.replace("package:", "").strip()
            if "base.apk" in clean:
                apk_path = clean
                break
        if not apk_path and path_out:
            apk_path = path_out.splitlines()[0].replace("package:", "").strip()
        if not apk_path: return None
        local_path = os.path.join(dest_dir, f"{package_name}.apk")
        print(f"[*] Pulling APK: {package_name}")
        self.execute_command(f"pull {apk_path} \"{local_path}\"")
        if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
            return local_path
        return None
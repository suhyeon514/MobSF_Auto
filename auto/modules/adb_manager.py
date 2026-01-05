import subprocess
import time
import os
class ADBManager:
    def __init__(self):
        self.device_id = None

    # 활성화된 에뮬레이터/기기 감지 및 선택
    # ADB를 사용하여 연결된 기기 목록을 확인하고, 우선순위에 적합한 기기를 선택
    def detect_device(self):
        print("[*] Detecting active ADB device...")
        subprocess.run(['adb', 'start-server'], capture_output=True)
        
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, encoding='utf-8')
            lines = result.stdout.strip().splitlines()
            
            valid_devices = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'device':
                    valid_devices.append(parts[0])

            if not valid_devices:
                print("[-] No active devices found.")
                return None

            # emulator-5554 우선 순위
            target = valid_devices[0]
            for d in valid_devices:
                if "emulator-5554" in d:
                    target = d
                    break
            
            self.device_id = target
            print(f"[+] Active Device Selected: {self.device_id}")
            
            # TCPIP 모드 활성화 (선택 사항)
            self.execute_command("tcpip 5555")
            return self.device_id

        except Exception as e:
            print(f"[-] Device detection error: {e}")
            return None

    # ADB 명령어 실행 : 선택된 기기에서 ADB 명령어를 실행
    # - 기기가 선택되지 않은 경우 None을 반환
    # - 명령어 실행 중 타임아웃이나 기타 오류가 발생하면 로그를 출력
    def execute_command(self, cmd, timeout=60):
        if not self.device_id:
            return None
        full_cmd = f"adb -s {self.device_id} {cmd}"
        try:
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', timeout=timeout)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                print(f"[-] ADB Command Failed: {full_cmd}\n{result.stderr.strip()}")
                return None
        except subprocess.TimeoutExpired:
            print(f"[-] ADB Timeout: {cmd}")
        except Exception as e:
            print(f"[-] ADB Error: {e}")
        return None

    # 서드파티 패키지 목록 조회
    # 기기에 설치된 서드파티(사용자 설치) 패키지 목록을 반환.
    # 기기가 여러 개일 경우 선택된 기기에서만 조회
    # - ADB 명령어 'shell pm list packages -3'를 사용
    def get_installed_packages(self):
        if not self.device_id:
            print("[-] No device selected.")
            return set()

        # 특정 기기에서 패키지 목록 추출
        out = self.execute_command(f"shell pm list packages -3")
        if not out:
            print("[-] Failed to retrieve installed packages.")
            return set()
        
        pkgs = set()
        if out:
            for line in out.splitlines():
                if line.startswith("package:"):
                    pkgs.add(line.split("package:")[1].strip())
        return pkgs

    # 특정 패키지의 APK 추출
    # 주어진 패키지 이름에 해당하는 APK 파일을 기기에서 추출하여 로컬 디렉토리에 저장
     # [수정됨] 특정 패키지의 APK 추출 (Split APK 대응 및 OS 경로 호환성 강화)
    def pull_apk(self, package_name, dest_dir):
        path_out = self.execute_command(f"shell pm path {package_name}")
        if not path_out:
            print(f"[-] Failed to get APK path for: {package_name}")
            return None

        # [수정] 여러 줄(Split APK)이 나올 경우 처리 로직
        lines = path_out.strip().splitlines()
        apk_path_on_device = None
        
        for line in lines:
            clean_line = line.replace("package:", "").strip()
            # base.apk를 최우선으로 찾음
            if "base.apk" in clean_line:
                apk_path_on_device = clean_line
                break
        
        # base.apk가 없으면 첫 번째 줄 사용
        if not apk_path_on_device and lines:
            apk_path_on_device = lines[0].replace("package:", "").strip()

        if not apk_path_on_device:
            return None

        # [수정] Windows/Mac 경로 호환성을 위해 os.path.join 사용
        local_path = os.path.join(dest_dir, f"{package_name}.apk")
        
        print(f"[*] Pulling APK: {package_name}")
        
        # 큰 따옴표("")로 감싸서 경로에 공백이 있어도 처리 가능하게 함
        result = self.execute_command(f"pull {apk_path_on_device} \"{local_path}\"")
        
        # 실제로 파일이 생겼는지 확인
        if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
            return local_path
        else:
            print(f"[-] Failed to pull APK (File not found locally): {package_name}")
            return None

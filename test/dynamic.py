import requests
import time
import json
import os
import sys
from dotenv import load_dotenv


# 1. .env 파일 활성화 (같은 경로에 있는 .env를 읽어 시스템 환경변수처럼 만듦)
load_dotenv()

# 2. 환경변수 가져오기 (없으면 None 반환)
MOBSF_URL = os.getenv("MOBSF_URL")
API_KEY = os.getenv("API_KEY")
APK_PATH = os.getenv("APK_PATH")
REPORT_DIR = os.getenv("REPORT_DIR")

# 3. 필수 설정값 검증 (하나라도 없으면 시작 전에 경고 후 종료)
if not all([MOBSF_URL, API_KEY, APK_PATH, REPORT_DIR]):
    print("[-] Error: .env 파일에서 필수 설정값을 찾을 수 없습니다.")
    print("    (MOBSF_URL, API_KEY, APK_PATH, REPORT_DIR를 확인하세요.)")
    sys.exit(1)

HEADERS = {"Authorization": API_KEY}


# --- Helper Function: JS 파일 읽기 ---
def load_frida_script_from_file(file_path="frida_script.js"):
    """외부 JS 파일을 읽어 문자열로 반환합니다."""
    # 스크립트 파일이 현재 파이썬 파일과 같은 폴더에 있다고 가정
    base_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(base_dir, file_path)

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"[-] Frida script file not found at: {full_path}")
    
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()
    
# --- MobSF API Interaction Functions ---

# mobsf 서버에 파일 업로드, 업로드된 hash 값을 반환
def upload_file():
    """1. 파일 업로드"""
    print(f"[*] Uploading APK from: {APK_PATH}")
    
    if not os.path.exists(APK_PATH):
        print(f"[-] Error: 파일이 존재하지 않습니다: {APK_PATH}")
        return None

    try:
        # === [수정된 부분] ===
        # 단순히 open만 하는 것이 아니라, (파일명, 파일객체, MIME타입) 튜플 형태로 보냅니다.
        # 이렇게 해야 MobSF가 "아, 이게 sample.apk 파일이구나"라고 인식합니다.
        file_name = os.path.basename(APK_PATH)  # 경로에서 'sample.apk'만 추출
        
        files = {
            'file': (file_name, open(APK_PATH, 'rb'), 'application/octet-stream')
        }
        # ===================

        response = requests.post(f"{MOBSF_URL}/api/v1/upload", files=files, headers=HEADERS)
        
        # 디버깅: 성공하면 200 OK와 json 데이터가 나와야 함
        if response.status_code != 200:
            print(f"[Debug] Upload Failed: {response.text}")
        
        return response.json()
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return {}

# 2. 정적 분석 수행, hash 값을 인자로 받아 정적 분석 요청
def static_scan(file_hash):
    """2. 정적 분석 수행 (동적 분석 전 필수)"""
    print("[*] Starting Static Scan...")
    data = {"hash": file_hash}
    response = requests.post(f"{MOBSF_URL}/api/v1/scan", data=data, headers=HEADERS)
    return response.json()

# 3. 동적 분석 환경 구동 (에뮬레이터 연동)
def start_dynamic_analysis(file_hash):
    """3. 동적 분석 환경 구동 (에뮬레이터 연동)"""
    print("[*] Starting Dynamic Analysis Environment...")
    data = {"hash": file_hash}
    # 이 API는 에뮬레이터를 준비시키고 앱을 설치합니다.
    response = requests.post(f"{MOBSF_URL}/api/v1/dynamic/start_analysis", data=data, headers=HEADERS)
    if response.status_code == 200:
        print("[+] Dynamic Analysis Started.")
    else:
        print("[-] Failed to start dynamic analysis.")
    time.sleep(5) # 에뮬레이터 구동 대기


'''
{"error": "Missing Parameters"} 
1. MobSF API (/api/v1/frida/instrument)는 필수 파라미터를 엄격하게 체크
2. auxiliary_hooks 의 파라미터가 빠져 있어서 서버가 요청을 거부
3. run_frida_instrumentation 함수 내의 payload 부분에 누락된 키를 추가
'''
def run_frida_instrumentation(file_hash):
    print("[*] Injecting Custom Frida Scripts...")
    
    """4. Frida 스크립트 주입 (외부 파일 사용)"""
    print("[*] Injecting Custom Frida Scripts from file...")
    
    try:
        # [핵심] 외부 .js 파일을 읽어와서 변수에 담습니다.
        custom_frida_script = load_frida_script_from_file("frida_script.js")
    except Exception as e:
        print(f"[-] Script Loading Error: {e}")
        return
    

    # 2. API 전송을 위한 Payload 구성
    # frida_code 파라미터에 위에서 만든 변수를 넣습니다.
    # [수정] 빠진 파라미터(auxiliary_hooks, frida_action)를 반드시 포함해야 함
    frida_payload = {
        "hash": file_hash,
        "default_hooks": "api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass",
        "auxiliary_hooks": "",    # <--- [중요] 비어있더라도 이 키가 없으면 에러 발생
        "frida_code": custom_frida_script,
        "frida_action": "spawn"   # <--- [권장] 명시적으로 지정 (spawn: 앱 시작시 후킹)
    }

    # 2. API 전송을 위한 Payload 구성
    # frida_code 파라미터에 위에서 만든 변수를 넣습니다.
    # frida_payload = {
    #     "hash": file_hash,
    #     "default_hooks": "api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass",
    #     "frida_code": custom_frida_script  # <--- 여기에 들어갑니다!
    # }
    
    # 3. MobSF API 호출
    response = requests.post(
        f"{MOBSF_URL}/api/v1/frida/instrument", 
        data=frida_payload, 
        headers=HEADERS
    )
    
    
    if response.status_code == 200:
        print("[+] Custom Frida Script Injected Successfully.")
    else:
        # 에러 메시지를 상세히 출력
        print(f"[-] Frida Injection Failed: {response.text}")
    
   
    # 후킹이 적용될 시간을 벌어줍니다.
    time.sleep(15)


def perform_automated_actions(file_hash):
    """5. 사용자 개입 없는 자동화 액션 수행"""
    print("[*] Performing Automated Actions...")
    
    # 예: Exported Activity 강제 실행 테스트
    activity_payload = {"hash": file_hash, "test": "exported"}

    requests.post(f"{MOBSF_URL}/api/v1/android/activity", data=activity_payload, headers=HEADERS)
    
    # 예: ADB 명령어로 랜덤 터치 이벤트 발생 (Monkey Test 유사 효과)
    # 실제로는 좌표를 계산하거나 특정 시나리오대로 tap 이벤트를 보냄
    # requests.post(f"{MOBSF_URL}/api/v1/android/adb_command", data={"cmd": "shell input tap 500 500"}, headers=HEADERS)
    
    print("[*] Collecting data for 30 seconds...")
    time.sleep(60) # 충분한 로그 수집 시간 부여

def stop_and_report(file_hash):
    """6. 분석 종료 및 결과 리포트 생성 + 지정된 경로에 저장"""
    print("[*] Stopping Analysis...")
    requests.post(f"{MOBSF_URL}/api/v1/dynamic/stop_analysis", data={"hash": file_hash}, headers=HEADERS)
    
    print("[*] Generating JSON Report...")
    response = requests.post(f"{MOBSF_URL}/api/v1/dynamic/report_json", data={"hash": file_hash}, headers=HEADERS)
    
    if response.status_code == 200:
        report = response.json()
        print("[+] Dynamic Analysis Complete.")

        # 1. 저장할 폴더가 없으면 자동으로 생성
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
            print(f"[*] Created directory: {REPORT_DIR}")

        # 2. 경로와 파일명 합치기 (os.path.join이 운영체제에 맞게 \ 또는 / 를 붙여줌)
        # 파일명에 해시값을 넣으면 덮어쓰기 방지 가능: f"result_{file_hash}.json"
        output_file_name = "dynamic_result.json"
        full_path = os.path.join(REPORT_DIR, output_file_name)

        # 3. 파일 저장
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        
        # 절대 경로로 출력해서 확실히 알려줌
        print(f"[+] Report saved to: {os.path.abspath(full_path)}")
        
        return report
    
    print("[-] Failed to generate report.")
    return None

# --- Main Execution Flow ---
if __name__ == "__main__":
    try:
        # Step 1: Upload
        upload_res = upload_file()


        # 업로드 실패 시 'hash' 키가 없으므로 체크
        if upload_res and 'hash' in upload_res:
            file_hash = upload_res['hash']
            print(f"[+] File Hash: {file_hash}")
            
            # Step 2: Static Scan
            static_scan(file_hash)
            
            # Step 3: Dynamic Start
            start_dynamic_analysis(file_hash)
            
            # Step 4: Frida Instrument (파일에서 읽어와서 주입)
            run_frida_instrumentation(file_hash)
            
            # Step 5: Automated Input
            perform_automated_actions(file_hash)
            
            # Step 6: Stop & Report
            stop_and_report(file_hash)
        else:
            print("[-] Upload failed or invalid response. Aborting.")
        
    except Exception as e:
        print(f"[-] Error occurred: {e}")
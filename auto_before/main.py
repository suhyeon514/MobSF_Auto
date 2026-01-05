import os
import sys
import time
import threading
import traceback
import frida
from datetime import datetime

# 사용자 모듈
from modules.adb_manager import ADBManager
from modules.mobsf_client import MobSFClient
from utils.file_handler import save_json, load_file_content
# 1. 상단 import에 추가
from config import (
    MOBSF_URL, API_KEY, APK_PATH, DIRS, WAIT_TIME, 
    TARGET_PACKAGES, TARGET_KEYWORD  # <--- 추가
)

def log(tag, message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {message}")

# =============================================================================
# [Thread] 서브 앱 감시자 (소켓 재사용 & 최적화 버전)
# =============================================================================
class SubAppHooker(threading.Thread):
    def __init__(self):
        super().__init__()
        self.running = True
        self.daemon = True
        self.device = None
        self.active_sessions = []
        self.hooked_pids = set()

        # 2. 하드코딩 제거하고 config 변수 사용
        self.target_packages = TARGET_PACKAGES
        self.target_keyword = TARGET_KEYWORD
        self.script_file = "hook_sub.js"

    def run(self):
        log("HOOKER", "감시 스레드 대기 중... (소켓 안정화)")
        time.sleep(5) # 초기 안정화 대기
        
        log("HOOKER", f"감시 시작 (Target: '{self.target_keyword}')")
        
        while self.running:
            try:
                # 1. 디바이스 연결 (연결이 없을 때만 수행 - 소켓 절약)
                if self.device is None:
                    try:
                        # MobSF가 서버를 켜둔 상태라고 가정하고 연결 시도
                        self.device = frida.get_usb_device(timeout=3)
                        log("CONN", "✅ Frida 서버 연결됨 (세션 유지 모드)")
                    except:
                        # 아직 서버가 없으면 5초 대기 (무리한 재접속 방지)
                        time.sleep(5)
                        continue

                # 2. 프로세스 스캔 (연결된 객체 재사용)
                if self.device:
                    try:
                        # 현재 실행 중인 프로세스 목록 가져오기
                        processes = self.device.enumerate_processes()
                        
                        for p in processes:
                            # 키워드 매칭 & 중복 후킹 방지
                            if self.target_keyword in p.name and p.pid not in self.hooked_pids:
                                log("SCAN", f"🔎 타겟 프로세스 발견! -> {p.name} (PID: {p.pid})")
                                self.inject_hook(p.pid, p.name)
                                
                    except frida.ServerNotRunningError:
                        log("WARN", "Frida 서버 끊김. 재연결 시도...")
                        self.device = None # 객체 초기화하여 재연결 유도
                    except Exception as e:
                        # 기타 에러 시 잠시 대기
                        pass
                
                # [중요] 루프 대기 시간을 3초로 늘려 소켓 반환 시간 확보
                time.sleep(3) 

            except Exception as e:
                log("ERR", f"스레드 예외: {e}")
                time.sleep(5)

    def inject_hook(self, pid, ident):
        try:
            self.hooked_pids.add(pid)
            log("INJECT", f"💉 {ident} 후킹 주입 시도...")
            
            # 연결된 device 객체 사용 (새 연결 안 만듦)
            session = self.device.attach(pid)
            self.active_sessions.append(session)
            
            js_code = load_file_content(self.script_file)
            if not js_code:
                js_code = "console.log('[ERROR] hook_sub.js missing');"

            script = session.create_script(js_code)
            script.on('message', self.on_message)
            script.load()
            
            # 이미 실행 중일 수 있으므로 resume 에러는 무시
            try: self.device.resume(pid)
            except: pass
            
            log("SUCCESS", f"🎉 {ident} 후킹 성공! (Logs Active)")

        except Exception as e:
            log("ERROR", f"후킹 실패 ({ident}): {e}")
            # 실패 시 다시 시도할 수 있게 PID 제거
            if pid in self.hooked_pids:
                self.hooked_pids.remove(pid)

    def on_message(self, message, data):
        if message['type'] == 'send':
            log("JS_LOG", message['payload'])
        elif message['type'] == 'error':
            log("JS_ERR", message['stack'])

    def stop(self):
        self.running = False
        # 종료 시 세션 정리 (TCP 소켓 반환)
        for s in self.active_sessions:
            try: s.detach()
            except: pass
        self.active_sessions.clear()
        self.hooked_pids.clear()
        self.device = None

# =============================================================================
# Main
# =============================================================================
def main():
    print("\n" + "="*60)
    print("      MobSF Automation (Socket Optimized)")
    print("="*60 + "\n")

    # 0. 이전 실행의 소켓 찌꺼기가 남았을 수 있으므로 대기
    log("INIT", "소켓 안정화 대기 (3초)...")
    time.sleep(3)

    adb = ADBManager()
    if not adb.detect_device():
        log("FATAL", "ADB 디바이스 없음")
        sys.exit(1)

    mobsf = MobSFClient(MOBSF_URL, API_KEY)
    apk_name = os.path.splitext(os.path.basename(APK_PATH))[0]

    # 감시자 준비 (아직 Start 안함)
    hooker = SubAppHooker()

    try:
        baseline_pkgs = adb.get_installed_packages()

        # 1. 업로드 (대량의 소켓 사용)
        log("STEP_1", "APK 업로드 중...")
        upload_res = mobsf.upload(APK_PATH)
        if not upload_res: raise Exception("Upload Failed")
        
        file_hash = upload_res['hash']
        main_pkg = upload_res.get('package_name')
        
        save_json(DIRS['STATIC'], f"upload_{apk_name}.json", upload_res)
        mobsf.scan_static(file_hash)
        
        # 소켓 쿨타임
        time.sleep(2)

        # 2. 동적 분석 시작
        log("STEP_2", "동적 분석 환경 초기화...")
        if mobsf.start_dynamic(file_hash):
            log("INFO", "✅ 환경 준비 완료.")
            
            # [시점 중요] MobSF가 서버 켠 직후에 감시자 투입
            hooker.start()
            
            log("HOOK_MAIN", "메인 앱 후킹 (MobSF)")
            frida_code = load_file_content("hook_main.js")
            mobsf.run_frida(file_hash, frida_code)
            
            print("\n" + "*"*50)
            print(f"[*] 대기 시간: {WAIT_TIME}초")
            print("[*] ⚠️ 지금 서브 앱을 실행하세요.")
            print("[*] 3초 주기로 스캔하여 자동으로 후킹합니다.")
            print("*"*50 + "\n")

            for i in range(WAIT_TIME):
                time.sleep(1)
                if i > 0 and i % 10 == 0:
                    log("PROGRESS", f"{i}/{WAIT_TIME}s")

            check_dropped_apks(adb, mobsf, baseline_pkgs, main_pkg)
            mobsf.stop_and_report(file_hash)
            log("SUCCESS", "분석 완료.")

    except KeyboardInterrupt:
        log("ABORT", "중단됨.")
    except Exception as e:
        log("FATAL", f"오류: {e}")
        traceback.print_exc()
    finally:
        hooker.stop()
        log("EXIT", "종료.")

def check_dropped_apks(adb, mobsf, baseline, main_pkg):
    log("CHECK", "추가 앱 확인 중...")
    current = adb.get_installed_packages()
    new_pkgs = current - baseline
    if main_pkg in new_pkgs: new_pkgs.remove(main_pkg)
    
    if new_pkgs:
        log("DETECT", f"발견됨: {new_pkgs}")
        for pkg in new_pkgs:
            local_path = adb.pull_apk(pkg, DIRS['DROPPED'])
            if local_path:
                res = mobsf.upload(local_path)
                mobsf.scan_static(res['hash'])

if __name__ == "__main__":
    main()
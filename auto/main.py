import os
import sys
import time
from config import MOBSF_URL, API_KEY, APK_PATH, DIRS, WAIT_TIME
from modules.adb_manager import ADBManager
from modules.mobsf_client import MobSFClient
from utils.file_handler import save_json, load_file_content

# 메인 실행 함수, 전반적인 분석 흐름 제어

def main():
    # 1. 초기화 (ADB & MobSF)
    adb = ADBManager()
    if not adb.detect_device():
        sys.exit(1)

    mobsf = MobSFClient(MOBSF_URL, API_KEY)
    apk_name = os.path.splitext(os.path.basename(APK_PATH))[0]

    try:
        # 2. Baseline 패키지 수집 (Dropped APK 비교용)
        print("[*] Capturing baseline packages...")
        baseline_pkgs = adb.get_installed_packages()

        # 3. 메인 APK 업로드 및 정적 분석
        upload_res = mobsf.upload(APK_PATH)
        if not upload_res:
            sys.exit(1)
        
        file_hash = upload_res['hash']
        main_pkg = upload_res.get('package_name')
        save_json(DIRS['STATIC'], f"upload_{apk_name}.json", upload_res)

        static_res = mobsf.scan_static(file_hash)
        save_json(DIRS['STATIC'], f"static_{apk_name}.json", static_res)

        time.sleep(5)  # MobSF 처리 대기, OS가 포트를 정리할 시간을 줌

        # 4. 동적 분석 & Frida
        if mobsf.start_dynamic(file_hash):
            frida_code = load_file_content("frida_script.js") or "console.log('No script');"
            mobsf.run_frida(file_hash, frida_code) # Frida 스크립트 주입

            # 5. 사용자 상호작용 대기 -> 설치된 APK 에서 사용자가 조작 수행하는 것을 대기
            print(f"[*] Waiting {WAIT_TIME}s for User Interaction...")
            time.sleep(WAIT_TIME)

            # 6. Dropped APK 처리
            check_dropped_apks(adb, mobsf, baseline_pkgs, main_pkg)

            # 7. 종료 및 결과 저장
            dynamic_report = mobsf.stop_and_report(file_hash)
            if dynamic_report:
                save_json(DIRS['DYNAMIC'], f"dynamic_{apk_name}.json", dynamic_report)
        
        # 패키지 기록 저장
        save_json(DIRS['PACKAGES'], "package_history.json", {"installed": list(adb.get_installed_packages())})
        print("\n[SUCCESS] Analysis Chain Completed.")

    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
    except Exception as e:
        print(f"\n[-] Critical Error: {e}")
        import traceback
        traceback.print_exc()

# 추가로 설치된 APK 감지 및 분석
def check_dropped_apks(adb, mobsf, baseline, main_pkg):
    print("\n" + "="*40)
    print("[*] Checking for Dropped APKs...")
    current = adb.get_installed_packages()
    new_pkgs = current - baseline
    
    if main_pkg in new_pkgs:
        new_pkgs.remove(main_pkg)

    if not new_pkgs:
        print("[-] No dropped APKs detected.")
    else:
        print(f"[!] New packages detected: {new_pkgs}")
        for pkg in new_pkgs:
            local_path = adb.pull_apk(pkg, DIRS['DROPPED'])
            if local_path:
                dropped_res = mobsf.upload(local_path)
                if dropped_res:
                    # Dropped APK는 정적 분석만 수행 (필요 시 동적 분석 추가 가능)
                    res = mobsf.scan_static(dropped_res['hash'])
                    save_json(DIRS['STATIC'], f"static_{pkg}.json", res)
    print("="*40 + "\n")

if __name__ == "__main__":
    main()
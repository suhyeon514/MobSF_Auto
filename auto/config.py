import os
from dotenv import load_dotenv

# 설정 파일

# 환경 변수 로드
load_dotenv()

# --- Configuration ---
MOBSF_URL = os.getenv("MOBSF_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY")
APK_PATH = os.getenv("APK_PATH")
WAIT_TIME = int(os.getenv("WAIT_TIME", 60))

# ---- API 키 검증 --- 
if not API_KEY or not APK_PATH:
    raise ValueError("[-] Error: .env 파일 내 API_KEY 및 APK_PATH 설정이 필요합니다.")

HEADERS = {"Authorization": API_KEY}

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIRS = {
    "STATIC": os.path.join(BASE_DIR, "static_reports"),
    "DYNAMIC": os.path.join(BASE_DIR, "dynamic_reports"),
    "PACKAGES": os.path.join(BASE_DIR, "installed_packages"),
    "DROPPED": os.path.join(BASE_DIR, "dropped_apks"),
}

# 디렉토리 자동 생성
for d in DIRS.values():
    os.makedirs(d, exist_ok=True)
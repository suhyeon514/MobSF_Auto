# 🛡️ MobSF Automated Security Analysis Tool

MobSF(Mobile Security Framework)를 활용한 Android APK **정적(Static) 및 동적(Dynamic) 분석 자동화 도구**

## ✨ Key Features
- **Automated Workflow**: APK 업로드 → 정적 분석 → 동적 분석 → 결과 리포트 저장을 원클릭으로 수행
- **Hybrid Environment Support**: Docker 기반 MobSF와 로컬 설치 MobSF 모두 지원
- **Frida Injection**: 사용자 정의 Frida 스크립트(`frida_script.js`) 자동 주입 및 후킹
- **Dropped APK Detection**: 분석 도중 기기에 새로 설치되거나 생성된 악성 APK를 탐지하고 추출하여 재분석

## 🛠️ Prerequisites
이 도구를 사용하기 위해 다음 환경이 필요함

1. **Python 3.8+**
2. **MobSF (Mobile Security Framework)**
   - [Docker 방식] 또는 [Local 설치] 모두 가능
   - MobSF 서버 정상 실행 필수 (기본: `http://localhost:8000`)
3. **ADB (Android Debug Bridge)**
   - 시스템 환경 변수(PATH)에 등록 필요
4. **Android Emulator / Device**
   - 루팅된 에뮬레이터 정상 동작 확인 필수 (Genymotion, Android Studio AVD 등)
5. **Setup (.env)** 
    
        ```# MobSF 서버 주소
        MOBSF_URL=http://localhost:8000

        # MobSF API Key (MobSF 대시보드 -> API Docs에서 확인 가능)
        API_KEY=YOUR_MOBSF_API_KEY_HERE

        # 분석할 APK 파일 경로 (절대 경로 권장)
        APK_PATH=C:/Path/To/Your/App.apk

        # 동적 분석 대기 시간 (초)
        WAIT_TIME=60
        ```

## 🚀 Usage
1. MobSF 서버 실행 (Docker 또는 Local)
2. 에뮬레이터 실행 및 ADB 연결 확인
3. 분석 시작
   ```bash
    python main.py
    ```


## 📂 Project Structure
    ```.
    ├── config.py              # 환경 설정 및 경로 관리
    ├── main.py                # 프로그램 진입점 (Main workflow)
    ├── frida_script.js        # Frida 후킹 스크립트
    ├── .env                   # API 키 및 설정 (Git 제외 대상)
    ├── modules/               # 핵심 기능 모듈
    │   ├── adb_manager.py     # ADB 제어 및 기기 관리
    │   └── mobsf_client.py    # MobSF API 통신
    ├── utils/                 # 유틸리티
    │   └── file_handler.py    # 파일 입출력 처리
    ├── static_reports/        # 정적 분석 결과 저장소
    └── dynamic_reports/       # 동적 분석 결과 저장소
    ```


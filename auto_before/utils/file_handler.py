import json
import os

# JSON 데이터를 파일로 저장할 때 사용하는 유틸 함수

def save_json(directory, filename, data):
    """JSON 데이터를 파일로 저장"""
    path = os.path.join(directory, filename)
    try:
        # 디렉토리가 없으면 생성
        os.makedirs(directory, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"[+] Report Saved: {path}")
        return True
    except Exception as e:
        print(f"[-] Save Error ({filename}): {e}")
        return False
    
# 파일 내용을 문자열로 로드 (없으면 None 반환)
def load_file_content(filepath):

    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"[-] Read Error ({filepath}): {e}")
        return None
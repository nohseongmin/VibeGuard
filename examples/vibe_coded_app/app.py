"""
데모용 '바이브코딩 결과물' 예시 앱.

AI 어시스턴트에게 "사용자 메모를 저장하는 간단한 Flask API 만들어줘" 라고 시켜
나온 듯한, 빠르게 동작하지만 보안 결함이 가득한 코드를 모사한 것이다.
VibeGuard 가 어떤 문제를 잡는지 보여주는 의도적 취약 코드이며, 실제 키는 모두 가짜다.
"""

import os
import sqlite3
import subprocess
import hashlib
import random
import pickle

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# (취약) API 키를 코드에 그대로 하드코딩
OPENAI_API_KEY = "sk-abc123FAKEfakeFAKEfake1234567890abcdEFGH"
DB_PASSWORD = "admin1234"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def get_db():
    return sqlite3.connect("notes.db")


@app.route("/notes")
def list_notes():
    # (취약) f-string 으로 SQL 조립 -> SQL 인젝션
    user_id = request.args.get("user_id")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM notes WHERE user_id = {user_id}")
    return jsonify(cur.fetchall())


@app.route("/hash")
def make_hash():
    # (취약) 비밀번호를 MD5 로 해시
    pw = request.args.get("pw", "")
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/token")
def make_token():
    # (취약) 예측 가능한 난수로 토큰 생성
    return str(random.randint(100000, 999999))


@app.route("/ping")
def ping():
    # (취약) 사용자 입력을 셸 명령으로 실행 -> 명령어 주입
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/fetch")
def fetch():
    # (취약) TLS 검증 비활성화
    url = request.args.get("url")
    return requests.get(url, verify=False).text


@app.route("/load")
def load_state():
    # (취약) 신뢰할 수 없는 데이터를 pickle 로 역직렬화
    data = request.data
    return str(pickle.loads(data))


if __name__ == "__main__":
    # (취약) 디버그 모드 + 모든 인터페이스 바인딩
    app.run(host="0.0.0.0", port=5000, debug=True)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2T4P 작업일보 사내망 서버.

같은 폴더의 '작업일보.html'을 사내망에 제공하고, 일보와 사용자 정보를 파일로 저장한다.
파이썬 표준 라이브러리만 사용하므로 추가 설치가 필요 없다 (Python 3.8 이상).

실행:
    python server.py                       # 8080 포트, 이 폴더의 data 폴더에 저장
    python server.py --port 80 --data "D:\\작업일보데이터"
    python server.py --data "\\\\파일서버\\공유폴더\\작업일보"   # 다른 PC에서 실행하고 파일서버에 저장

접속: http://<서버 이름 또는 IP>:<포트>/
처음 접속한 사람이 운영자 계정을 만든다. 이후 운영자가 '사용자 관리'에서 사번을 등록한다.

저장 구조 (data 폴더):
    users.json                 사용자 (비밀번호는 해시로만 저장)
    reports/2026-01-31.json    하루 일보 1개 = 파일 1개
    history/                   덮어쓰거나 삭제하기 직전의 일보 사본
"""
# --- 필요한 도구 불러오기 (모두 파이썬에 기본으로 들어 있어 따로 설치할 것이 없습니다) ---
# argparse=실행 옵션(--port 등) 읽기, hashlib/hmac=비밀번호 암호화, json=데이터 파일 읽고 쓰기,
# os=폴더와 파일 다루기, re=글자 모양 검사, secrets=추측할 수 없는 무작위 값 만들기, threading=여러 사람 동시 처리, time=시간
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

# --- 기본 설정값 ---
# BASE = 이 server.py 파일이 들어 있는 폴더, PAGE = 화면 파일 이름
BASE = os.path.dirname(os.path.abspath(__file__))
PAGE = "작업일보.html"
# PAGE_HEAD = 화면 파일 앞에 붙여 보내는 머리말(한글 깨짐 방지, 휴대폰 화면 맞춤, 숨김 규칙).
# 작업일보.html 에는 이 부분이 없어서, 서버가 내보낼 때 붙여 줍니다.
PAGE_HEAD = (
    '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
    "<style>:root{color-scheme:light}body{margin:0;font:14px system-ui,sans-serif}"
    "img{max-width:100%}[hidden]{display:none!important}</style></head><body>"
)
# STATIC_DIRS = 브라우저에 내줘도 되는 폴더와 파일 종류(글꼴, 엑셀 읽기 도구). 여기 없는 파일(예: data 폴더)은 절대 내주지 않습니다.
STATIC_DIRS = {"fonts": {".otf": "font/otf", ".ttf": "font/ttf", ".woff2": "font/woff2"},
               "vendor": {".js": "text/javascript; charset=utf-8"}}
# DATE_RE = 날짜가 2026-01-31 모양인지 검사하는 규칙, ID_RE = 사번에 쓸 수 있는 글자(영문, 숫자, _ . -) 규칙
DATE_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
# MAX_BODY = 한 번에 받을 수 있는 최대 크기(512KB), SESSION_TTL = 로그인 유지 시간(12시간),
# PBKDF2_ROUNDS = 비밀번호를 암호화할 때 반복하는 횟수(많을수록 뚫기 어려움), MIN_PW = 비밀번호 최소 길이
MAX_BODY = 512 * 1024
SESSION_TTL = 12 * 3600
PBKDF2_ROUNDS = 200_000
MIN_PW = 6


# 현재 시각을 2026-01-31T14:05:00 모양의 글자로 만듭니다(저장 시각 기록용).
def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# 비밀번호를 되돌릴 수 없는 암호문(해시)으로 바꿉니다. 파일에는 이 암호문만 저장하므로, 파일을 열어 봐도 원래 비밀번호는 알 수 없습니다.
# salt 는 사람마다 다르게 섞는 무작위 값으로, 같은 비밀번호라도 암호문이 다르게 나오게 합니다.
def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()


# 요청을 거절할 때 쓰는 오류. status = 거절 번호(401=로그인 필요, 403=권한 없음, 404=없음 등), message = 화면에 보여 줄 안내 문구
class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# =====================================================================
# Store = 데이터 창고. 일보와 사용자 정보를 파일로 읽고 쓰는 일을 모두 맡습니다.
# =====================================================================
class Store:
    """파일 저장소. 모든 접근은 lock 안에서 한다."""

    # 서버가 켜질 때 한 번 실행: data 폴더(없으면 만듦)에서 사용자와 일보를 모두 읽어 기억해 둡니다.
    def __init__(self, data_dir):
        self.dir = data_dir
        self.reports_dir = os.path.join(data_dir, "reports")
        self.history_dir = os.path.join(data_dir, "history")
        self.users_file = os.path.join(data_dir, "users.json")
        for d in (self.reports_dir, self.history_dir):
            os.makedirs(d, exist_ok=True)
        self.lock = threading.RLock()
        self.rev = int(time.time())  # 일보가 바뀔 때마다 증가. 화면은 이 값이 바뀌었을 때만 다시 받는다
        self.users = self._read(self.users_file, {})
        self.reports = {}
        for name in sorted(os.listdir(self.reports_dir)):
            key = name[:-5]
            if name.endswith(".json") and DATE_RE.match(key):
                doc = self._read(os.path.join(self.reports_dir, name), None)
                if isinstance(doc, dict):
                    self.reports[key] = doc
        self.sessions = {}
        self.fails = {}

    @staticmethod
    # 파일 하나를 읽습니다. 파일이 없거나 깨져 있으면 기본값을 돌려주고 서버는 계속 돌아갑니다.
    def _read(path, default):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return default
        except (OSError, ValueError) as e:
            print("경고: %s 을(를) 읽지 못했습니다: %s" % (path, e), file=sys.stderr)
            return default

    @staticmethod
    # 파일 하나를 안전하게 씁니다. 임시 파일에 먼저 다 쓴 뒤 이름을 바꾸는 방식이라, 쓰는 도중 전원이 나가도 기존 파일이 깨지지 않습니다.
    def _write(path, obj):
        tmp = "%s.%s.tmp" % (path, secrets.token_hex(4))
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # ----- 일보 -----
    # 일보를 덮어쓰거나 지우기 직전에, 원래 내용을 history 폴더에 사본으로 남깁니다(실수했을 때 복구용).
    def _keep_history(self, date):
        old = self.reports.get(date)
        if old is not None:
            self._write(os.path.join(self.history_dir, "%s_%s.json" % (date, time.strftime("%Y%m%d-%H%M%S"))), old)

    # 일보 저장: 사본 남기기 → 날짜, 저장 시각, 저장한 사람 기록 → reports/날짜.json 파일로 쓰기 → 변경 번호(rev) 올리기
    def put_report(self, date, doc, user):
        with self.lock:
            self._keep_history(date)
            doc["date"] = date
            doc["updatedAt"] = now_iso()
            doc["updatedBy"] = {"id": user["id"], "name": user["name"]}
            self._write(os.path.join(self.reports_dir, date + ".json"), doc)
            self.reports[date] = doc
            self.rev += 1

    # 일보 삭제: 사본을 남긴 뒤 파일을 지웁니다.
    def delete_report(self, date):
        with self.lock:
            if date not in self.reports:
                return
            self._keep_history(date)
            try:
                os.remove(os.path.join(self.reports_dir, date + ".json"))
            except FileNotFoundError:
                pass
            del self.reports[date]
            self.rev += 1

    # ----- 사용자 -----
    # 사용자 목록을 users.json 파일에 씁니다.
    def _save_users(self):
        self._write(self.users_file, self.users)

    # 화면으로 보내도 되는 사용자 정보만 골라 줍니다(비밀번호 암호문은 절대 보내지 않음).
    def public_user(self, uid):
        u = self.users[uid]
        return {"id": uid, "name": u["name"], "role": u["role"], "active": u.get("active", True), "created": u.get("created", ""),
                "crew": u.get("crew", "")}  # crew = 소속 조 (A/B/C, 없으면 빈 값)

    # 새 사용자를 등록합니다. role 은 admin(운영자), manager(관리자), user(현장관리자) 중 하나. 운영자만 사용자 관리와 일보 삭제를 할 수 있습니다.
    def set_user(self, uid, name, password, role, crew=""):
        salt = secrets.token_hex(16)
        self.users[uid] = {"name": name, "role": role, "salt": salt, "hash": hash_pw(password, salt),
                           "active": True, "created": now_iso(), "crew": crew}
        self._save_users()

    # 비밀번호를 바꿉니다(새 salt 로 다시 암호화).
    def set_password(self, uid, password):
        salt = secrets.token_hex(16)
        self.users[uid].update(salt=salt, hash=hash_pw(password, salt))
        self._save_users()

    # 입력한 비밀번호가 맞는지 확인합니다. 입력값을 같은 방법으로 암호화해서 저장된 암호문과 비교합니다.
    def check_password(self, uid, password):
        u = self.users.get(uid)
        if not u:
            hash_pw(password, "00" * 16)  # 없는 사번도 같은 시간이 걸리게 한다
            return False
        return hmac.compare_digest(u["hash"], hash_pw(password, u["salt"]))

    # 사용 중인 운영자 목록. "운영자가 한 명은 남아 있어야 한다"는 규칙을 검사할 때 씁니다.
    def active_admins(self, without=None):
        return [i for i, u in self.users.items() if u["role"] == "admin" and u.get("active", True) and i != without]

    # ----- 로그인 세션 (메모리에만 둔다. 서버를 다시 켜면 다시 로그인) -----
    # 로그인 성공 시 "출입증"(무작위 긴 글자)을 발급합니다. 브라우저는 이후 요청마다 이 출입증을 함께 보냅니다.
    def new_session(self, uid):
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {"id": uid, "exp": time.time() + SESSION_TTL}
        return token

    # 출입증을 보고 누구인지 알려 줍니다. 12시간이 지났거나, 삭제/사용 중지된 사용자면 무효로 처리합니다.
    def session_user(self, token):
        s = self.sessions.get(token or "")
        if not s:
            return None
        if s["exp"] < time.time() or s["id"] not in self.users or not self.users[s["id"]].get("active", True):
            self.sessions.pop(token, None)
            return None
        s["exp"] = time.time() + SESSION_TTL
        return self.public_user(s["id"])

    # 그 사용자의 출입증을 모두 무효로 만듭니다(강제 로그아웃). 비밀번호 초기화, 사용 중지, 삭제 때 씁니다.
    def drop_sessions(self, uid):
        for t in [t for t, s in self.sessions.items() if s["id"] == uid]:
            del self.sessions[t]

    # 같은 PC에서 10분 안에 로그인을 10번 틀리면 잠시 막습니다(비밀번호를 계속 찍어 보는 시도 방지).
    def login_blocked(self, ip):
        recent = [t for t in self.fails.get(ip, []) if t > time.time() - 600]
        self.fails[ip] = recent
        return len(recent) >= 10


# =====================================================================
# Handler = 창구 직원. 브라우저에서 요청이 올 때마다 무엇을 원하는지 보고 처리합니다.
# =====================================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "Ilbo/1.0"
    store = None

    # 검은 창에 기록을 남깁니다. 단순 조회(GET)는 너무 많아서 생략하고, 저장/삭제/로그인 같은 요청만 남깁니다.
    def log_message(self, fmt, *args):
        if self.command != "GET":
            sys.stderr.write("%s %s %s\n" % (time.strftime("%m-%d %H:%M:%S"), self.client_address[0], fmt % args))

    # ----- 응답 -----
    # 브라우저로 답을 보냅니다(공통 부분). no-store = 브라우저가 옛 내용을 기억해 두지 말고 항상 새로 받게 함
    def send_bytes(self, status, body, ctype, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # 데이터(JSON 형식)로 답을 보냅니다.
    def send_json(self, obj, status=200, extra=None):
        self.send_bytes(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", extra)

    # ----- 요청 -----
    # 브라우저가 보낸 쿠키에서 출입증(ilbo=...)을 꺼냅니다.
    def token(self):
        m = re.search(r"(?:^|;\s*)ilbo=([A-Za-z0-9_\-]+)", self.headers.get("Cookie", ""))
        return m.group(1) if m else None

    # 브라우저가 보낸 내용(일보, 사번/비밀번호 등)을 읽습니다. 너무 크거나 형식이 틀리면 거절합니다.
    def body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n > MAX_BODY:
            raise ApiError(413, "보낸 내용이 너무 큽니다.")
        try:
            obj = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
        except ValueError:
            raise ApiError(400, "잘못된 요청입니다.")
        if not isinstance(obj, dict):
            raise ApiError(400, "잘못된 요청입니다.")
        return obj

    # 로그인했는지 확인합니다. admin=True 면 운영자인지도 확인합니다. 아니면 거절(401 또는 403).
    def need_user(self, admin=False):
        user = self.store.session_user(self.token())
        if not user:
            raise ApiError(401, "로그인이 필요합니다.")
        if admin and user["role"] != "admin":
            raise ApiError(403, "운영자만 할 수 있습니다.")
        return user

    # 모든 요청이 처음 들어오는 곳. 주소가 /api/ 로 시작하면 데이터 요청(api), 아니면 화면/글꼴 파일 요청(static)으로 보냅니다.
    # 처리 중 문제가 생기면 서버가 멈추지 않고 그 요청에만 오류 답을 보냅니다.
    def dispatch(self):
        url = urlparse(self.path)
        path = unquote(url.path)
        try:
            if path.startswith("/api/"):
                if self.command != "GET" and self.headers.get("X-Requested-With") != "ilbo":
                    raise ApiError(400, "잘못된 요청입니다.")
                with self.store.lock:
                    self.api(path[5:].strip("/").split("/"), parse_qs(url.query))
            elif self.command == "GET":
                self.static(path)
            else:
                raise ApiError(404, "없는 주소입니다.")
        except ApiError as e:
            self.send_json({"error": e.message}, e.status)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # noqa: BLE001 - 한 요청의 오류가 서버를 멈추지 않게 한다
            print("오류:", repr(e), file=sys.stderr)
            self.send_json({"error": "서버 오류가 발생했습니다."}, 500)

    # 조회(GET), 보내기(POST), 저장(PUT), 삭제(DELETE) 요청 모두 위 dispatch 가 받습니다.
    do_GET = do_POST = do_PUT = do_DELETE = dispatch

    # 화면 파일과 글꼴 등을 내줍니다. 주소가 / 이면 작업일보.html 앞뒤에 머리말/꼬리말을 붙여 보냅니다.
    def static(self, path):
        if path in ("/", "/index.html"):
            with open(os.path.join(BASE, PAGE), "rb") as f:
                self.send_bytes(200, PAGE_HEAD.encode("utf-8") + f.read() + b"</body></html>", "text/html; charset=utf-8")
            return
        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] in STATIC_DIRS:
            name = os.path.basename(parts[1])
            ctype = STATIC_DIRS[parts[0]].get(os.path.splitext(name)[1].lower())
            full = os.path.join(BASE, parts[0], name)
            if ctype and os.path.isfile(full):
                with open(full, "rb") as f:
                    self.send_bytes(200, f.read(), ctype, {"Cache-Control": "max-age=86400"})
                return
        raise ApiError(404, "없는 주소입니다.")

    # ----- API -----
    # 데이터 요청 처리. p 는 주소를 / 로 나눈 것입니다. 예: /api/reports/2026-01-31 → ["reports", "2026-01-31"]
    def api(self, p, query):
        st, m = self.store, self.command
        # GET /api/me : "나 로그인되어 있나요?" → 로그인한 사용자 정보와, 사용자가 한 명도 없는지(setup) 알려 줌
        if p == ["me"] and m == "GET":
            return self.send_json({"setup": not st.users, "user": st.session_user(self.token())})

        # POST /api/setup : 처음 한 번만 가능한 운영자 계정 만들기. 사용자가 이미 있으면 거절
        if p == ["setup"] and m == "POST":
            if st.users:
                raise ApiError(403, "이미 운영자 계정이 있습니다.")
            b = self.body()
            uid, name, pw = self.clean_id(b.get("id")), self.clean_name(b.get("name")), self.clean_pw(b.get("password"))
            st.set_user(uid, name, pw, "admin")
            return self.login_ok(uid)

        # POST /api/login : 로그인. 사번/비밀번호가 맞고 사용 중인 계정이면 출입증 발급
        if p == ["login"] and m == "POST":
            ip = self.client_address[0]
            if st.login_blocked(ip):
                raise ApiError(429, "로그인 실패가 많습니다. 10분 뒤에 다시 시도하세요.")
            b = self.body()
            uid, pw = str(b.get("id", "")).strip(), str(b.get("password", ""))
            if not st.check_password(uid, pw) or not st.users[uid].get("active", True):
                st.fails.setdefault(ip, []).append(time.time())
                raise ApiError(401, "사번 또는 비밀번호가 맞지 않습니다.")
            return self.login_ok(uid)

        # POST /api/logout : 로그아웃. 출입증을 없앰
        if p == ["logout"] and m == "POST":
            st.sessions.pop(self.token() or "", None)
            return self.send_json({"ok": True}, extra={"Set-Cookie": "ilbo=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})

        # POST /api/password : 본인 비밀번호 변경. 현재 비밀번호가 맞아야 함
        if p == ["password"] and m == "POST":
            user = self.need_user()
            b = self.body()
            if not st.check_password(user["id"], str(b.get("old", ""))):
                raise ApiError(400, "현재 비밀번호가 맞지 않습니다.")
            st.set_password(user["id"], self.clean_pw(b.get("new")))
            return self.send_json({"ok": True})

        # GET /api/reports : 일보 전체 받기(로그인 필요). 화면이 가진 변경 번호(rev)와 같으면 "바뀐 것 없음"만 답함
        if p == ["reports"] and m == "GET":
            self.need_user()
            if query.get("rev", [""])[0] == str(st.rev):
                return self.send_json({"rev": st.rev, "unchanged": True})
            return self.send_json({"rev": st.rev, "reports": st.reports})

        # PUT /api/reports/날짜 : 일보 저장(로그인한 누구나),  DELETE /api/reports/날짜 : 일보 삭제(운영자만)
        if len(p) == 2 and p[0] == "reports" and m in ("PUT", "DELETE"):
            if not DATE_RE.match(p[1]):
                raise ApiError(400, "날짜 형식이 맞지 않습니다.")
            if m == "PUT":
                user = self.need_user()
                st.put_report(p[1], self.body(), user)
            else:
                self.need_user(admin=True)
                st.delete_report(p[1])
            return self.send_json({"ok": True, "rev": st.rev})

        # GET /api/users : 사용자 목록(운영자만)
        if p == ["users"] and m == "GET":
            self.need_user(admin=True)
            return self.send_json({"users": [st.public_user(i) for i in sorted(st.users)]})

        # POST /api/users : 새 사번 등록(운영자만). 이미 있는 사번이면 거절
        if p == ["users"] and m == "POST":
            self.need_user(admin=True)
            b = self.body()
            uid = self.clean_id(b.get("id"))
            if uid in st.users:
                raise ApiError(409, "이미 등록된 사번입니다.")
            role, crew = self.clean_role(b.get("role")), self.clean_crew(b.get("crew", ""))
            if role == "user" and not crew:  # 현장관리자는 소속 조가 있어야 본인 조의 불량 유형을 볼 수 있다
                raise ApiError(400, "현장관리자는 소속 조를 선택해야 합니다.")
            st.set_user(uid, self.clean_name(b.get("name")), self.clean_pw(b.get("password")), role, crew)
            return self.send_json({"ok": True})

        # POST /api/users/사번 : 이름, 권한, 사용 여부, 비밀번호 바꾸기,  DELETE /api/users/사번 : 사용자 삭제 (둘 다 운영자만)
        # 본인 삭제와 마지막 운영자를 없애는 변경은 막습니다.
        if len(p) == 2 and p[0] == "users" and m in ("POST", "DELETE"):
            me = self.need_user(admin=True)
            uid = p[1]
            if uid not in st.users:
                raise ApiError(404, "없는 사번입니다.")
            if m == "DELETE":
                if uid == me["id"]:
                    raise ApiError(400, "본인 계정은 삭제할 수 없습니다.")
                if not st.active_admins(without=uid):
                    raise ApiError(400, "운영자가 한 명은 남아 있어야 합니다.")
                del st.users[uid]
                st._save_users()
                st.drop_sessions(uid)
                return self.send_json({"ok": True})
            b = self.body()
            u = st.users[uid]
            if "name" in b:
                u["name"] = self.clean_name(b["name"])
            if "crew" in b:
                u["crew"] = self.clean_crew(b["crew"])
            if "role" in b or "active" in b:
                role = self.clean_role(b.get("role", u["role"]))
                active = bool(b.get("active", u.get("active", True)))
                if (role != "admin" or not active) and not st.active_admins(without=uid):
                    raise ApiError(400, "운영자가 한 명은 남아 있어야 합니다.")
                u["role"], u["active"] = role, active
                if not active:
                    st.drop_sessions(uid)
            st._save_users()
            if "password" in b:
                st.set_password(uid, self.clean_pw(b["password"]))
                if uid != me["id"]:
                    st.drop_sessions(uid)
            return self.send_json({"ok": True})

        raise ApiError(404, "없는 주소입니다.")

    # 로그인 성공 처리: 출입증을 만들어 브라우저 쿠키에 심습니다.
    # HttpOnly = 화면의 스크립트가 출입증을 읽지 못하게 함, SameSite=Strict = 다른 사이트에서 이 출입증을 몰래 쓰지 못하게 함
    def login_ok(self, uid):
        token = self.store.new_session(uid)
        self.send_json({"user": self.store.public_user(uid)},
                       extra={"Set-Cookie": "ilbo=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict" % (token, SESSION_TTL)})

    @staticmethod
    # 아래 clean_ 함수들은 입력값 검사입니다: 사번 형식, 이름 길이, 비밀번호 길이, 권한 값. 맞지 않으면 안내 문구와 함께 거절합니다.
    def clean_id(v):
        v = str(v or "").strip()
        if not ID_RE.match(v):
            raise ApiError(400, "사번은 영문, 숫자, - _ . 만 쓸 수 있습니다 (32자 이내).")
        return v

    @staticmethod
    def clean_name(v):
        v = str(v or "").strip()
        if not v or len(v) > 40:
            raise ApiError(400, "이름을 입력하세요 (40자 이내).")
        return v

    @staticmethod
    def clean_pw(v):
        v = str(v or "")
        if len(v) < MIN_PW or len(v) > 100:
            raise ApiError(400, "비밀번호는 %d자 이상이어야 합니다." % MIN_PW)
        return v

    @staticmethod
    def clean_role(v):
        if v not in ("admin", "manager", "user"):
            raise ApiError(400, "권한 값이 맞지 않습니다.")
        return v

    @staticmethod
    def clean_crew(v):
        # 소속 조는 A, B, C 또는 빈 값(없음)만 받는다
        v = str(v or "").strip().upper()
        if v not in ("", "A", "B", "C"):
            raise ApiError(400, "소속 조는 A, B, C 중에서 선택하세요.")
        return v


# =====================================================================
# 프로그램 시작 부분: 실행 옵션(--port, --host, --data)을 읽고, 데이터 창고를 준비한 뒤, 서버를 켭니다.
# Ctrl+C 를 누르거나 검은 창을 닫을 때까지 계속 요청을 기다립니다.
# =====================================================================
def main():
    ap = argparse.ArgumentParser(description="2T4P 작업일보 사내망 서버")
    ap.add_argument("--port", type=int, default=8080, help="접속 포트 (기본 8080)")
    ap.add_argument("--host", default="0.0.0.0", help="접속을 받을 주소 (기본: 모든 주소)")
    ap.add_argument("--data", default=os.path.join(BASE, "data"), help="데이터 저장 폴더 (기본: 이 폴더의 data)")
    args = ap.parse_args()
    if not os.path.isfile(os.path.join(BASE, PAGE)):
        sys.exit("'%s' 파일이 server.py와 같은 폴더에 있어야 합니다." % PAGE)
    Handler.store = Store(os.path.abspath(args.data))
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print("2T4P 작업일보 서버 실행 중 - 포트 %d" % args.port)
    print("데이터 폴더: %s (일보 %d건, 사용자 %d명)" % (Handler.store.dir, len(Handler.store.reports), len(Handler.store.users)))
    print("접속 주소: http://<이 컴퓨터 이름 또는 IP>:%d/   (끝내려면 Ctrl+C)" % args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n서버를 종료합니다.")


# 이 파일을 직접 실행했을 때(python server.py) main 을 실행합니다.
if __name__ == "__main__":
    main()

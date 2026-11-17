# Web Auth Server - Python
# 구조: 봇 토큰 발급 -> 웹 코드 입력 -> DB 기록 -> 봇 폴링
# 실행: pip install flask  ->  python web_auth_server.py
# 환경: WEB_AUTH_SECRET (봇과 같은 값), PORT (기본 5000)
# 주의: IP/이메일은 이 서버에서도 수집하지 않음. hCaptcha를 쓰면 hCaptcha가 IP를 볼 수 있지만, 우리가 저장하지 않음.
import os, sqlite3, secrets, time, hashlib
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DB = os.path.join(os.path.expanduser("~"), "kurimanju_web_auth.db")
SECRET = os.getenv("WEB_AUTH_SECRET", "change-this-secret")

def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT, guild_id TEXT, code TEXT, status TEXT DEFAULT 'pending', created INTEGER, expires INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS verified(user_id TEXT, guild_id TEXT, verified_at INTEGER, PRIMARY KEY(user_id, guild_id))")
    return c

PAGE = """
<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kurimanju 인증</title><style>
body{font-family:system-ui;background:#0f0f12;color:#fff;display:flex;justify-content:center;padding:40px 16px;margin:0}
.card{background:#1a1a1e;border:1px solid #2a2a2e;border-radius:16px;padding:28px;max-width:420px;width:100%}
h1{font-size:20px;margin:0 0 8px} p{color:#aaa;font-size:14px;line-height:1.6}
input{width:100%;padding:12px;border-radius:10px;border:1px solid #333;background:#111;color:#fff;font-size:16px;box-sizing:border-box}
button{width:100%;padding:12px;border:none;border-radius:10px;background:#ff5a8a;color:#fff;font-size:16px;cursor:pointer;margin-top:12px}
.note{font-size:12px;color:#777;margin-top:12px}
.ok{color:#7ee2a8} .err{color:#ff7a7a}
</style></head><body><div class="card">
<h1>Kurimanju 인증</h1><p>디스코드에서 받은 <b>인증 코드 8자</b>를 입력하세요.<br>코드는 5분 뒤 만료됩니다.<br>IP / 이메일은 수집하지 않습니다.</p>
<form method="post" action="/verify">
<input type="hidden" name="token" value="{{token}}">
<label>인증 코드</label><input name="code" placeholder="예: A1B2C3D4" maxlength="8" required>
<label style="display:block;margin-top:12px">간단 확인: 3 + 4 = ?</label><input name="captcha" placeholder="7" required>
<button>인증하기</button></form>
<p class="note">봇 명령어: /인증토큰 으로 코드 발급 → 이 페이지에서 입력 → 봇이 자동으로 역할 부여</p>
{% if msg %}<p class="{{cls}}">{{msg}}</p>{% endif %}
</div></body></html>
"""

@app.route("/")
def index():
    return jsonify({"ok": True, "service": "Kurimanju Web Auth", "endpoints": ["/verify?token=...", "/api/issue", "/api/status?token=..."]})

@app.route("/api/issue", methods=["POST"])
def issue():
    # 봇이 호출: {secret, user_id, guild_id} -> token 발급
    j = request.get_json(force=True, silent=True) or {}
    if j.get("secret") != SECRET: return jsonify({"ok": False, "error": "secret mismatch"}), 403
    token = secrets.token_urlsafe(16)
    code = secrets.token_hex(4).upper()
    now = int(time.time())
    c = db(); c.execute("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?,?,?)", (token, str(j.get("user_id")), str(j.get("guild_id")), code, "pending", now, now+300)); c.commit(); c.close()
    return jsonify({"ok": True, "token": token, "code": code, "url": f"{request.host_url}verify?token={token}", "expires_in": 300})

@app.route("/verify", methods=["GET", "POST"])
def verify():
    token = request.args.get("token") or request.form.get("token", "")
    if request.method == "GET":
        return render_template_string(PAGE, token=token, msg="", cls="")
    code = (request.form.get("code") or "").strip().upper()
    captcha = (request.form.get("captcha") or "").strip()
    if captcha != "7":
        return render_template_string(PAGE, token=token, msg="간단 확인 실패. 다시 입력하세요.", cls="err")
    c = db(); row = c.execute("SELECT user_id, guild_id, code, expires FROM sessions WHERE token=?", (token,)).fetchone()
    if not row: c.close(); return render_template_string(PAGE, token=token, msg="토큰 없음. 봇에서 /인증토큰 다시 발급하세요.", cls="err")
    uid, gid, saved, exp = row
    if int(time.time()) > exp:
        c.execute("UPDATE sessions SET status='expired' WHERE token=?", (token,)); c.commit(); c.close()
        return render_template_string(PAGE, token=token, msg="만료됨. /인증토큰 다시 발급하세요.", cls="err")
    if code != saved:
        c.close(); return render_template_string(PAGE, token=token, msg="코드 불일치.", cls="err")
    c.execute("UPDATE sessions SET status='verified' WHERE token=?", (token,))
    c.execute("INSERT OR REPLACE INTO verified VALUES(?,?,?)", (uid, gid, int(time.time()))); c.commit(); c.close()
    return render_template_string(PAGE, token=token, msg="인증 완료! 디스코드로 돌아가세요. 봇이 역할을 부여합니다.", cls="ok")

@app.route("/api/status")
def status():
    token = request.args.get("token", "")
    c = db(); row = c.execute("SELECT status, user_id, guild_id FROM sessions WHERE token=?", (token,)).fetchone(); c.close()
    if not row: return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "status": row[0], "user_id": row[1], "guild_id": row[2]})

@app.route("/api/verified")
def verified():
    # 봇 폴링용: guild_id로 인증 완료 목록
    gid = request.args.get("guild_id", ""); secret = request.args.get("secret", "")
    if secret != SECRET: return jsonify({"ok": False}), 403
    c = db(); rows = c.execute("SELECT user_id, verified_at FROM verified WHERE guild_id=?", (gid,)).fetchall(); c.close()
    return jsonify({"ok": True, "verified": [{"user_id": r[0], "verified_at": r[1]} for r in rows]})

if __name__ == "__main__":
    print("Kurimanju Web Auth running on http://0.0.0.0:5000")
    print("1) pip install flask")
    print("2) WEB_AUTH_SECRET=너의비밀 python web_auth_server.py")
    print("3) 봇에서 /인증토큰 -> 웹 URL에서 코드 입력 -> 봇이 /api/verified 폴링")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))

"""
EMON JWT API  v2  (OB55)      — Owner: EMON

  /token?uid=<uid>&password=<password>[&server_name=BD|IND][&key=<API_KEY>]
  /health

Same answer shape as before:
  {"status":"success","real_uid","access_token","open_id","token","time"}   (+ region, client_url, expires_at, credit)

What changed
  * The login body is now the proven OB55 / 1.134.14 payload from majorlogin_new.py (the old file built its own,
    older 1.132.4 body and never used majorlogin_new.py).
  * No protobuf library / pb2 file needed (hand written parser) -> no version errors.
  * server_name=IND uses the IND device profile, anything else the BD one.
  * Optional API_KEY and a short result cache (same uid+password is not logged in again until the token is nearly expired).
  * Returns region + client_url + expiry too (handy for the Friend / Like / Info APIs).
Environment (optional):  API_KEY   RELEASE_VERSION (default OB55)   LOGIN_HOST   PORT
"""
import base64, gzip, hashlib, json, os, threading, time

import requests
import urllib3
from Crypto.Cipher import AES
from flask import Flask, jsonify, request

import majorlogin_new

urllib3.disable_warnings()
app = Flask(__name__)

CREDIT = {"dev": "EMON", "tg": "@EMON"}
API_KEY = os.environ.get("API_KEY", "").strip()
RELEASE_VERSION = os.environ.get("RELEASE_VERSION", "OB55")
LOGIN_HOST = os.environ.get("LOGIN_HOST", "loginbp.ppmainecoonghj.com")
GUEST_URL = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"
MSDK_UA = "GarenaMSDK/4.0.42(NX809J ;Android 9;en;US;app 1.134.14 2024010012;)"

_CACHE, _LOCK = {}, threading.Lock()


# ───────────────────────── protobuf reader ─────────────────────────
def pb_parse(data):
    res, pos, n = {}, 0, len(data)
    while pos < n:
        try:
            key = shift = 0
            while True:
                b = data[pos]; pos += 1
                key |= (b & 0x7F) << shift
                if not b & 0x80:
                    break
                shift += 7
            fn, wt = key >> 3, key & 7
            if wt == 0:
                v = shift = 0
                while True:
                    b = data[pos]; pos += 1
                    v |= (b & 0x7F) << shift
                    if not b & 0x80:
                        break
                    shift += 7
            elif wt == 2:
                ln = shift = 0
                while True:
                    b = data[pos]; pos += 1
                    ln |= (b & 0x7F) << shift
                    if not b & 0x80:
                        break
                    shift += 7
                v = data[pos:pos + ln]; pos += ln
            elif wt == 1:
                v = data[pos:pos + 8]; pos += 8
            elif wt == 5:
                v = data[pos:pos + 4]; pos += 4
            else:
                break
            res.setdefault(fn, []).append(v)
        except IndexError:
            break
    return res


def _s(v):
    return v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else v


def decode_response(resp: bytes):
    """tries: plain, skip 64-byte signature, then AES-decrypted versions.  -> (fields, mode) or (None, 'unknown')"""
    def ok(blob):
        f = pb_parse(blob) if blob else {}
        t = _s((f.get(8) or [b""])[0])
        return f if isinstance(t, str) and t.count(".") == 2 else None

    cands = [("plain", resp), ("skip 64B", resp[64:])]
    if len(resp) >= 16 and len(resp) % 16 == 0:
        try:
            dec = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(resp)
            pad = dec[-1]
            if 1 <= pad <= 16:
                dec = dec[:-pad]
            cands += [("aes", dec), ("aes skip 64B", dec[64:])]
        except Exception:
            pass
    # server normally sends plain protobuf starting with field 1 (0x0A); otherwise it has the 64-byte prefix
    if resp[:1] != b"\x0a":
        cands = cands[1:2] + cands[:1] + cands[2:]
    for mode, blob in cands:
        f = ok(blob)
        if f:
            return f, mode
    return None, "unknown"


def decode_jwt(token):
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


# ───────────────────────── Garena calls ─────────────────────────
def get_access_token(uid, password):
    try:
        r = requests.post(GUEST_URL, json={"client_id": 100067, "client_secret": CLIENT_SECRET, "client_type": 2,
                                           "password": password, "response_type": "token", "uid": int(uid)},
                          headers={"User-Agent": MSDK_UA, "Accept": "application/json",
                                   "Content-Type": "application/json; charset=utf-8", "Connection": "Keep-Alive"},
                          verify=False, timeout=12)
        d = (r.json().get("data") or {}) if r.status_code == 200 else {}
        return d.get("access_token"), d.get("open_id"), None if d else f"HTTP {r.status_code}"
    except Exception as e:
        return None, None, str(e)


def major_login(access_token, open_id, server_name):
    try:
        body = majorlogin_new.build_payload(access_token, open_id, "IND" if server_name == "IND" else "BD")
        r = requests.post(f"https://{LOGIN_HOST}/MajorLogin", data=body, verify=False, timeout=15, headers={
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)", "Accept": "*/*",
            "Accept-Encoding": "deflate, gzip", "Authorization": "Bearer ", "X-GA": "v1 1",
            "X-GA-SV": str(int(time.time())), "ReleaseVersion": RELEASE_VERSION,
            "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1"})
        raw = r.content
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        if r.status_code in (200, 201):
            return raw, None
        return None, f"HTTP {r.status_code}: {raw[:120].decode('utf-8', 'replace')}"
    except Exception as e:
        return None, str(e)


# ───────────────────────── routes ─────────────────────────
@app.before_request
def _auth():
    if API_KEY and request.path not in ("/", "/health") and request.args.get("key") != API_KEY:
        return jsonify(status="error", message="invalid key"), 401


@app.get("/token")
def api_token():
    t0 = time.time()
    uid = request.args.get("uid", "").strip()
    password = request.args.get("password", "").strip()
    server = (request.args.get("server_name") or "BD").upper().strip()
    if not uid or not password:
        return jsonify(status="error", message="Missing uid or password"), 400
    if not uid.isdigit() or len(uid) < 8:
        return jsonify(status="error", message="Invalid UID format"), 400

    ck = hashlib.sha1(f"{uid}:{password}:{server}".encode()).hexdigest()
    with _LOCK:
        c = _CACHE.get(ck)
    if c and c["exp"] > time.time() + 120:
        return jsonify({**c["out"], "cached": True, "time": f"{time.time() - t0:.2f}s"}), 200

    access_token, open_id, err = get_access_token(uid, password)
    if not access_token or not open_id:
        return jsonify(status="error", message="OAuth failed", details=err), 400
    raw, err = major_login(access_token, open_id, server)
    if not raw:
        return jsonify(status="error", message=err or "JWT generation failed"), 400
    f, mode = decode_response(raw)
    if not f:
        return jsonify(status="error", message="No JWT token received", decode_mode=mode), 400

    token = _s(f[8][0])
    jp = decode_jwt(token)
    exp = jp.get("exp") or time.time() + 3 * 3600
    out = {"status": "success", "real_uid": str(jp.get("account_id") or (f.get(1) or ["N/A"])[0]),
           "access_token": access_token, "open_id": open_id, "token": token,
           "region": str(jp.get("lock_region") or _s((f.get(2) or [b""])[0]) or server),
           "client_url": _s((f.get(10) or [b""])[0]) or None, "expires_at": int(exp), "credit": CREDIT}
    with _LOCK:
        _CACHE[ck] = {"out": out, "exp": exp}
    return jsonify({**out, "time": f"{time.time() - t0:.2f}s"}), 200


@app.get("/health")
@app.get("/")
def health():
    return jsonify(status="healthy", service="EMON JWT API", release_version=RELEASE_VERSION, credit=CREDIT)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8789))
    print(f"✅ EMON JWT API running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)

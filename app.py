"""Potapenko Escape web app: Flask/Wsgi server and lightweight 1v1 matchmaking."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from flask import Flask, jsonify, request, send_from_directory
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid

ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / ".local" / "users.json"
OWNER_SALT = bytes.fromhex("8ac7fda3f4f09e7c512430bf1bd1ce87")
OWNER_PASSWORD_HASH = "f36a17ade0f44bec97ac562cd6840c4271cc46ef8f35c21b5cbde2cb5e965c72"
lock = RLock()
sessions: dict[str, str] = {}
queue: list[dict] = []
matches: dict[str, dict] = {}
player_matches: dict[str, str] = {}
app = Flask(__name__, static_folder=None)


def password_hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000).hex()


def load_users() -> dict:
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


users = load_users()
if "owner" not in users:
    users["owner"] = {
        "username": "owner", "salt": OWNER_SALT.hex(), "password_hash": OWNER_PASSWORD_HASH,
        "admin": True, "banned": False, "mmr": 1000, "created": datetime.now(timezone.utc).isoformat(),
        "game": {"coins": 120, "unlocked": 1, "best": 0, "heroes": [0], "selectedHero": 0, "upgrades": {}, "volume": 45, "device": "pc", "mode": "levels", "caseWelcome": True},
    }


def save_users() -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = DATA_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, DATA_FILE)


save_users()


def public_user(record: dict) -> dict:
    record.setdefault("mmr", 1000)
    return {"username": record["username"], "admin": bool(record.get("admin")), "banned": bool(record.get("banned")), "created": record.get("created"), "mmr": int(record["mmr"]), "game": record.get("game", {})}


def safe_game_data(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    def number(name: str, default: float, minimum: float, maximum: float) -> float:
        try:
            return max(minimum, min(maximum, float(value.get(name, default))))
        except (TypeError, ValueError):
            return default
    heroes = value.get("heroes", [0])
    if not isinstance(heroes, list):
        heroes = [0]
    heroes = sorted({int(item) for item in heroes if str(item).isdigit() and 0 <= int(item) < 18})
    upgrades = value.get("upgrades", {})
    if not isinstance(upgrades, dict):
        upgrades = {}
    clean_upgrades = {str(int(k)): int(max(0, min(5, int(v)))) for k, v in upgrades.items() if str(k).isdigit() and str(v).isdigit() and int(k) < 18}
    return {
        "coins": int(number("coins", 0, 0, 2_000_000_000)),
        "unlocked": int(number("unlocked", 1, 1, 20)), "best": int(number("best", 0, 0, 1_000_000)),
        "heroes": heroes or [0], "selectedHero": int(number("selectedHero", 0, 0, 17)), "upgrades": clean_upgrades,
        "volume": int(number("volume", 45, 0, 100)), "device": "phone" if value.get("device") == "phone" else "pc",
        "mode": "duel" if value.get("mode") == "duel" else ("arcade" if value.get("mode") == "arcade" else "levels"),
        "caseWelcome": bool(value.get("caseWelcome", True)),
    }


def json_error(message: str, status: int):
    return jsonify(error=message), status


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    username = sessions.get(token)
    record = users.get(username) if username else None
    if not record or record.get("banned"):
        return None, None, token
    return username, record, token


def require_user():
    username, record, token = current_user()
    if not record:
        return None, None, token, json_error("Сессия завершена или аккаунт заблокирован. Войди снова.", 403)
    return username, record, token, None


@app.get("/api/me")
def api_me():
    username, record, _, error = require_user()
    return error or jsonify(user=public_user(record))


@app.get("/api/admin/users")
def admin_users():
    _, record, _, error = require_user()
    if error:
        return error
    if not record.get("admin"):
        return json_error("Доступ только для owner", 403)
    with lock:
        listing = [public_user(row) for row in users.values()]
    return jsonify(users=listing)


@app.post("/api/register")
@app.post("/api/login")
def auth():
    body = request.get_json(silent=True) or {}
    registering = request.path.endswith("register")
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))
    if registering:
        if not re.fullmatch(r"[a-z0-9_-]{3,20}", username):
            return json_error("Логин: 3–20 символов, латинские буквы, цифры, _ или -.", 400)
        if len(password) < 6 or len(password) > 80:
            return json_error("Пароль должен быть длиной от 6 до 80 символов.", 400)
        with lock:
            if username in users:
                return json_error("Этот логин уже занят.", 409)
            salt = secrets.token_bytes(16)
            users[username] = {"username": username, "salt": salt.hex(), "password_hash": password_hash(password, salt), "admin": False, "banned": False, "mmr": 1000, "created": datetime.now(timezone.utc).isoformat(), "game": {"coins": 120, "unlocked": 1, "best": 0, "heroes": [0], "selectedHero": 0, "upgrades": {}, "volume": 45, "device": "pc", "mode": "levels", "caseWelcome": True}}
            save_users()
            record = users[username]
    else:
        record = users.get(username)
        if not record or not hmac.compare_digest(password_hash(password, bytes.fromhex(record["salt"])), record["password_hash"]):
            return json_error("Неверный логин или пароль.", 401)
        if record.get("banned"):
            return json_error("Этот аккаунт заблокирован владельцем игры.", 403)
    token = secrets.token_urlsafe(32)
    sessions[token] = username
    return jsonify(token=token, user=public_user(record))


@app.post("/api/logout")
@app.post("/api/save")
@app.post("/api/admin/action")
def account_actions():
    username, record, token, error = require_user()
    if error:
        return error
    body = request.get_json(silent=True) or {}
    if request.path == "/api/logout":
        sessions.pop(token, None)
        return jsonify(ok=True)
    if request.path == "/api/save":
        with lock:
            incoming = safe_game_data(body.get("game"))
            if incoming:
                record["game"] = incoming
                save_users()
        return jsonify(game=record.get("game", {}))
    if not record.get("admin"):
        return json_error("Доступ только для owner", 403)
    action, target = body.get("action"), str(body.get("target", "")).strip().lower()
    with lock:
        target_record = users.get(target)
        if not target_record:
            return json_error("Игрок не найден", 404)
        if action == "ban":
            if target == "owner":
                return json_error("Аккаунт owner нельзя заблокировать", 400)
            target_record["banned"] = True
        elif action == "unban":
            target_record["banned"] = False
        elif action == "adjust_coins":
            try:
                amount = int(body.get("amount", 0))
            except (TypeError, ValueError):
                amount = 0
            game = target_record.setdefault("game", {})
            game["coins"] = max(0, min(2_000_000_000, int(game.get("coins", 0)) + amount))
        elif action == "grant_hero":
            try:
                hero_id = int(body.get("heroId"))
            except (TypeError, ValueError):
                hero_id = -1
            if not 0 <= hero_id < 18:
                return json_error("Неизвестный персонаж", 400)
            game = target_record.setdefault("game", {})
            owned = game.setdefault("heroes", [0])
            if hero_id not in owned:
                owned.append(hero_id)
        else:
            return json_error("Неизвестное действие", 400)
        save_users()
        result = public_user(target_record)
    return jsonify(user=result)


def token_match(token: str):
    match_id = player_matches.get(token)
    return matches.get(match_id) if match_id else None


def clean_match(match: dict, token: str):
    own = match["players"].get(token)
    if not own:
        return None
    other_token = next((key for key in match["players"] if key != token), None)
    other = match["players"].get(other_token) if other_token else None
    remaining = max(0, 60 - (time.time() - match["started"])) if match.get("started") else 60
    outcome = None
    if match.get("finished"):
        if match.get("result") == "opponent_left":
            outcome = "loss" if own["username"] == match.get("leaver") else "opponent_left"
        else:
            outcome = "win" if match.get("winner") == own["username"] else "loss"
    return {"status": "finished" if match.get("finished") else ("playing" if match.get("started") else "waiting"), "matchId": match["id"], "role": own["role"], "opponent": ({"username": other["username"], "heroId": other["heroId"], "x": other["x"], "z": other["z"], "role": other["role"], "updated": other["updated"]} if other else None), "remaining": remaining, "result": outcome, "mmrDelta": (own.get("mmrDelta", 0) if match.get("finished") else 0), "mmr": users.get(own["username"], {}).get("mmr", 1000)}


@app.post("/api/match/queue")
def match_queue():
    username, record, token, error = require_user()
    if error:
        return error
    body = request.get_json(silent=True) or {}
    try:
        hero_id = int(body.get("heroId", 0))
    except (TypeError, ValueError):
        hero_id = 0
    if hero_id not in record.get("game", {}).get("heroes", [0]):
        return json_error("Сначала выбери открытого бойца", 400)
    with lock:
        existing = token_match(token)
        if existing and not existing.get("finished"):
            return jsonify(match=clean_match(existing, token))
        queue[:] = [entry for entry in queue if time.time() - entry["created"] < 90 and entry["token"] != token]
        entry = {"token": token, "username": username, "heroId": hero_id, "created": time.time()}
        opponent_index = next((index for index, waiting in enumerate(queue) if waiting["username"] != username), None)
        if opponent_index is not None:
            opponent = queue.pop(opponent_index)
            role_pair = ["chaser", "runner"]
            secrets.SystemRandom().shuffle(role_pair)
            now = time.time()
            room = {"id": uuid.uuid4().hex[:10], "started": now, "finished": False, "result": None, "players": {}}
            for item, role in zip((entry, opponent), role_pair):
                room["players"][item["token"]] = {"username": item["username"], "heroId": item["heroId"], "role": role, "x": secrets.choice([-5.0, 5.0]), "z": secrets.choice([-5.0, 5.0]), "updated": now, "mmrDelta": 0}
                player_matches[item["token"]] = room["id"]
            matches[room["id"]] = room
            return jsonify(match=clean_match(room, token))
        queue.append(entry)
        return jsonify(match={"status": "waiting", "role": None, "opponent": None, "remaining": 60, "mmr": record.get("mmr", 1000)})


@app.get("/api/match/state")
def match_state():
    _, _, token, error = require_user()
    if error:
        return error
    with lock:
        match = token_match(token)
        if not match:
            return jsonify(match={"status": "none"})
        return jsonify(match=clean_match(match, token))


@app.post("/api/match/update")
def match_update():
    username, _, token, error = require_user()
    if error:
        return error
    body = request.get_json(silent=True) or {}
    with lock:
        match = token_match(token)
        if not match:
            return json_error("Матч не найден", 404)
        own = match["players"].get(token)
        try:
            own["x"] = max(-7.1, min(7.1, float(body.get("x", own["x"]))))
            own["z"] = max(-7.1, min(7.1, float(body.get("z", own["z"]))))
        except (TypeError, ValueError):
            pass
        own["updated"] = time.time()
        if not match.get("finished"):
            other = next((player for key, player in match["players"].items() if key != token), None)
            elapsed = time.time() - match["started"]
            winner = None
            if other and ((own["x"] - other["x"]) ** 2 + (own["z"] - other["z"]) ** 2) ** .5 < 1.0 and own["role"] == "chaser":
                winner = own
            elif elapsed >= 60:
                winner = other if own["role"] == "chaser" else own
            if winner:
                match["finished"] = True
                match["result"] = "draw" if not other else "decided"
                match["winner"] = winner["username"] if other else None
                for player in match["players"].values():
                    delta = 25 if player is winner else -15
                    player["mmrDelta"] = delta
                    account = users.get(player["username"])
                    if account:
                        account["mmr"] = max(0, min(99999, int(account.get("mmr", 1000)) + delta))
                save_users()
        return jsonify(match=clean_match(match, token))


@app.post("/api/match/leave")
def match_leave():
    _, _, token, error = require_user()
    if error:
        return error
    with lock:
        queue[:] = [entry for entry in queue if entry["token"] != token]
        match = token_match(token)
        if match and not match.get("finished"):
            match["finished"] = True
            match["result"] = "opponent_left"
            match["leaver"] = users.get(username, {}).get("username", username)
            for key, player in match["players"].items():
                delta = -15 if key == token else 25
                player["mmrDelta"] = delta
                if player["username"] in users:
                    users[player["username"]]["mmr"] = max(0, int(users[player["username"]].get("mmr", 1000)) + delta)
            save_users()
    return jsonify(ok=True)


@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/<path:filename>")
def static_files(filename):
    if filename.startswith(".local/") or filename == ".local":
        return json_error("Не найдено", 404)
    return send_from_directory(ROOT, filename)


if __name__ == "__main__":
    print("Игра открыта: http://127.0.0.1:8000")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), threaded=True)

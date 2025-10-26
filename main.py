import json
import os
import requests
import binascii
import random
import telebot
import time
from x7m_ProTo import*
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
from concurrent.futures import ThreadPoolExecutor, as_completed
from _7aMa import like_pb2, like_count_pb2, _7ama_pb2, output_pb2, my_pb2

BOT_TOKEN = "7943258414:AAFHs6Nv1Pw420uAb5WMRn2n29ARp7g2v6A"
bot = telebot.TeleBot(BOT_TOKEN)

DEV_ID = 5260441331
AUTH_FILE = "auth_groups.json"
ACCOUNTS_FILE = 'tokens.json'

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

SESSION = requests.Session()
SESSION.verify = False

def log_debug(msg):
    print(f"[DEBUG] {msg}")

def log_error(msg):
    print(f"[ERROR] {msg}")

def getGuestAccessToken(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        resp = SESSION.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                            headers=headers, data=data, timeout=12)
        data_response = resp.json()
    except Exception as e:
        log_error(f"getGuestAccessToken request error for uid {uid}: {e}")
        return {"error": "request_failed"}

    if data_response.get("success") is True:
        resp_obj = data_response.get("response", {})
        if resp_obj.get("error") == "auth_error":
            return {"error": "auth_error"}
    return {"access_token": data_response.get("access_token"), "open_id": data_response.get("open_id")}

def check_guest(uid, password):
    token_data = getGuestAccessToken(uid, password)
    if token_data.get("error") == "auth_error":
        return uid, None, None, True
    access_token = token_data.get("access_token")
    open_id = token_data.get("open_id")
    if access_token and open_id:
        log_debug(f"UID {uid}: guest login OK (access_token obtained).")
        return uid, access_token, open_id, False
    log_debug(f"UID {uid}: guest login failed or missing token.")
    return uid, None, None, False

def login(uid, access_token, open_id, platform_type):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "Free Fire"
    game_data.game_version = 1
    game_data.version_code = "1.115.1"
    game_data.os_info = "iOS 26"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1170
    game_data.screen_height = 2532
    game_data.dpi = "1000"
    game_data.cpu_info = "Apple A15 Bionic"
    game_data.total_ram = 6144
    game_data.gpu_name = "Apple GPU (5-core)"
    game_data.gpu_version = "Metal 3"
    game_data.user_id = uid
    game_data.ip_address = "172.190.111.97"
    game_data.language = "ar"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = 4
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)

    try:
        serialized_data = game_data.SerializeToString()
    except Exception as e:
        log_error(f"Serialize error for uid {uid}: {e}")
        return None

    padded_data = pad(serialized_data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(padded_data)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB50",
        "Content-Length": str(len(encrypted_data))
    }
    try:
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=18)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            try:
                jwt_msg.ParseFromString(response.content)
            except Exception as e:
                log_debug(f"UID {uid}: failed parse JWT response.")
                return None
            if jwt_msg.token:
                log_debug(f"UID {uid}: login succeeded (JWT obtained).")
                return jwt_msg.token
        else:
            log_debug(f"UID {uid}: MajorLogin returned status {response.status_code}.")
    except Exception as e:
        log_error(f"UID {uid}: error during MajorLogin request: {e}")
    return None

def load_accounts():
    try:
        return json.load(open(ACCOUNTS_FILE, "r", encoding="utf-8"))
    except Exception:
        return {}

def get_tokens_local_sync(retries_per_account: int = 2, platform_type: int = 4):
    accounts = load_accounts()
    tokens = []
    if not isinstance(accounts, dict):
        log_error("Accounts file format invalid (expected JSON object).")
        return tokens

    for uid, password in accounts.items():
        success = False
        for attempt in range(retries_per_account):
            try:
                uid_str, access_token, open_id, err_flag = check_guest(uid, password)
                if err_flag:
                    log_debug(f"UID {uid}: invalid guest credentials.")
                    break
                if not access_token or not open_id:
                    log_debug(f"UID {uid}: no access_token/open_id from guest (attempt {attempt+1}).")
                    continue
                jwt_token = login(uid_str, access_token, open_id, platform_type)
                if jwt_token:
                    tokens.append(jwt_token)
                    success = True
                    break
            except Exception as e:
                log_error(f"UID {uid}: exception while obtaining token (attempt {attempt+1}): {e}")
                time.sleep(0.5)
        if not success:
            log_debug(f"UID {uid}: token not obtained after {retries_per_account} attempts.")
    log_debug(f"Collected {len(tokens)} valid tokens from local accounts.")
    return tokens

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()

def create_uid_proto(uid):
    pb = _7ama_pb2.uid_generator()
    pb.saturn_ = int(uid)
    pb.garena = 1
    return pb.SerializeToString()

def create_like_proto(uid):
    pb = like_pb2.like()
    pb.uid = int(uid)
    return pb.SerializeToString()

def decode_protobuf(binary):
    try:
        pb = like_count_pb2.Info()
        pb.ParseFromString(binary)
        return pb
    except DecodeError:
        return None

def make_request(enc_uid, token):
    url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    try:
        res = SESSION.post(url, data=bytes.fromhex(enc_uid), headers=headers, timeout=12)
        return decode_protobuf(res.content)
    except Exception as e:
        log_debug(f"make_request error: {e}")
        return None

def send_like_with_token(enc_like_hex, token, timeout=12):
    url = "https://clientbp.ggblueshark.com/LikeProfile"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    try:
        r = SESSION.post(url, data=bytes.fromhex(enc_like_hex), headers=headers, timeout=timeout)
        return r.status_code
    except Exception as e:
        return None

def send_likes_threaded(uid, tokens, max_workers=20):
    enc_like_hex = encrypt_message(create_like_proto(uid))
    results = []
    if not tokens:
        return results
    workers = min(max_workers, len(tokens))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(send_like_with_token, enc_like_hex, t): t for t in tokens}
        for fut in as_completed(futures):
            try:
                status = fut.result()
                results.append(status)
            except Exception:
                results.append(None)
    return results

if os.path.exists(AUTH_FILE):
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            AUTH_GROUPS = json.load(f)
    except Exception:
        AUTH_GROUPS = []
else:
    AUTH_GROUPS = []

def save_auth_groups():
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(AUTH_GROUPS, f)

@bot.message_handler(commands=['allow'])
def auth_group(message):
    if message.from_user.id != DEV_ID:
        return
    if message.chat.type in ["group", "supergroup"]:
        if message.chat.id not in AUTH_GROUPS:
            AUTH_GROUPS.append(message.chat.id)
            save_auth_groups()
            bot.reply_to(message, "done allowing group")
        else:
            bot.reply_to(message, "group already allowed")

@bot.message_handler(commands=['stop'])
def unauth_group(message):
    if message.from_user.id != DEV_ID:
        return
    if message.chat.type in ["group", "supergroup"]:
        if message.chat.id in AUTH_GROUPS:
            AUTH_GROUPS.remove(message.chat.id)
            save_auth_groups()
            bot.reply_to(message, "group removed")
        else:
            bot.reply_to(message, "group isn't added")

@bot.message_handler(commands=['like'])
def like_command(message):
    if not (message.chat.type in ["group", "supergroup"] or message.from_user.id == DEV_ID):
        bot.reply_to(message, "you are not allowed")
        return

    if message.chat.type in ["group", "supergroup"] and message.chat.id not in AUTH_GROUPS:
        bot.reply_to(message, "group is not allowed")
        return

    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "❌ استخدم الصيغة: /like 12345678")
        return

    uid = parts[1].strip()
    bot.reply_to(message, f"⏳ جاري إرسال اللايكات لـ UID {uid}...")

    try:
        tokens = get_tokens_local_sync(retries_per_account=2)
        if not tokens:
            bot.reply_to(message, "❌ لا توجد توكنات صالحة")
            return

        enc_uid = encrypt_message(create_uid_proto(uid))
        before = make_request(enc_uid, tokens[0])
        if not before:
            bot.reply_to(message, "❌ لم يتم العثور على معلومات الحساب")
            return

        before_data = json.loads(MessageToJson(before))
        likes_before = int(before_data.get("AccountInfo", {}).get("Likes", 0))
        nickname = before_data.get("AccountInfo", {}).get("PlayerNickname", "Unknown")
        responses = send_likes_threaded(uid, tokens, max_workers=30)
        success_count = sum(1 for r in responses if r == 200)
        after = make_request(enc_uid, tokens[0])
        likes_after = 0
        if after:
            after_data = json.loads(MessageToJson(after))
            likes_after = int(after_data.get("AccountInfo", {}).get("Likes", 0))

        text = f"""Likes sent successfully\n\nName: {nickname}\n\nLikes Before: {likes_before}\n\nLikes After: {likes_after}\n\nLikes Added: {likes_after - likes_before}"""
        bot.reply_to(message, text)

    except Exception as e:
        bot.reply_to(message, f"⚠️ حدث خطأ: {e}")

print("🚀 this testing ...")
bot.infinity_polling()

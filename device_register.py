import secrets
import uuid
import time
import json
import hashlib
import gzip
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from urllib.parse import urlencode

def generate_random_token():
    return secrets.token_bytes(32)

def derive_secret_key():
    primary_key = bytes([
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
        0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
        0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
        0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
        0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25
    ])
    secondary_key = bytes([
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
        0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
        0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
        0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
        0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    ])
    return bytes(a ^ b for a, b in zip(primary_key, secondary_key))

def sha512_digest(data):
    return hashlib.sha512(data).digest()

def derive_aes_key_iv(random_bytes):
    hash_input = sha512_digest(random_bytes) + derive_secret_key()
    hash_output = sha512_digest(hash_input)
    return hash_output[:16], hash_output[16:32]

def aes_encrypt(plaintext, aes_key, aes_iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def encrypted_payload(data):
    prefix = b"\x74\x63\x05\x10\x00\x00"
    random_bytes = generate_random_token()
    aes_key, aes_iv = derive_aes_key_iv(random_bytes)
    encrypted_content = aes_encrypt(sha512_digest(data) + data, aes_key, aes_iv)
    return prefix + random_bytes + encrypted_content

def generate_uuid():
    return str(uuid.uuid4())

def md5_hash(data):
    return hashlib.md5(data).hexdigest()

def current_time_millis():
    return int(time.time() * 1000)

def current_time_seconds():
    return int(time.time())

def generate_android_id():
    return secrets.token_hex(8)

def post_request(url, headers, data):
    response = requests.post(url, headers=headers, data=data)
    response_json = response.json()
    if 'tnc_data' in response_json:
        del response_json['tnc_data']
    return response_json

def compress_gzip(data):
    return gzip.compress(data)

def build_post_payload(android_id, client_id, google_aid, uuid_client):
    payload = {
        "magic_tag": "ss_app_log",
        "header": {
            "display_name": "TikTok",
            "update_version_code": 2023205030,
            "manifest_version_code": 2023205030,
            "app_version_minor": "",
            "aid": 1233,
            "channel": "googleplay",
            "package": "com.zhiliaoapp.musically",
            "app_version": "32.5.3",
            "version_code": 320503,
            "sdk_version": "3.9.17-bugfix.9",
            "sdk_target_version": 29,
            "git_hash": "3e93151",
            "os": "Android",
            "os_version": "11",
            "os_api": 30,
            "device_model": "Pixel 2",
            "device_brand": "google",
            "device_manufacturer": "Google",
            "cpu_abi": "arm64-v8a",
            "release_build": "e7cd5de_20231207",
            "density_dpi": 420,
            "display_density": "mdpi",
            "resolution": "1794x1080",
            "language": "en",
            "timezone": -5,
            "access": "wifi",
            "not_request_sender": 1,
            "rom": "6934943",
            "rom_version": "RP1A.201005.004.A1",
            "cdid": client_id,
            "sig_hash": "194326e82c84a639a52e5c023116f12a",
            "gaid_limited": 0,
            "google_aid": google_aid,
            "openudid": android_id,
            "clientudid": uuid_client,
            "tz_name": "America/New_York",
            "tz_offset": -18000,
            "req_id": generate_uuid(),
            "device_platform": "android",
            "custom": {
                "is_kids_mode": 0,
                "filter_warn": 0,
                "web_ua": "Mozilla/5.0 (Linux; Android 11; Pixel 2 Build/RP1A.201005.004.A1; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36",
                "user_period": 0,
                "screen_height_dp": 683,
                "user_mode": -1,
                "apk_last_update_time": 1702363135217,
                "screen_width_dp": 411
            },
            "apk_first_install_time": 1697783355395,
            "is_system_app": 0,
            "sdk_flavor": "global",
            "guest_mode": 0
        },
        "_gen_time": current_time_millis()
    }
    return compress_gzip(json.dumps(payload).encode('utf-8'))

def build_headers(md5_hash_value):
    return {
        'log-encode-type': 'gzip',
        'x-tt-request-tag': 't=0;n=1',
        'sdk-version': '2',
        'X-SS-REQ-TICKET': str(current_time_millis()),
        'passport-sdk-version': '19',
        'x-tt-dm-status': 'login=0;ct=1;rt=4',
        'x-vc-bdturing-sdk-version': '2.3.4.i18n',
        'Content-Type': 'application/octet-stream;tt-data=a',
        'X-SS-STUB': md5_hash_value,
        'Host': 'log-va.tiktokv.com'
    }

def build_registration_url(android_id, client_id):
    params = {
        "tt_data": "a",
        "ac": "wifi",
        "channel": "googleplay",
        "aid": "1233",
        "app_name": "musical_ly",
        "version_code": "320503",
        "version_name": "32.5.3",
        "device_platform": "android",
        "os": "android",
        "ab_version": "32.5.3",
        "ssmix": "a",
        "device_type": "Pixel 2",
        "device_brand": "google",
        "language": "en",
        "os_api": "30",
        "os_version": "11",
        "openudid": android_id,
        "manifest_version_code": "2023205030",
        "resolution": "1080*1794",
        "dpi": "420",
        "update_version_code": "2023205030",
        "_rticket": str(current_time_millis()),
        "is_pad": "0",
        "current_region": "TW",
        "app_type": "normal",
        "timezone_name": "America/New_York",
        "residence": "TW",
        "app_language": "en",
        "ac2": "wifi5g",
        "uoo": "0",
        "op_region": "TW",
        "timezone_offset": "-18000",
        "build_number": "32.5.3",
        "host_abi": "arm64-v8a",
        "locale": "en",
        "ts": str(current_time_seconds()),
        "cdid": client_id
    }
    return 'https://log-va.tiktokv.com/service/2/device_register/?' + urlencode(params)

def register_device():
    android_id = generate_android_id()
    client_id = generate_uuid()
    google_aid = generate_uuid()
    client_uuid = generate_uuid()
    compressed_payload = build_post_payload(android_id, client_id, google_aid, client_uuid)
    encrypted_payload_data = encrypted_payload(compressed_payload)
    headers = build_headers(md5_hash(encrypted_payload_data))
    registration_url = build_registration_url(android_id, client_id)
    response = post_request(registration_url, headers, encrypted_payload_data)
    print(f"Device registration response: {response}")

if __name__ == "__main__":
    register_device()

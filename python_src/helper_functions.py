"""
Helper functions to run mutual authentication and key agreement.
------------------------------
Coded By:
Kamal Raj (kamal@kamalraj.in)
------------------------------
"""
import requests
import demo_puf as puf
import ascon
import os
import json

FILENAME = "ram.json"

def send_auth_request(server_url,data):
    payload = "type=auth&device_id=" + data
    response = requests.get(server_url,payload)
    if(response.status_code == 200):
        return response.text
    else:
        print("Server not responding")

def auth_server(r1,nonce,tag):
    authentic = 0
    tag = bytes.fromhex(tag)
    nonce = bytes.fromhex(nonce)
    tag_bar = ascon.ascon_encrypt(key=r1,nonce=nonce,associateddata=b'',plaintext=b'')
    if(tag_bar == tag):
        authentic = 1
    else:
        authentic = 0
    return authentic

def send_challenge_response(server_url,r2,nonce,sid):
    tag2 = ascon.ascon_encrypt(key=r2,nonce=nonce,associateddata=b'',plaintext=b'')
    payload = "sid=" + sid + "&tag2=" + tag2.hex()
    response = requests.get(server_url,payload)
    if(response.status_code == 200):
        print(response.text)
    else:
        print("Server not responding")

def keygen(r1,r2):
    key = bytes(a ^ b for a, b in zip(r1, r2))
    return key

def send_message_securely(trusted_server,session_id,message,nonce,key):
    ciphertext = ascon.ascon_encrypt(key=key,nonce=nonce,plaintext=message,associateddata='')
    ciphertext = ciphertext.hex()
    payload = "sid=" + session_id + "&ct=" + ciphertext
    response = requests.get(trusted_server,payload)
    if(response.status_code == 200):
        print(response.text)
    else:
        print("Server not responding")

def init_ram():
    if not os.path.exists(FILENAME):
        data = {"nonce": "", "key": "", "timestamp": "", "session_token":""}
        with open(FILENAME, "w") as f:
            json.dump(data, f, indent=4)

def ram(action, field, value=None):
    init_ram()
    
    with open(FILENAME, "r") as f:
        data = json.load(f)

    if field not in data:
        raise KeyError(f"Invalid field '{field}'. Must be one of {list(data.keys())}.")

    if action == "read":
        return data[field]
    
    elif action == "write":
        data[field] = value
        with open(FILENAME, "w") as f:
            json.dump(data, f, indent=4)
        return True

    elif action == "increment":
        try:
            current = int(data.get(field, 0)) if str(data.get(field, "")).isdigit() else 0
        except ValueError:
            current = 0
        step = int(value) if value is not None else 1
        new_value = current + step
        data[field] = str(new_value)
        with open(FILENAME, "w") as f:
            json.dump(data, f, indent=4)
        return new_value

    else:
        raise ValueError("Invalid action. Use 'read', 'write', or 'increment'.")

# print(ram("read", "nonce"))
# ram("write", "key", "abcd1234")
# print(ram("increment", "nonce"))        # increments by 1
# print(ram("increment", "nonce", 100))   # increments by 100
# print(ram("read", "nonce"))
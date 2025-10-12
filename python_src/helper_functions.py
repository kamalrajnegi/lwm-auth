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

def send_auth_request(server_url,data):
    payload = "type=auth&device_id=" + data
    response = requests.get(server_url,payload)
    if(response.status_code == 200):
        return response.text
    else:
        print("Server not responding")

def auth_server(r1,nonce,tag):
    authentic = 0
    # ch = bytes.fromhex(ch)
    tag = bytes.fromhex(tag)
    nonce = bytes.fromhex(nonce)
    # response = puf.demo_puf(challenge=ch)
    tag_bar = ascon.ascon_encrypt(key=r1,nonce=nonce,associateddata=b'',plaintext=b'')
    if(tag_bar == tag):
        authentic = 1
    else:
        authentic = 0
    return authentic

def send_challenge_response(server_url,r2,nonce,sid):
    # ch = bytes.fromhex(ch)
    nonce = bytes.fromhex(nonce)
    # response = puf.demo_puf(challenge=ch)
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
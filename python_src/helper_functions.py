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
    print(payload) 
    response = requests.get(server_url,payload)
    if(response.status_code == 200):
        print(response.text)
    else:
        print("Server not responding")

def auth_server(ch,nonce,tag):
    authentic = 2
    response = puf.demo_puf(challenge=ch)
    tag_bar = ascon.ascon_encrypt(key=response,nonce=nonce)
    if(tag_bar == tag):
        authentic = 1
    else:
        authentic = 0
    return authentic

def send_challenge_response(server_url,data):
    respond = requests.get(server_url,data)
    return respond

def keygen(r1,r2):
    key = r1 ^ r2
    return key

def send_message_securely():
    print("secure communication will be completed here")
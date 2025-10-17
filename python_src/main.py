"""
Main function for mutual authentication and key agreement.
Also, function for secure communication with the server.
------------------------------
Coded By:
Kamal Raj (kamal@kamalraj.in)
------------------------------
"""

import helper_functions as lwmauth
import json
import demo_puf as puf

trusted_server = "https://lwm-auth.org/demo-auth"
param1 = "hello"
device_id = "demo_device"

def mutual_auth():
    # Step-1: Send request for authentication and decode received response
    rsp = lwmauth.send_auth_request(trusted_server,device_id)
    rsp = json.loads(rsp)
    first_challenge = bytes.fromhex(rsp['c1'])
    first_response = puf.demo_puf(first_challenge)
    session_token = rsp['nonce']
    auth_tag1 = rsp['tag1']
    lwmauth.ram("write","nonce",session_token)
    lwmauth.ram("write","session_token",session_token)
    lwmauth.ram("increment","nonce")

    # Step-2: Authenticate server
    authentic = lwmauth.auth_server(first_response,session_token,auth_tag1)
    if(authentic):
        print("Server is authentic")
        second_challenge = bytes.fromhex(rsp['c2'])
    else:
        print("Server is not authentic")
        second_challenge = bytes.fromhex(rsp['c2'])                # need to replace with some random challenge
        
    
    # Step-3: Send request for give challenge
    second_response = puf.demo_puf(second_challenge)
    nonce = lwmauth.ram("read","nonce")
    nonce = bytes.fromhex(nonce)
    lwmauth.ram("increment","nonce")
    lwmauth.send_challenge_response(trusted_server,second_response,nonce,session_token)

    # Step-4: Generate key and use it for secure communication
    key = lwmauth.keygen(first_response,second_response)
    lwmauth.ram("write", "key", key.hex())

    return 1

def secure_communication():
    nonce = lwmauth.ram("read","nonce")
    nonce = bytes.fromhex(nonce)
    lwmauth.ram("increment","nonce")

    key = lwmauth.ram("read","key")
    key = bytes.fromhex(key)
    
    session_token = lwmauth.ram("read","session_token")
    message = b'hello lwm-auth'
    lwmauth.send_message_securely(trusted_server,session_token,message,nonce,key)

if __name__ == "__main__":
    try:
        choice = int(input("Enter \n1. for Mutual Authentication Test \n2. for Secure Communication Test\n"))
        if choice == 1:
            done = mutual_auth()
            print("Success: ", done)
        elif choice == 2:
            secure_communication()
        else:
            print("Invalid choice\n")
    except ValueError:
        print("Invalid input. Please enter a valid integer (1 or 2).")
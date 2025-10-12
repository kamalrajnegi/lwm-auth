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
flash_memory = "RWM.json"
random_access_memory= "RAM.json"
param1 = "hello"
device_id = "demo_device"

def mutual_auth():
    # Step-1: Send request for authentication
    rsp = lwmauth.send_auth_request(trusted_server,device_id)

    # Encode to json
    rsp = json.loads(rsp)

    # Step-2: Authenticate server
    first_challenge = bytes.fromhex(rsp['c1'])
    first_response = puf.demo_puf(first_challenge)
    session_id = rsp['nonce']
    auth_tag1 = rsp['tag1']
    authentic = lwmauth.auth_server(first_response,session_id,auth_tag1)

    if(authentic):
        print("Server is authentic")
        second_challenge = rsp['c2']
    else:
        print("Server is not authentic")
        # second_challenge = random_challenge
    
    # Step-3: Send request for give challenge
    second_challenge = bytes.fromhex(rsp['c2'])
    second_response = puf.demo_puf(second_challenge)
    nonce = rsp['nonce']                                                            #need to update the nonce
    lwmauth.send_challenge_response(trusted_server,second_response,nonce,session_id)                    #original nonce is now token for session

    # Step-4: Generate key and use it for secure communication
    key = lwmauth.keygen(first_response,second_response)
    with open("temp_data.txt", "w") as f:
        f.write(key.hex())

    return key

def secure_communication():
    with open("temp_data.txt", "r") as f:
        key = f.read().strip()
    key = byte_data = bytes.fromhex(key)
    nonce = b'\x00\x00x\00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    session_id = nonce.hex()
    message = b'hello lwm-auth'
    lwmauth.send_message_securely(trusted_server,session_id,message,nonce,key)

if __name__ == "__main__":
    try:
        choice = int(input("Enter \n1. for Mutual Authentication Test \n2. for Secure Communication Test\n"))
        if choice == 1:
            key = mutual_auth()
            print("Shared Key: ", key.hex())
        elif choice == 2:
            secure_communication()
        else:
            print("Invalid choice\n")
    except ValueError:
        print("Invalid input. Please enter a valid integer (1 or 2).")
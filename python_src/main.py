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
    ch1 = bytes.fromhex(rsp['c1'])
    r1 = puf.demo_puf(ch1)
    authentic = lwmauth.auth_server(r1,rsp['nonce'],rsp['tag1'])

    if(authentic):
        print("Server is authentic")
    else:
        print("Server is not authentic")
    
    # Step-3: Send request for give challenge
    ch2 = bytes.fromhex(rsp['c2'])
    r2 = puf.demo_puf(ch2)
    tag2 = lwmauth.send_challenge_response(r2,rsp['nonce'])

    # Step-4: Generate key and use it for secure communication
    key = lwmauth.keygen(r1,r2)

    return key

def secure_communication():
    lwmauth.send_message_securely()

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
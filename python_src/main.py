"""
Main function for mutual authentication and key agreement.
Also, function for secure communication with the server.
------------------------------
Coded By:
Kamal Raj (kamal@kamalraj.in)
------------------------------
"""

import helper_functions as lwmauth

trusted_server = "https://lwm-auth.org/demo-auth"
flash_memory = "RWM.json"
random_access_memory= "RAM.json"
param1 = "hello"
device_id = "demo_device"

def mutual_auth():
    # Step-1: Send request for authentication
    rsp = lwmauth.send_auth_request(trusted_server,device_id)

    # Step-2: Authenticate server
    # lwmauth.auth_server(rsp)
    
    # Step-3: Send request for give challenge
    # lwmauth.send_challenge_response(trusted_server)

    # Step-4: Generate key and use it for secure communication
    # lwmauth.keygen(r1,r2)

def secure_communication():
    lwmauth.send_message_securely()

if __name__ == "__main__":
    try:
        choice = int(input("Enter \n1. for Mutual Authentication Test \n2. for Secure Communication Test\n"))
        if choice == 1:
            mutual_auth()
        elif choice == 2:
            secure_communication()
        else:
            print("Invalid choice\n")
    except ValueError:
        print("Invalid input. Please enter a valid integer (1 or 2).")
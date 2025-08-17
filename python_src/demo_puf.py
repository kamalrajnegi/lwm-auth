"""
A simple demo PUF constructed using ASCON HASH. In a real device, it can be a PUF circuit.
No random errors are added in this version, it'll be added in the future.
------------------------------
Coded By:
Kamal Raj (kamal@kamalraj.in)
------------------------------
"""
import ascon

# puf_uid variable is to simulate physical property of the PUF.
# It must be unique for each and every devices or PUF. No two or more devices or PUF can have same UID
puf_uid = b'abcdef' 

# Demo PUF constructed using ASCON Hash function. 
def demo_puf(challenge):
    make_puf = puf_uid + challenge
    response = ascon.ascon_hash(message=make_puf)
    return response

if __name__ == "__main__":
    challenge = b'0001'
    response = demo_puf(challenge)
    print(response.hex())
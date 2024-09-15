## Overview

JWack is a powerful security tool designed for interacting with JSON Web Tokens (JWT). It allows users to decode JWTs, perform brute-force attacks on secrets, test for vulnerabilities like alg:none, modify JWT payloads, sign tokens with custom RSA keys and JWK headers, and test injection attacks on the jku and kid parameters. The tool is designed to assist security researchers, penetration testers, and developers in evaluating the security of JWT implementations in web applications.
## Features
1. **JWT Decode:** Decodes the JWT header, payload, and signature for analysis.
2. **JWT Secret Bruteforce:** Brute forces the secret used to sign the JWT using a wordlist.
3. **alg Attack:** Exploits weak JWT implementations where the alg field can be tampered with.
4. **Parameter Editing:** Modify or add parameters to the JWT header and payload.
5. **Unverified Signature Bypass:** Test the system’s vulnerability to unsigned JWTs by creating a new token with altered claims while keeping the signature intact.
6. **JWK (JSON Web Key) Support:** Generate an RSA key pair, convert the public key into JWK format, and sign the JWT with the RSA private key.
7. **JKU & kid Parameter Injection (Coming Soon):** Exploit potential vulnerabilities in JWT implementations by injecting malicious values into the JKU and kid parameters. (Currently under development).
## Usage
The tool can be run from the command line using various options and flags. Below is a detailed guide on each command.
### Command Line Options

```
-f, --file <path> Path to the wordlist for brute-force attack.

-t, --token <JWT> JWT to decode, edit, or sign.

-d, --decode Decode the JWT token.

-bf, --bruteforce Brute-force the JWT secret.

-n, --none Perform alg:none attack.

-e, --edit Edit header or payload values.

-us, --unverified Generate token with altered values using the same signature (Unverified Signature Bypass).

-jwk, --jwk Generate a JWK key and sign the JWT.

-jku, --jku Perform JKU header injection.

-kid, --kid Inject malicious `kid` parameter values (Coming Soon).
```
## Usage
### 1. **`Decoding a JWT`**
`python jwack.py -t <JWT> --decode`
This will output the decoded header and payload of the JWT.
### 2. **`Brute Forcing JWT Secret`**
`python jwack.py -t <JWT> -f <wordlist> --bruteforce`
This will try each secret in the provided wordlist to match the JWT signature.
### 3. **`alg Attack`**
`python jwack.py -t <JWT> --none`
This exploits the vulnerable `alg` parameter by changing it to `none` and removing the signature.
### 4. **`Editing JWT Payload`**
`python jwack.py -t <JWT> --edit`
The tool will prompt you to edit or add new parameters to the header or payload.
### 5. **`Unverified Signature Bypass`**
`python jwack.py -t <JWT> --unverified`
This will modify the JWT claims but retain the original signature to test if the system verifies signatures properly.
### 6. **`Generate and Sign JWT with JWK`**
`python jwack.py -t <JWT> --jwk`
This generates an RSA key pair, converts the public key to a JWK, and signs the token with the RSA private key.
### 7. **`JKU Header Injection`**
This feature will allow users to inject a malicious URL in the `jku` header, which could be used to retrieve a malicious key set.
`python jwack.py -t <JWT> --jku`
### 8. **`kid Parameter Injection (Coming Soon)`**
This feature will allow users to inject custom `kid` values to test if the server resolves the key in an unsafe manner, such as via file inclusion or remote key requests.
`python jwack.py -t <JWT> --kid`

## **Functions Description**

### **1. `jwt_decode(token)`**

- **Purpose**: Decodes the JWT and returns its header, payload, and signature.
- **Parameters**: `token` - The JWT string.
- **Returns**: Decoded header and payload.

### **2. `jwt_secret_bruteforce(file_path, token)`**

- **Purpose**: Performs a brute-force attack on the JWT signature using a wordlist of candidate secrets.
- **Parameters**:
    - `file_path` - Path to the wordlist.
    - `token` - The JWT to be brute-forced.
- **Returns**: The secret used to sign the JWT if found.

### **3. `alg_none(token)`**

- **Purpose**: Exploits JWTs that allow changing the algorithm to `none`.
- **Parameters**: `token` - The JWT string.
- **Returns**: Modified JWT with the `none` algorithm and no signature.

### **4. `edit_param(token)`**

- **Purpose**: Allows the user to interactively edit or add parameters to the JWT's header or payload.
- **Parameters**: `token` - The JWT string.
- **Returns**: Modified JWT.

### **5. `generate_rsa_jwk(token)`**

- **Purpose**: Generates an RSA key pair and outputs the public key in JWK format.
- **Parameters**: `token` - The JWT string (used to extract the `kid` if present).
- **Returns**: JWK and private RSA key.

### **6. `sign_with_jwk(token)`**

- **Purpose**:

Signs the JWT with the generated RSA private key using the JWK header format.

- **Parameters**: `token` - The JWT string to be signed.
- **Returns**: Signed JWT with JWK and RSA private key.

### **7. `unverified_signature_bypass(token)`**

- **Purpose**: Alters the JWT payload and retains the same signature to test systems that don't properly verify signatures.
- **Parameters**: `token` - The JWT string.
- **Returns**: JWT with modified claims and the original signature intact.

### **8. `jku_header_injection(token)` (Coming Soon)**

- **Purpose**: Injects a custom URL into the `jku` field to point to an external key set.
- **Parameters**: `token` - The JWT string.
- **Returns**: JWT with the malicious `jku` value.

### **9. `kid_parameter_injection(token)` (Coming Soon)**

- **Purpose**: Injects malicious or custom `kid` values to test how the server resolves the key used to sign the token.
- **Parameters**: `token` - The JWT string.
- **Returns**: JWT with an altered `kid` value.

## **Conclusion**

**JWack** is a versatile tool aimed at security professionals and developers who need to test the robustness of JWT implementations. With upcoming features like JKU and `kid` injection, it will become even more comprehensive. Use this tool responsibly in your security assessments to uncover vulnerabilities in JWT authentication and authorization mechanisms.
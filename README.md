# JWack

JWack is a powerful security tool designed for interacting with JSON Web Tokens (JWT). It allows users to decode JWTs, perform brute-force attacks on secrets, test for vulnerabilities like alg:none, modify JWT payloads, and sign tokens with custom RSA keys and JWK headers. The tool is designed to assist security researchers, penetration testers, and developers in evaluating the security of JWT implementations in web applications.


## Features

**JWT Decode:** Decodes the JWT header, payload, and signature for analysis.
**JWT Secret Bruteforce:**Brute forces the secret used to sign the JWT using a wordlist.
alg
**Attack:** Exploits weak JWT implementations where the alg field can be tampered with.
**Parameter Editing:** Modify or add parameters to the JWT header and payload.
**Unverified Signature Bypass:** Test the system’s vulnerability to unsigned JWTs by creating a new token with altered claims while keeping the signature intact.
**JWK (JSON Web Key) Support:** Generate an RSA key pair, convert the public key into JWK format, and sign the JWT with the RSA private key.

## Usage
-f, --file <path>        Path to the wordlist for brute-force attack.
-t, --token <JWT>        JWT to decode, edit, or sign.
-d, --decode             Decode the JWT token.
-bf, --bruteforce        Brute-force the JWT secret.
-n, --none               Perform alg:none attack.
-e, --edit               Edit header or payload values.
-us, --unverified        Generate token with altered values using the same signature (Unverified Signature Bypass).
-jwk, --jwk              Generate a JWK key and sign the JWT.


## Functions Description

### 1. jwt_decode(token)
**Purpose:** Decodes the JWT and returns its header, payload, and signature.
**Parameters:** token - The JWT string.
**Returns:** Decoded header and payload.

### 2. jwt_secret_bruteforce(file_path, token)
**Purpose:** Performs a brute-force attack on the JWT signature using a wordlist of candidate secrets.
**Parameters:**
file_path - Path to the wordlist.
token - The JWT to be brute-forced.
**Returns:** The secret used to sign the JWT if found.

### 3. alg_none(token)
**Purpose:** Exploits JWTs that allow changing the algorithm to none.
**Parameters:** token - The JWT string.
**Returns:** Modified JWT with the none algorithm and no signature.

### 4. edit_param(token)
**Purpose:** Allows the user to interactively edit or add parameters to the JWT's header or payload.
**Parameters:** token - The JWT string.
**Returns:** Modified JWT.

### 5. generate_rsa_jwk(token)
**Purpose:** Generates an RSA key pair and outputs the public key in JWK format.
**Parameters:** token - The JWT string (used to extract the kid if present).
**Returns:** JWK and private RSA key.

### 6. sign_with_jwk(token)
**Purpose:** Signs a JWT with a generated RSA key and embeds the JWK in the JWT header.
**Parameters:** token - The JWT string.
**Returns:** A signed JWT with the RSA key.

## Error Handling
**Invalid JWT Token Format:** Ensure the JWT is correctly formatted with three sections: header, payload, and signature.
**Brute Force Failures:** If no secret is found, consider expanding the wordlist.
**JWK Generation Error:** Ensure the JWT contains a valid kid or leave it blank.

## Potential Use Cases
**Penetration Testing:** Test web applications for insecure JWT handling and vulnerabilities.
**Developer Education:** Help developers understand and mitigate JWT-related security risks.
**Token Manipulation:** Modify JWTs for testing various claims and parameters in real-world applications.

## Limitations
Brute-force attacks are dependent on the size of the wordlist.
Signature verification depends on the correct implementation of the algorithm.
RSA signing requires additional time due to key generation.

## Conclusion
JWack is a comprehensive tool for JWT manipulation and security testing. With features like decoding, brute-forcing, modifying claims, and signing tokens with RSA keys, it serves as a valuable resource for security professionals.

## To be done
- **JKU Parameter Injection**: Find and exploit vulnerabilities in the `jku` (JWK Set URL) parameter that can lead to unauthorized key retrieval and JWT manipulation.
- **kid Parameter Injection**: Identify and exploit vulnerabilities in the `kid` (Key ID) parameter, allowing for key injection attacks.

## work in progress!

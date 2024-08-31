# JWack

**JWack** is a tool designed to scan, decode, and exploit vulnerabilities in JSON Web Tokens (JWT). It provides security professionals with a suite of features to identify and exploit common JWT misconfigurations and weaknesses in web applications.

## Features

- **JWT Decode**: Effortlessly decode JWTs to analyze the header, payload, and signature components.
- **JWT Secret Brute Force**: Perform brute-force attacks to crack weak JWT secret keys.
- **Scan for None Algorithm**: Detect JWTs that use the `none` algorithm, which can allow attackers to bypass signature verification.
- **Scan for Unverified Signature Bypass**: Identify scenarios where JWT signatures are not properly verified, leading to potential security bypasses.
- **Edit parameters and add parameters**: Edit the values of paramters in each section and add all the other paramters. 


## To be done
- **Scanning and Exploiting JWK Parameter Injections**: Detect and exploit vulnerabilities in JSON Web Keys (JWK) parameters.
- **Scanning and Exploiting JKU Parameter Injection**: Find and exploit vulnerabilities in the `jku` (JWK Set URL) parameter that can lead to unauthorized key retrieval and JWT manipulation.
- **Scanning and Exploiting kid Parameter Injection**: Identify and exploit vulnerabilities in the `kid` (Key ID) parameter, allowing for key injection attacks.

## work in progress!

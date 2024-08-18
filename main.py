import base64
import json

# JWT token
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
header_b64, payload_b64, signature_b64 = jwt_token.split('.')

header = base64.urlsafe_b64decode(header_b64 + "==").decode('utf-8')
payload = base64.urlsafe_b64decode(payload_b64 + "==").decode('utf-8')

header_json = json.loads(header)
payload_json = json.loads(payload)
header_json['alg'] = 'HS256'
print("Decoded Header:", header_json)
print("Decoded Payload:", payload_json)

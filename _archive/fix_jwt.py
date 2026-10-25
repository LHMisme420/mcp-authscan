import re

with open('app.py', 'r') as f:
    content = f.read()

# Fix create_access_token calls
content = re.sub(r'create_access_token\(identity=org_id\)', 'create_access_token(identity=str(org_id))', content)

# The get_jwt_identity() returns string, keep it as string
with open('app.py', 'w') as f:
    f.write(content)

print("✅ JWT fixed")

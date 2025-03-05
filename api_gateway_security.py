# api_gateway_security.py

from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

SECRET_KEY = 'your_secret_key'

@app.route('/secure-endpoint', methods=['POST'])
def secure_endpoint():
    token = request.headers.get('Authorization').split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'message': 'Secure data'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 403

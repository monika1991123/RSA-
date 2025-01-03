print("Starting the application...")  # 新添加的测试行
from flask import Flask, render_template, jsonify, request
from rsa_crypto import RSACrypto
import json

app = Flask(__name__)
crypto = RSACrypto()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    try:
        private_key, public_key = crypto.generate_key_pair()
        return jsonify({
            'status': 'success',
            'private_key': private_key,
            'public_key': public_key
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        public_key = data['public_key']
        plaintext = data['plaintext']
        
        ciphertext = crypto.encrypt(public_key, plaintext)
        return jsonify({
            'status': 'success',
            'ciphertext': ciphertext
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        private_key = data['private_key']
        ciphertext = data['ciphertext']
        
        plaintext = crypto.decrypt(private_key, ciphertext)
        return jsonify({
            'status': 'success',
            'plaintext': plaintext
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


if __name__ == '__main__':
    app.run(debug=True, port=5001)

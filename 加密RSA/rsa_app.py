from flask import Flask, request, jsonify, send_file
from rsa_crypto import RSACrypto
import os

app = Flask(__name__)
crypto = RSACrypto()

@app.route('/')
def index():
    return send_file('templates/index.html')

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
    data = request.get_json()
    public_key = data.get('public_key')
    plaintext = data.get('plaintext')
    
    if not public_key or not plaintext:
        return jsonify({
            'status': 'error',
            'message': '公钥和明文不能为空'
        }), 400
    
    try:
        ciphertext = crypto.encrypt(public_key, plaintext)
        return jsonify({
            'status': 'success',
            'ciphertext': ciphertext
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    private_key = data.get('private_key')
    ciphertext = data.get('ciphertext')
    
    if not private_key or not ciphertext:
        return jsonify({
            'status': 'error',
            'message': '私钥和密文不能为空'
        }), 400
    
    try:
        plaintext = crypto.decrypt(private_key, ciphertext)
        return jsonify({
            'status': 'success',
            'plaintext': plaintext
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

@app.route('/save-file', methods=['POST'])
def save_file():
    data = request.get_json()
    content = data.get('content')
    filename = data.get('filename')
    
    if not content or not filename:
        return jsonify({
            'status': 'error',
            'message': '内容和文件名不能为空'
        }), 400
    
    try:
        desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
        file_path = os.path.join(desktop_path, filename)
        with open(file_path, 'w') as f:
            f.write(content)
        return jsonify({
            'status': 'success',
            'message': f'文件已保存到桌面：{filename}'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)

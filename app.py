import time
import json
import hashlib
import rsa
from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256



# Define block structure
class Block:
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

# Define blockchain rules
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

blockchain = Blockchain()

app = Flask(__name__)

# Implement PoW consensus algorithm
def proof_of_work(previous_proof):
    new_proof = 1
    check_proof = False
    while check_proof is False:
        hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
        if hash_operation[:4] == '0000':
            check_proof = True
        else:
            new_proof += 1
    return new_proof

# Define wallet structure
class Wallet:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def sign_transaction(self, transaction):
        hashed_transaction = hashlib.sha256(json.dumps(transaction).encode()).hexdigest()
        return rsa.sign(hashed_transaction.encode(), self.private_key, 'SHA-256')

    def verify_transaction(self, transaction, signature):
        hashed_transaction = hashlib.sha256(json.dumps(transaction).encode()).hexdigest()
        try:
            rsa.verify(hashed_transaction.encode(), signature, self.public_key)
            return True
        except:
            return False

# Initialize Flask app
app = Flask(__name__)

# Initialize blockchain and wallet
blockchain = Blockchain()
wallet = Wallet()

# Define API routes
@app.route('/blockchain', methods=['GET'])
def get_blockchain():
    response = {
        'chain': [vars(block) for block in blockchain.chain],
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/transaction', methods=['POST'])
def add_transaction():
    data = request.get_json()
    required_fields = ['sender', 'recipient', 'amount']
    if not all(field in data for field in required_fields):
        return 'Missing fields', 400
    transaction = {
        'sender': data['sender'],
        'recipient': data['recipient'],
        'amount': data['amount']
    }
    signature = wallet.sign_transaction(transaction)
    if wallet.verify_transaction(transaction, signature):
        blockchain.add_block(Block(len(blockchain.chain), transaction, blockchain.get_latest_block().hash))
        response = {
            'message': 'Transaction added successfully'
        }
        return jsonify(response), 201
    else:
        return 'Invalid transaction', 

@app.route('/mine', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_latest_block()
    previous_proof = proof_of_work(previous_block.index)
    transaction = {
    'sender': '0',
    'recipient': wallet.public_key,
    'amount': 1
    }
    new_block = Block(len(blockchain.chain), transaction, previous_block.hash)
    blockchain.add_block(new_block)
    response = {
        'message': 'Block mined successfully',
        'index': new_block.index,
        'timestamp': new_block.timestamp,
        'data': new_block.data,
        'previous_hash': new_block.previous_hash,
        'hash': new_block.hash
        }
    return jsonify(response), 200

@app.route('/wallet', methods=['POST'])
def create_wallet():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    wallet = {
        'private_key': private_key,
        'public_key': public_key
    }
    return jsonify(wallet), 201


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
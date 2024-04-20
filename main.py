import os
import json
import hashlib
import time
import string

# Define constants
BLOCK_SIZE_LIMIT = 1000000
SIG_OPERATIONS_LIMIT = 20000
DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"

# Function to hash data using SHA-256
def sha256(data):
    return hashlib.sha256(data).digest()

# Function to perform double SHA-256 hashing
def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# Function to validate the block's size
def validate_block_size(block):
    block_size = len(str(block).encode('utf-8'))
    return block_size <= BLOCK_SIZE_LIMIT

# Function to validate the number of signature operations
def validate_signature_operations(block):
    total_sig_operations = 0
    for tx in block['vin']:
        if 'witness' in tx:
            for witness in tx['witness']:
                total_sig_operations += len(witness.split()) - 1  # Counting the number of signature operations
    return total_sig_operations <= SIG_OPERATIONS_LIMIT

# Function to validate transaction inputs
def validate_transaction_inputs(block):
    for tx in block['vin']:
        if tx['is_coinbase']:  # Skip validation for coinbase transactions
            continue
        # Validate prevout scriptpubkey
        prevout_scriptpubkey_hash = double_sha256(bytes.fromhex(tx['prevout']['scriptpubkey']))
        tx['prevout']['scriptpubkey_hash'] = prevout_scriptpubkey_hash.hex()  # Add scriptpubkey_hash to block data
        if prevout_scriptpubkey_hash.hex() != tx['prevout']['scriptpubkey_hash']:
            return False
        # Validate scriptsig
        if tx['scriptsig'] != "":
            return False  # Empty scriptsig expected
    return True

# Function to validate transaction outputs
def validate_transaction_outputs(block):
    for txout in block['vout']:
        # Validate scriptpubkey
        scriptpubkey_hash = double_sha256(bytes.fromhex(txout['scriptpubkey']))
        txout['scriptpubkey_hash'] = scriptpubkey_hash.hex()  # Add scriptpubkey_hash to block data
        if scriptpubkey_hash.hex() != txout['scriptpubkey_hash']:
            return False
    return True

# Function to validate the entire block
def validate_block(block):
    if not validate_block_size(block):
        return False, "Block size exceeds limit"
    if not validate_signature_operations(block):
        return False, "Exceeded signature operations limit"
    if not validate_transaction_inputs(block):
        return False, "Invalid transaction inputs"
    if not validate_transaction_outputs(block):
        return False, "Invalid transaction outputs"
    return True, "Block is valid"

# Function to load transactions from the mempool folder
def load_transactions(mempool_path='mempool/'):
    valid_transactions = []
    invalid_transactions = []
    try:
        for filename in os.listdir(mempool_path):
            if filename.endswith('.json'):
                with open(os.path.join(mempool_path, filename), 'r') as file:
                    try:
                        data = json.load(file)
                        valid, message = validate_block(data)
                        if valid:
                            valid_transactions.append(data)
                        else:
                            invalid_transactions.append((filename[:-5], message))
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON from {filename}")
                        invalid_transactions.append((filename[:-5], "Invalid JSON format"))
    except FileNotFoundError:
        print(f"Directory not found: {mempool_path}")
    except Exception as e:
        print(f"An error occurred while loading transactions: {e}")
    return valid_transactions, invalid_transactions

# Function to serialize a transaction
def serialize_transaction(transaction):
    if transaction is None:
        return ""
    return json.dumps(transaction, separators=(',', ':'))

# Function to serialize the block header
def serialize_block_header(block_header):
    serialized_header = ""
    serialized_header += str(block_header["version"])
    serialized_header += str(block_header["previous_block_hash"])
    serialized_header += str(block_header["merkle_root"])
    serialized_header += str(block_header["timestamp"])
    serialized_header += str(block_header["bits"])
    serialized_header += str(block_header["nonce"])
    return serialized_header

# Function to create a block header
def create_block_header(merkle_root, timestamp, previous_block_hash, nonce):
    return {
        "version": "04000000",  
        "previous_block_hash": previous_block_hash,
        "merkle_root": merkle_root,
        "timestamp": str(timestamp),
        "bits": "ffff0000",  
        "nonce": str(nonce)
    }

# Function to calculate the merkle root
def calculate_merkle_root(transactions):
    if not transactions:
        return None

    # Convert transaction hashes to binary, use double SHA256 of an empty string for missing txids
    hash_list = []
    for tx in transactions:
        tx_hash = tx.get('txid', '')
        hash_list.append(double_sha256(bytes.fromhex(tx_hash))[::-1])

    while len(hash_list) > 1:
        new_hash_list = []
        # Process pairs. For odd length, the last is repeated.
        for i in range(0, len(hash_list), 2):
            left = hash_list[i]
            right = hash_list[i + 1] if i + 1 < len(hash_list) else left
            new_hash = double_sha256(left + right)
            new_hash_list.append(new_hash)
        hash_list = new_hash_list

    return hash_list[0][::-1].hex() if hash_list else None

# Function to mine a block
def mine_block(transactions, previous_block_hash):
    timestamp = int(time.time())
    merkle_root = calculate_merkle_root(transactions)
    block_header = create_block_header(merkle_root, timestamp, previous_block_hash, 0)
    block_header_serialized = serialize_block_header(block_header)
    # Placeholder for mining logic
    nonce = 0
    while True:
        block_hash = double_sha256((block_header_serialized + str(nonce)).encode('utf-8'))
        if int(block_hash[::-1].hex(), 16) < int(DIFFICULTY_TARGET, 16):
            break
        nonce += 1
    block_header = create_block_header(merkle_root, timestamp, previous_block_hash, nonce)
    #block_header_serialized = serialize_block_header(block_header)
    return block_header, nonce, block_hash[::-1].hex()

# Function to write output to output.txt
def write_output(block_header, coinbase_tx, txids, block_hash):
    with open('output.txt', 'w') as f:
        f.write(serialize_block_header(block_header) + '\n')
        f.write(serialize_transaction(coinbase_tx) + '\n')
        f.write(block_hash + '\n')  # Write the block hash
        for txid in txids:
            f.write(txid + '\n')

# Main function
'''def main():
    valid_transactions, invalid_transactions = load_transactions()
    try:
        if not valid_transactions:
            print("No valid transactions to mine.")
            return
        coinbase_tx = valid_transactions[0]  # Assuming the first transaction is the coinbase transaction
        previous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # Initialize previous_block_hash
        block_transactions = valid_transactions[:]  # Make a copy of valid_transactions for this block
        block_transactions.pop(0)  # Remove coinbase transaction from block transactions
        
        # Calculate txids for block transactions
        txids = []
        for tx in block_transactions:
            txid = tx.get('txid')
            if txid is None:
                # Calculate txid if it's missing
                serialized_tx = serialize_transaction(tx)
                if not all(c in string.hexdigits for c in serialized_tx):
                    print(f"Transaction serialization error: {serialized_tx}")
                    continue  # Skip invalid transaction
                txid = double_sha256(bytes.fromhex(serialized_tx))[::-1].hex()
            txids.append(txid)
        
        block_header, nonce, block_hash = mine_block(block_transactions, previous_block_hash)
        write_output(block_header, coinbase_tx, txids, block_hash)
    except Exception as e:
            print(e)
'''
def main():
    valid_transactions, invalid_transactions = load_transactions()
    try:
        if not valid_transactions:
            print("No valid transactions to mine.")
            return
        
        # Find the coinbase transaction
        coinbase_tx = valid_transactions[0]
        '''
        for tx in valid_transactions:
            if 'is_coinbase' in tx and tx['is_coinbase']:
                coinbase_tx = tx
                break
        
            if coinbase_tx is None:
               print("Coinbase transaction not found.")
'''
        # Remove the coinbase transaction from the list of transactions
        block_transactions = [tx for tx in valid_transactions if not tx.get('is_coinbase')]

        previous_block_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"  # Initialize previous_block_hash
        
        # Calculate txids for block transactions
        txids = []
        for tx in block_transactions:
            txid = tx.get('txid')
            if txid is None:
                # Generate a unique identifier for the transaction
                txid = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
            txids.append(txid)

        # Mine the block
        block_header, nonce, block_hash = mine_block(block_transactions, previous_block_hash)
        
        # Write output to file
        write_output(block_header, coinbase_tx, txids, block_hash)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()

import json
import hashlib
from web3 import Web3
from web3.exceptions import ContractLogicError

# ------------------ Ganache Config ------------------
GANACHE_RPC_URL = "http://127.0.0.1:7545"

# ⚠️ Update these values after each Ganache restart/redeploy
CONTRACT_ADDRESS = "0x14cc78292524978057EFB739De4381d38c4b61Bc"
SENDER_ADDRESS = "0x4158fbD19d0D337b6c2be4dC7F6b84Eb731c7e8D"
PRIVATE_KEY = "9581a219ccc0914652998034abf008f436c459ced00ab27d43eb5617198f6cf7"

# ------------------ ABI ------------------
CONTRACT_ABI = json.loads('''[
    {"inputs":[],"stateMutability":"nonpayable","type":"constructor"},
    {"inputs":[{"internalType":"bytes32","name":"certId","type":"bytes32"}],"name":"CertificateAlreadyRegistered","type":"error"},
    {"inputs":[{"internalType":"bytes32","name":"certId","type":"bytes32"}],"name":"CertificateNotFound","type":"error"},
    {"anonymous":false,"inputs":[
        {"indexed":true,"internalType":"bytes32","name":"certId","type":"bytes32"},
        {"indexed":false,"internalType":"string","name":"cid","type":"string"},
        {"indexed":false,"internalType":"string","name":"fileHash","type":"string"},
        {"indexed":true,"internalType":"address","name":"issuer","type":"address"}],
     "name":"CertificateRegistered","type":"event"},
    {"inputs":[
        {"internalType":"bytes32","name":"certId","type":"bytes32"},
        {"internalType":"string","name":"cid","type":"string"},
        {"internalType":"string","name":"fileHash","type":"string"}],
     "name":"registerCertificate","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"certId","type":"bytes32"}],
     "name":"getCertificate","outputs":[
        {"internalType":"string","name":"cid","type":"string"},
        {"internalType":"string","name":"fileHash","type":"string"},
        {"internalType":"address","name":"issuer","type":"address"},
        {"internalType":"uint256","name":"timestamp","type":"uint256"}],
     "stateMutability":"view","type":"function"}
]''')

# ------------------ Web3 Setup ------------------
w3 = Web3(Web3.HTTPProvider(GANACHE_RPC_URL))
if not w3.is_connected():
    raise ConnectionError(f"❌ Failed to connect to Ganache at {GANACHE_RPC_URL}")

sender_address = w3.to_checksum_address(SENDER_ADDRESS)
contract_address = w3.to_checksum_address(CONTRACT_ADDRESS)
contract = w3.eth.contract(address=contract_address, abi=CONTRACT_ABI)

# ------------------ Utility: Generate cert_id ------------------
def generate_cert_id(cert_name, student_username):
    """
    Generate a cert_id compatible with Solidity bytes32 input.
    Must match exactly the logic used when uploading certificate.
    """
    combined = f"{cert_name}-{student_username}"
    hex_hash = hashlib.sha256(combined.encode()).hexdigest()
    # Add "0x" prefix for Web3.to_bytes
    return Web3.to_bytes(hexstr="0x" + hex_hash)

# ------------------ Register Certificate ------------------
def register_certificate(cert_id, cid, file_hash, private_key=PRIVATE_KEY, sender_address=sender_address):
    try:
        print("DEBUG: Preparing to register certificate...")
        print("DEBUG cert_id:", cert_id.hex())
        print("DEBUG CID:", cid)
        print("DEBUG file_hash:", file_hash)

        nonce = w3.eth.get_transaction_count(sender_address)
        txn = contract.functions.registerCertificate(cert_id, cid, file_hash).build_transaction({
            "chainId": 1337,
            "gas": 2000000,
            "gasPrice": w3.to_wei("50", "gwei"),
            "nonce": nonce,
        })

        signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        if receipt.status == 1:
            print("✅ Certificate registered successfully")
        else:
            print("❌ Transaction failed")

        return receipt

    except ContractLogicError as e:
        # Solidity revert error
        print(f"❌ Registration failed: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error during registration: {e}")
        return None

# ------------------ Get Certificate ------------------
def get_certificate(cert_id):
    try:
        cert = contract.functions.getCertificate(cert_id).call()
        return {
            "cid": cert[0],
            "file_hash": cert[1],
            "issuer": cert[2],
            "timestamp": cert[3],
        }
    except ContractLogicError as e:
        print(f"❌ Blockchain fetch error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error during fetch: {e}")
        return None

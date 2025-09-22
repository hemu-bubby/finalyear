import hashlib
from web3 import Web3
from certificates.blockchain import get_certificate  # Import your existing function

# ------------------ Shared Function ------------------
def generate_cert_id(cert_name, student_username):
    """
    Generate a cert_id compatible with Solidity bytes32 input.
    Must match exactly the logic used when uploading certificate.
    """
    combined = f"{cert_name}-{student_username}"
    # Convert sha256 hash to bytes32 for Solidity
    return Web3.to_bytes(hexstr=hashlib.sha256(combined.encode()).hexdigest())


if __name__ == "__main__":
    # ------------------ Inputs ------------------
    cert_name = "BE certificate5"
    student_username = "sample"  # Replace with actual username

    # ------------------ Generate cert_id ------------------
    cert_id = generate_cert_id(cert_name, student_username)
    print(f"DEBUG: Generated cert_id (hex): {cert_id.hex()}")  # For debugging

    # ------------------ Fetch certificate ------------------
    record = get_certificate(cert_id)

    # ------------------ Display Result ------------------
    if record:
        print("✅ Certificate found on blockchain:")
        print(f"CID: {record['cid']}")
        print(f"File Hash: {record['file_hash']}")
        print(f"Issuer: {record['issuer']}")
        print(f"Timestamp: {record['timestamp']}")
    else:
        print("❌ Certificate not found on blockchain.")

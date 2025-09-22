import requests
import os
import hashlib

from cryptography.fernet import Fernet

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from .models import Certificate
from .serializers import CertificateSerializer
from .blockchain import register_certificate, get_certificate, generate_cert_id  # Shared functions

# IPFS endpoint
IPFS_API = "http://127.0.0.1:5001/api/v0"

# Ganache account info
GANACHE_ACCOUNT_ADDRESS = "0x4158fbD19d0D337b6c2be4dC7F6b84Eb731c7e8D"
GANACHE_ACCOUNT_PRIVATE_KEY = "9581a219ccc0914652998034abf008f436c459ced00ab27d43eb5617198f6cf7"


def safe_register_certificate(cert_id, cid, file_hash):
    """
    Attempt blockchain registration and handle errors gracefully.
    """
    receipt = register_certificate(cert_id, cid, file_hash, GANACHE_ACCOUNT_PRIVATE_KEY, GANACHE_ACCOUNT_ADDRESS)
    if receipt is None:
        print("⚠️ Registration skipped or failed. Possibly already registered.")
        return False
    if getattr(receipt, "status", 0) != 1:
        print("❌ Transaction reverted on blockchain.")
        return False
    return True


class CertificateUploadAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = CertificateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        certificate = serializer.save(student=request.user)

        try:
            # Generate encryption key
            key = Fernet.generate_key()
            fernet = Fernet(key)

            # Read original file
            with open(certificate.file.path, "rb") as input_file:
                file_data = input_file.read()

            # Encrypt file
            encrypted_data = fernet.encrypt(file_data)

            # Save encrypted file temporarily
            encrypted_path = certificate.file.path + ".enc"
            with open(encrypted_path, "wb") as output_file:
                output_file.write(encrypted_data)

            # Calculate SHA-256 hash of encrypted file
            hash_hex = hashlib.sha256(encrypted_data).hexdigest()

            # Upload encrypted file to IPFS
            with open(encrypted_path, "rb") as f:
                res = requests.post(f"{IPFS_API}/add", files={"file": f})
            res.raise_for_status()
            cid = res.json().get("Hash")
            if not cid:
                return Response({"error": "IPFS returned no CID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Save IPFS info to model
            certificate.cid = cid
            certificate.encryption_key = key.decode()
            certificate.file_hash = hash_hex
            certificate.save()

            # Blockchain registration
            cert_id = generate_cert_id(certificate.certificate_name, certificate.student.username)
            print("DEBUG: Cert ID for blockchain:", cert_id.hex())  # Debug info

            success = safe_register_certificate(cert_id, cid, hash_hex)
            if not success:
                return Response({
                    "warning": "Certificate may already exist on blockchain or registration failed.",
                    "certificate": CertificateSerializer(certificate).data
                }, status=status.HTTP_201_CREATED)

            # Cleanup temporary encrypted file
            os.remove(encrypted_path)

        except requests.RequestException as e:
            return Response({"error": f"IPFS request failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(CertificateSerializer(certificate).data, status=status.HTTP_201_CREATED)


class CertificateVerifyAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        cid = request.data.get("cid")
        if not cid:
            return Response({"error": "CID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            certificate = Certificate.objects.get(cid=cid)

            # Download encrypted file from IPFS
            res = requests.post(f"{IPFS_API}/cat?arg={cid}")
            res.raise_for_status()
            encrypted_file = res.content

            # Compute hash and check with stored
            hash_hex = hashlib.sha256(encrypted_file).hexdigest()
            hash_match = (hash_hex == certificate.file_hash)

            # Fetch blockchain hash and check
            cert_id = generate_cert_id(certificate.certificate_name, certificate.student.username)
            blockchain_data = get_certificate(cert_id)
            blockchain_hash = blockchain_data.get('file_hash') if blockchain_data else None

            blockchain_hash_match = (blockchain_hash == hash_hex)
            valid = hash_match and blockchain_hash_match

            return Response({
                "valid": valid,
                "message": "Certificate is authentic!" if valid else "Hash mismatch! File may be tampered.",
                "certificate": CertificateSerializer(certificate).data,
                "downloaded_file_hash": hash_hex,
                "blockchain_certificate_hash": blockchain_hash,
            }, status=200 if valid else 400)

        except Certificate.DoesNotExist:
            return Response({"valid": False, "message": "Certificate not found"}, status=404)
        except requests.RequestException as e:
            return Response({"error": f"IPFS request failed: {str(e)}"}, status=500)
        except Exception as e:
            return Response({"error": str(e)}, status=500)

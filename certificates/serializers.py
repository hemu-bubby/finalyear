from rest_framework import serializers
from .models import Certificate

class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = ['id', 'student', 'certificate_name', 'file', 'cid', 'uploaded_at', 'encryption_key', 'file_hash']
        read_only_fields = ['cid', 'uploaded_at', 'encryption_key', 'file_hash']

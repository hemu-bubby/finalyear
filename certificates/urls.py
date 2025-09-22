from django.urls import path
from .views import CertificateUploadAPIView, CertificateVerifyAPIView

urlpatterns = [
    path("upload/", CertificateUploadAPIView.as_view(), name="certificate-upload"),
    path("verify/", CertificateVerifyAPIView.as_view(), name="certificate-verify"),
]

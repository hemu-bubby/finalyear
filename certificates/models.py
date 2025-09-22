from django.db import models
from django.conf import settings

class Certificate(models.Model):
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    certificate_name = models.CharField(max_length=200)
    file = models.FileField(upload_to='certificates')
    cid = models.CharField(max_length=255, unique=True, blank=True, null=True)
    encryption_key = models.CharField(max_length=100, blank=True, null=True)
    file_hash = models.CharField(max_length=64, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.certificate_name} - {self.student.username}"

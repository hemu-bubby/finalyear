from rest_framework import generics
from .models import User
from .serializers import UserSerializer

# Signup API
class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

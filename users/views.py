from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import SignUpSerializer
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework.exceptions import ValidationError
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.
class SignUpView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        response = {
            'status': status.HTTP_201_CREATED,
            'message': user.username
        }
        return Response(response)


class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = self.request.data.get('username')
        password = self.request.data.get('password')

        user = authenticate(username=username, password=password)

        if not user:
            raise ValidationError({'message': 'Username yoki parol notogri'})

        refresh_token = RefreshToken.for_user(user)

        response = {
            'status': status.HTTP_201_CREATED,
            'message': 'Siz ruxatdan otdingiz',
            'refresh_token': str(refresh_token),
            'access_token': str(refresh_token.access_token),
        }
        return Response(response)


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(
                {
                    "status": status.HTTP_200_OK,
                    "message": "Siz muvaffaqiyatli logout qildingiz"
                },
                status=status.HTTP_200_OK
            )

        except Exception:
            return Response(
                {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Refresh token noto‘g‘ri yoki yuborilmadi"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

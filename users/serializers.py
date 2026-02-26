from rest_framework import serializers, status, viewsets
from .models import User
from rest_framework.exceptions import ValidationError

class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    conf_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'phone_number', 'address', 'password',
                  'conf_password']

    def validate(self, data):
        password = data.get('password', None)
        conf_password = data.get('conf_password', None)

        if password is None or conf_password is None or password != conf_password:
            response = {
                'status': status.HTTP_400_BAD_REQUEST,
                'message': 'Parollar mos emas yoki xato kiritildi'
            }
            raise ValidationError(response)
        if len([i for i in password if i == ' ']) > 0:
            response = {
                'status': status.HTTP_400_BAD_REQUEST,
                'message': 'Parollar xato kiritildi'
            }
            raise ValidationError(response)

        return data

    def validate_username(self, username):
        if len(username) < 6:
            raise ValidationError({'message': 'Username kamida 7 ta bolishi kerak'})
        elif not username.isalnum():
            raise ValidationError({'message': 'Username da ortiqcha belgilar bolmasligi kerak'})
        elif username[0].isdigit():
            raise ValidationError({'message': 'Username raqam bilan boshlanmasin'})
        return username

    def create(self, validated_data):
        validated_data.pop('conf_password')

        user = User.objects.create_user(
            **validated_data
        )

        return user

class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'phone_number', 'address']

        def update(self, instance, validated_data):
            instance.username = validated_data.get('username', instance.username)
            instance.first_name = validated_data.get('first_name', instance.first_name)
            instance.last_name = validated_data.get('last_name', instance.last_name)
            instance.email = validated_data.get('email', instance.email)
            instance.phone_number = validated_data.get('phone_number', instance.phone_number)
            instance.address = validated_data.get('address', instance.address)

            instance.save()
            return instance

class ProfileViewSerializers(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'phone_number', 'address']


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, atters):
        old_password = atters.get('old_password')
        new_password = atters.get('new_password')
        confirm_password = atters.get('confirm_password')
        if old_password != confirm_password:
            raise ValidationError({
                'status': status.HTTP_400_BAD_REQUEST,
                'message':"eski paro; va yangi parol bir xil bo'lmasligi kerak"
            })
        if new_password is None or confirm_password is None or new_password != confirm_password:
            response = {
                'status': status.HTTP_400_BAD_REQUEST,
                'message': 'Parollar mos emas yoki xato kiritildi'
            }
            raise ValidationError(response)

        if ' ' in new_password:
            raise ValidationError({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': "Parolda bo'sh joy bo'lishi mumkin emas"
            })
        if len(new_password) <= 6:
            raise ValidationError({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': "Parol kamida 6ta belgidan iborat bo'lishi kerak "
            })
        return atters

    def update(self, instance, validated_data):
        user = instance.check_password(validated_data.get('old_password'))
        user.set_password(validated_data.get('new_password'))
        user.save()
        return user


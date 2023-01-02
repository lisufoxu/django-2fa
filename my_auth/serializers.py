from rest_framework import serializers
from two_factor.utils import totp_digits

from django_otp.plugins.otp_email.models import EmailDevice

from my_auth.models import SMSDevice
from my_auth.registry import EMAIL_CODE


class DeviceMethodSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=10)
    verbose_name = serializers.CharField(max_length=100)


class EmailDeviceSerializer(serializers.ModelSerializer):
    code = serializers.ReadOnlyField(default=EMAIL_CODE)
    email = serializers.EmailField(required=True, max_length=254)

    class Meta:
        model = EmailDevice
        fields = ['id', 'name', 'email', 'code', 'confirmed', 'valid_until', 'persistent_id']
        read_only_fields = ['confirmed', 'valid_until']


class SMSDeviceSerializer(serializers.ModelSerializer):
    code = serializers.ReadOnlyField(default=EMAIL_CODE)
    phone_number = serializers.CharField(required=True, max_length=20)

    class Meta:
        model = SMSDevice
        fields = ['id', 'name', 'phone_number', 'code', 'confirmed', 'valid_until', 'persistent_id']
        read_only_fields = ['confirmed', 'valid_until']


class DeviceValidationSerializer(serializers.Serializer):
    persistent_id = serializers.CharField(required=True, max_length=64)
    token = serializers.CharField(required=True, min_length=totp_digits(), max_length=totp_digits())

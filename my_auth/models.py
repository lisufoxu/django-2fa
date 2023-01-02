from django.db import models
from django_otp.models import SideChannelDevice, ThrottlingMixin
from two_factor.gateways import send_sms


class SMSDevice(ThrottlingMixin, SideChannelDevice):
    OTP_SMS_TOKEN_VALIDITY = 300

    phone_number = models.CharField(max_length=20)

    def generate_challenge(self):
        self.generate_token(valid_secs=self.OTP_SMS_TOKEN_VALIDITY)

        send_sms(device=self, token=self.token)

        message = "sent by sms"

        return message

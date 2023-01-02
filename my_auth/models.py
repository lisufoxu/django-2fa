from django.db import models
from django.utils import timezone
from django_otp.models import SideChannelDevice, ThrottlingMixin, VerifyNotAllowed
from two_factor.gateways import send_sms

from my_auth.conf import TOKEN_VALIDITY, TOKEN_FAILURES_LIMIT


class SMSDevice(ThrottlingMixin, SideChannelDevice):
    OTP_SMS_TOKEN_VALIDITY = 300

    phone_number = models.CharField(max_length=20)

    def generate_challenge(self):
        self.generate_token(valid_secs=self.OTP_SMS_TOKEN_VALIDITY)

        send_sms(device=self, token=self.token)

        message = "sent by sms"

        return message

    def verify_is_allowed(self):
        if (self.throttling_failure_count >= TOKEN_FAILURES_LIMIT and
                self.throttling_failure_timestamp is not None):

            elapsed_time = (timezone.now() - self.throttling_failure_timestamp).total_seconds()

            if elapsed_time < TOKEN_VALIDITY:
                return (False,
                        {'reason': VerifyNotAllowed.N_FAILED_ATTEMPTS,
                         'failure_count': self.throttling_failure_count,
                         'locked_until': self.throttling_failure_timestamp + timezone.timedelta(seconds=TOKEN_VALIDITY)}
                        )
            else:
                self.throttle_reset()

        return True, None

    def verify_token(self, token):
        verify_allowed, _ = self.verify_is_allowed()
        if verify_allowed:
            verified = super().verify_token(token)

            if verified:
                self.throttle_reset()
            else:
                self.throttle_increment()
        else:
            verified = False

        return verified

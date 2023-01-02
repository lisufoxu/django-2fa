from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_email.models import EmailDevice

from my_auth.models import SMSDevice


EMAIL_CODE = 'email'
SMS_CODE = 'sms'


class MethodBase:
    model = None
    code = None
    verbose_name = None

    def get_device_from_setup_data(self, request, setup_data, **kwargs):
        return None


class EmailMethod(MethodBase):
    model = EmailDevice
    code = EMAIL_CODE
    verbose_name = _('Email')

    def get_device_from_setup_data(self, request, setup_data, **kwargs):
        if setup_data and not request.user.email:
            request.user.email = setup_data.get('email')
            request.user.save(update_fields=['email'])
        device = EmailDevice.objects.devices_for_user(request.user).first()
        if not device:
            device = EmailDevice(user=request.user, name='default')
        return device


class SMSMethod(MethodBase):
    model = SMSDevice
    code = SMS_CODE
    verbose_name = _('SMS')


class MethodRegistry:
    _methods = []

    def __init__(self):
        self.register(EmailMethod())
        self.register(SMSMethod())

    def register(self, method):
        self._methods.append(method)

    def unregister(self, code):
        self._methods = [m for m in self._methods if m.code != code]

    def get_method(self, code):
        try:
            return [meth for meth in self._methods if meth.code == code][0]
        except IndexError:
            return None

    def get_methods(self):
        return self._methods


registry = MethodRegistry()

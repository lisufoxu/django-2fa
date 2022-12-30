from django import forms
from django_otp.forms import OTPAuthenticationFormMixin


class DeviceSelectionForm(OTPAuthenticationFormMixin, forms.Form):
    otp_device = forms.ChoiceField(choices=[])

    def __init__(self, user, request=None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['otp_device'].choices = self.device_choices(user)

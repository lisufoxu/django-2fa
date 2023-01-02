from django.utils.translation import gettext as _


class SMSConsole:
    @classmethod
    def send_sms(cls, device, token):
        cls._add_message(_('Fake SMS to %(number)s: "Your token is: %(token)s"'),
                         device, token)

    @classmethod
    def _add_message(cls, message, device, token):
        message = message % {'number': device.phone_number,
                             'token': token}
        print(message)

import json

from django.test import TestCase
from django.contrib.auth import get_user
from django.contrib.auth.models import User
from django.urls import reverse
from django_otp.plugins.otp_email.models import EmailDevice
from rest_framework import status


class EmailDeviceTestCase(TestCase):
    def setUp(self):
        username = 'admin'
        email = 'admin@a.com'
        passwd = 'xxx'
        self.user = User.objects.create_user(username, email, passwd)
        self.device = EmailDevice.objects.create(user=self.user, name='default', email=email, confirmed=False)
        self.device.generate_token()
        self.client.login(username=username, password=passwd)

    def test_user_created(self):
        self.assertEqual(User.objects.count(), 1)

    def test_verify_device(self):
        self.assertEqual(self.device.confirmed, False)
        data = {
            'persistent_id': self.device.persistent_id,
            'token': self.device.token,
        }
        response = self.client.post(
            reverse('my_auth:setup-device-complete-list'),
            data=json.dumps(data),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(EmailDevice.objects.get(id=self.device.id).confirmed, True)


class Login2FaTestCase(TestCase):
    username = 'admin'
    email = 'admin@a.com'
    passwd = 'xxx'

    def setUp(self):
        self.user = User.objects.create_user(self.username, self.email, self.passwd)

    @property
    def auth_url(self):
        return reverse('my_auth:login')

    def login_credentials(self):
        return self.client.post(
            self.auth_url,
            data={
                'auth-username': self.username,
                'auth-password': self.passwd,
                'custom_login_view-current_step': 'auth',
            },
        )

    def login_token(self, token):
        self.client.post(
            self.auth_url,
            data={
                'token-otp_token': token,
                'custom_login_view-current_step': 'token',
            },
        )

    def login_select_device(self, device):
        self.client.post(
            self.auth_url,
            data={
                'device-otp_device': device.persistent_id,
                'custom_login_view-current_step': 'device',
            },
        )

    def test_login_no_device(self):
        self.login_credentials()
        self.assertEqual(get_user(self.client).is_authenticated, True)

    def test_login_one_device(self):
        self.device = EmailDevice.objects.create(user=self.user, name='name', email=self.email, confirmed=True)
        self.login_credentials()
        self.assertEqual(get_user(self.client).is_authenticated, False)
        self.device.refresh_from_db()
        self.login_token(self.device.token)
        self.assertEqual(get_user(self.client).is_authenticated, True)

    def test_login_with_device_selection(self):
        self.device1 = EmailDevice.objects.create(user=self.user, name='name1', email=self.email, confirmed=True)
        self.device2 = EmailDevice.objects.create(user=self.user, name='name2', email=self.email, confirmed=True)
        self.login_credentials()
        self.assertEqual(get_user(self.client).is_authenticated, False)
        self.login_select_device(self.device2)
        self.assertEqual(get_user(self.client).is_authenticated, False)
        self.device2.refresh_from_db()
        self.login_token(self.device2.token)
        self.assertEqual(get_user(self.client).is_authenticated, True)

    def test_remembered_device(self):
        # login does not require
        pass

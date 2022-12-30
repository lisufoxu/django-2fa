from django.contrib.auth.forms import AuthenticationForm
from django.http.response import HttpResponse
from django.views import View
from django.utils.translation import gettext as _
from django_otp import user_has_device, devices_for_user
from django_otp.forms import OTPTokenForm
from django_otp.models import Device
from django_otp.plugins.otp_email.models import EmailDevice
from rest_framework import mixins, status
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.validators import ValidationError
from rest_framework.viewsets import GenericViewSet
from two_factor.forms import AuthenticationTokenForm, BackupTokenForm
from two_factor.views.core import LoginView
from two_factor.views.utils import LoginStorage

from my_auth.forms import DeviceSelectionForm
from my_auth.registry import registry, EmailMethod
from my_auth.serializers import DeviceMethodSerializer, EmailDeviceSerializer, DeviceValidationSerializer


class DeviceStorage(LoginStorage):
    def _get_user_device(self):
        id = self.data.get("device_persistent_id")

        return id and Device.from_persistent_id(id)

    def _set_user_device(self, device):
        self.data["device_persistent_id"] = device.persistent_id

    user_device = property(_get_user_device,
                           _set_user_device)


class HasObjectPermission(BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user == obj.user


class AuthenticatedView(View):
    def get(self, request):
        return HttpResponse(request.user.is_authenticated)


class CustomLoginView(LoginView):
    form_list = (
        ('auth', AuthenticationForm),
        ('device', DeviceSelectionForm),
        ('token', AuthenticationTokenForm),
        ('backup', BackupTokenForm),
    )
    storage_name = 'my_auth.views.DeviceStorage'

    def render_next_step(self, form, **kwargs):
        if self.steps.current == 'auth':
            require_2fa = not form.get_user().is_superuser
            if not require_2fa:
                return self.render_done(form, **kwargs)
        return super().render_next_step(form, **kwargs)

    def user_has_any_device(self, user):
        if not user:
            return False
        return user_has_device(self.get_user(), confirmed=True)

    def has_token_step(self):
        return (
            self.user_has_any_device(self.get_user()) and
            not self.remember_agent
        )

    def has_backup_step(self):
        return (
            self.user_has_any_device(self.get_user()) and
            'token' not in self.storage.validated_step_data and
            not self.remember_agent
        )

    def has_device_step(self):
        devices = devices_for_user(self.get_user(), confirmed=True) if self.get_user() else []
        if not devices:
            return False

        return (
            len([d for d in devices]) > 1 and
            not self.remember_agent
        )

    condition_dict = {
        'device': has_device_step,
        'token': has_token_step,
        'backup': has_backup_step,
    }

    def get_device(self, step=None):
        self.device_cache = self.storage.user_device or super().get_device()
        if not self.device_cache:
            try:
                self.device_cache = next(devices_for_user(self.get_user(), confirmed=True))
            except StopIteration:
                pass
        return self.device_cache

    def process_step(self, form):
        if self.steps.current == 'device' and form.is_valid():
            device = Device.from_persistent_id(form.cleaned_data.get('otp_device'))
            if device and device.user == self.get_user():
                self.device_cache = device
                self.storage.user_device = self.device_cache
        return super().process_step(form)

    def get_form_kwargs(self, step=None):
        if step == 'device':
            return {
                'user': self.get_user(),
            }
        return super().get_form_kwargs(step)


class DeviceMethodViewSet(GenericViewSet,
                          mixins.ListModelMixin):
    serializer_class = DeviceMethodSerializer

    def get_queryset(self):
        return None

    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(registry.get_methods(), many=True)
        return Response(serializer.data)


class DeviceMixin:
    serializer_map = {
        EmailDevice: EmailDeviceSerializer
    }


class MyDeviceViewSet(GenericViewSet,
                      mixins.ListModelMixin,
                      DeviceMixin):
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        ret = {}

        for model, serializer_class in self.serializer_map.items():
            code = next((m.code for m in registry.get_methods() if m.model == model), None)
            ret[code] = serializer_class(
                model.objects.devices_for_user(self.request.user), many=True
            ).data

        return Response(ret)


class CreateDeviceMixin(mixins.CreateModelMixin,
                        DeviceMixin):
    _method = None

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_map.get(self._method.model)(data=request.data)
        serializer.is_valid(raise_exception=True)

        device = self._method.model.objects.devices_for_user(self.request.user).filter(
            name=serializer.validated_data.get('name')).first()

        if not device:
            device = serializer.save(user=self.request.user, confirmed=False)

        device.generate_challenge()
        device.save()
        serializer = self.serializer_map.get(self._method.model)(device)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class SetupEmailDeviceViewSet(GenericViewSet,
                              mixins.DestroyModelMixin,
                              CreateDeviceMixin):
    _method = EmailMethod
    queryset = EmailDevice.objects
    serializer_class = EmailDeviceSerializer
    permission_classes = [IsAuthenticated, HasObjectPermission]


class SetupDeviceCompleteViewSet(GenericViewSet,
                                 mixins.CreateModelMixin,
                                 DeviceMixin):
    serializer_class = DeviceValidationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return None

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        device = Device.from_persistent_id(serializer.validated_data.get('persistent_id'))

        if not device or device.user != request.user:
            raise ValidationError(_('Device not found. Please enter a valid persistent_id.'))

        if device.verify_token(serializer.validated_data.get('token')):
            device.confirmed = True
            device.save(update_fields=['confirmed'])
        else:
            raise ValidationError(OTPTokenForm.otp_error_messages.get('invalid_token'))

        serializer = self.serializer_map.get(device.__class__)(device)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

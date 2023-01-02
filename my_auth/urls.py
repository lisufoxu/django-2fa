from django.urls import path, include
from my_auth.views import AuthenticatedView, CustomLoginView, SetupEmailDeviceViewSet, SetupDeviceCompleteViewSet, \
    DeviceMethodViewSet, MyDeviceViewSet, SetupSMSDeviceViewSet
from django.contrib.auth.views import LogoutView
from rest_framework.routers import DefaultRouter


app_name = 'my_auth'

router = DefaultRouter()
router.register('setup-email-device', SetupEmailDeviceViewSet, basename='setup-email-device')
router.register('setup-sms-device', SetupSMSDeviceViewSet, basename='setup-sms-device')
router.register('setup-device-complete', SetupDeviceCompleteViewSet, basename='setup-device-complete')
router.register('device-method', DeviceMethodViewSet, basename='device-method')
router.register('my-device', MyDeviceViewSet, basename='my-device')


urlpatterns = [
    path('', include(router.urls)),
    path('login/', CustomLoginView.as_view(template_name='my_auth/login.html'), name='login'),
    path('logout/', LogoutView.as_view()),
    path('authenticated/', AuthenticatedView.as_view()),
]

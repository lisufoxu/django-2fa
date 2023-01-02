from rest_framework.throttling import UserRateThrottle


class VerifyDeviceThrottle(UserRateThrottle):
    scope = 'verify_2fa_token'

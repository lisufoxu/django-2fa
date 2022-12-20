from django.urls import path
from my_auth.views import AuthenticatedView, CustomLoginView
from django.contrib.auth.views import LogoutView


app_name = 'my_auth'

urlpatterns = [
    path('login/', CustomLoginView.as_view(template_name='my_auth/login.html'), name='login'),
    path('logout/', LogoutView.as_view()),
    path('authenticated/', AuthenticatedView.as_view()),
]

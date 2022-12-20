from django.http.response import HttpResponse
from django.views import View
from two_factor.views.core import LoginView


class AuthenticatedView(View):
    def get(self, request):
        return HttpResponse(request.user.is_authenticated)


class CustomLoginView(LoginView):
    def render_next_step(self, form, **kwargs):
        if self.steps.current == 'auth':
            require_2fa = not form.get_user().is_superuser
            if not require_2fa:
                return self.render_done(form, **kwargs)
        return super().render_next_step(form, **kwargs)

from django.urls import path
from .views import UserCreateView, EmailSubmitView

urlpatterns = [
    path('contact_us/', UserCreateView.as_view(), name='contact'),
    path('submit_email/', EmailSubmitView.as_view(), name='submit_email'),
]
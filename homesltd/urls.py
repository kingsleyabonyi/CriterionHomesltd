from django.urls import path
from .views import UserCreateView

urlpatterns = [
    path('contact_us/', UserCreateView.as_view(), name='contact'),
]
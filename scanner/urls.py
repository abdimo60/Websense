from django.urls import path
from .views import scan_url

urlpatterns = [
    path("scan/", scan_url),
]
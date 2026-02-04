from django.urls import path
from .views import index, scan_url

urlpatterns = [
    path("", index),
    path("api/scan/", scan_url),
]

from django.urls import path
from .views import index, scan_url


# Frontend page and scan API endpoint
urlpatterns = [
    path("", index),
    path("api/scan/", scan_url),
]

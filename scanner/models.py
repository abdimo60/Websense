from django.db import models

class URL(models.Model):
    canonical_url = models.URLField(max_length=2048, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.canonical_url

class Scan(models.Model):
    RISK_UNKNOWN = "unknown"
    RISK_LOW = "low"
    RISK_MEDIUM = "medium"
    RISK_HIGH = "high"

    RISK_CHOICES = [
        (RISK_UNKNOWN, "Unknown"),
        (RISK_LOW, "Low"),
        (RISK_MEDIUM, "Medium"),
        (RISK_HIGH, "High"),
    ]

    CONF_LOW = "low"
    CONF_MEDIUM = "medium"
    CONF_HIGH = "high"

    CONF_CHOICES = [
        (CONF_LOW, "Low"),
        (CONF_MEDIUM, "Medium"),
        (CONF_HIGH, "High"),
    ]

    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name="scans")
    score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=20, choices=RISK_CHOICES, default=RISK_UNKNOWN)
    confidence = models.CharField(max_length=20, choices=CONF_CHOICES, default=CONF_LOW)
    created_at = models.DateTimeField(auto_now_add=True)
    checks = models.JSONField(default=dict, blank=True)

    def __str__(self) -> str:
        return f"Scan {self.id} ({self.risk_level})"
    
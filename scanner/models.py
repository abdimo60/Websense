from django.db import models

# Store a normalised URL once to avoid duplicates
class URL(models.Model):
    canonical_url = models.URLField(max_length=2048, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.canonical_url


# Risk level based on the combined scan signals
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

# Confidence level for the scan result
    CONF_LOW = "low"
    CONF_MEDIUM = "medium"
    CONF_HIGH = "high"

    CONF_CHOICES = [
        (CONF_LOW, "Low"),
        (CONF_MEDIUM, "Medium"),
        (CONF_HIGH, "High"),
    ]

# User facing result shown in the UI
    STATE_SAFE = "SAFE"
    STATE_BE_CAREFUL = "BE_CAREFUL"
    STATE_UNSAFE = "UNSAFE"

    STATE_CHOICES = [
        (STATE_SAFE, "Safe"),
        (STATE_BE_CAREFUL, "Be careful"),
        (STATE_UNSAFE, "Unsafe"),
    ]

    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name="scans")
    score = models.IntegerField(default=0)
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_CHOICES,
        default=RISK_UNKNOWN,
    )
    confidence = models.CharField(
        max_length=20,
        choices=CONF_CHOICES,
        default=CONF_LOW,
    )
    state = models.CharField(
        max_length=20,
        choices=STATE_CHOICES,
        default=STATE_BE_CAREFUL,
    )
    created_at = models.DateTimeField(auto_now_add=True)

# Store raw check results for transparency and debugging
    checks = models.JSONField(default=dict, blank=True)

    def __str__(self) -> str:
        return f"Scan {self.id} ({self.state})"
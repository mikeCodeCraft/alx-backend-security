# ip_tracking/tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login", "/accounts/login/"]

@shared_task
def detect_anomalies():
    """
    Runs hourly to flag suspicious IPs that:
    1. Make more than 100 requests/hour
    2. Access sensitive endpoints
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    ip_request_counts = {}

    for log in logs:
        ip = log.ip_address
        ip_request_counts[ip] = ip_request_counts.get(ip, 0) + 1

        # Check for sensitive path access
        if any(log.path.startswith(path) for path in SENSITIVE_PATHS):
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                reason=f"Accessed sensitive path: {log.path}"
            )

    # Flag IPs with >100 requests/hour
    for ip, count in ip_request_counts.items():
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                reason=f"Exceeded 100 requests/hour (made {count})"
            )

    return f"Anomaly detection completed. Checked {len(ip_request_counts)} IPs."

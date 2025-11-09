import time
import requests
from django.utils import timezone
from django.http import HttpResponseForbidden
from django.conf import settings
from django.core.cache import cache
from .models import RequestLog, BlockedIP


class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # ✅ Skip checks for whitelisted IPs
        if hasattr(settings, "WHITELISTED_IPS") and ip in settings.WHITELISTED_IPS:
            self.log_request(ip)
            return self.get_response(request)

        # ✅ Block if in blacklist (Task 1)
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Forbidden: Your IP has been blocked.")

        # ✅ Rate check (disabled for now, Task 3)
        # if self.get_request_count(ip) > 10:
        #     return HttpResponseForbidden("Too many requests")

        self.log_request(ip)
        return self.get_response(request)

    def get_client_ip(self, request):
        """Extracts client IP even behind proxies"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def get_request_count(self, ip):
        """Count requests in last 60 seconds"""
        one_min_ago = timezone.now() - timezone.timedelta(seconds=60)
        return RequestLog.objects.filter(ip_address=ip, timestamp__gte=one_min_ago).count()

    def log_request(self, ip):
        """Store IP + optional geo lookup"""
        country, city = self.get_geo_data(ip)

        RequestLog.objects.create(
            ip_address=ip,
            timestamp=timezone.now(),
            country=country,
            city=city
        )

    def get_geo_data(self, ip):
        """Return (country, city) with 24h caching"""
        cache_key = f"geo_{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            data = response.json()
            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")
        except Exception:
            country = "Unknown"
            city = "Unknown"

        cache.set(cache_key, (country, city), 60 * 60 * 24)  # 24 hrs
        return country, city

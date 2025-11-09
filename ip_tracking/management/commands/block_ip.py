from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Block an IP address"

    def add_arguments(self, parser):
        parser.add_argument("ip_address", type=str)

    def handle(self, *args, **options):
        ip = options["ip_address"]
        obj, created = BlockedIP.objects.get_or_create(ip_address=ip)
        if created:
            self.stdout.write(self.style.SUCCESS("IP blocked successfully"))
        else:
            self.stdout.write(self.style.WARNING("IP is already blocked"))

from django.core.management.base import BaseCommand
from django.conf import settings
from pathlib import Path
import requests

OPENPHISH_URL = "https://openphish.com/feed.txt"

class Command(BaseCommand):
    help = "Download OpenPhish feed to scanner/data/openphish.txt"

    def handle(self, *args, **options):
        out_path = Path(settings.BASE_DIR) / "scanner" / "data" / "openphish.txt"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        r = requests.get(OPENPHISH_URL, timeout=10)
        r.raise_for_status()

        out_path.write_text(r.text, encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Saved OpenPhish feed to {out_path}"))

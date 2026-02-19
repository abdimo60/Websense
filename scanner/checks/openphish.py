from dataclasses import dataclass
from urllib.parse import urlparse
from pathlib import Path


@dataclass
class OpenPhishResult:
    status: str
    match_url: str | None
    error: str | None


DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "openphish.txt"


def normalize_for_compare(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def check_openphish(url: str) -> OpenPhishResult:
    try:
        if not DATA_FILE.exists():
            return OpenPhishResult("unavailable", None, "feed_missing")

        target = normalize_for_compare(url)

        with open(DATA_FILE, "r", encoding="utf-8") as f:
            for line in f:
                feed_url = line.strip()
                if not feed_url:
                    continue

                feed_norm = normalize_for_compare(feed_url)

                if target == feed_norm:
                    return OpenPhishResult("listed", feed_url, None)

        return OpenPhishResult("not_listed", None, None)

    except Exception as e:
        return OpenPhishResult("unavailable", None, str(e)[:160])

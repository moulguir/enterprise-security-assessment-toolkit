from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def get_hostname(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return parsed.hostname or ""


def is_https(url: str) -> bool:
    parsed = urlparse(normalize_url(url))
    return parsed.scheme == "https"


def safe_filename_from_url(url: str) -> str:
    hostname = get_hostname(url)

    if not hostname:
        return "unknown_target"

    return (
        hostname
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .replace(".", "_")
    )
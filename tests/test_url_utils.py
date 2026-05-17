from sec_assess.utils.url_utils import (
    get_hostname,
    is_https,
    normalize_url,
    safe_filename_from_url,
)


def test_normalize_url_adds_https_when_missing_scheme():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_https_url():
    assert normalize_url("https://example.com") == "https://example.com"


def test_normalize_url_keeps_http_url():
    assert normalize_url("http://example.com") == "http://example.com"


def test_get_hostname_from_https_url():
    assert get_hostname("https://example.com/path") == "example.com"


def test_get_hostname_from_url_without_scheme():
    assert get_hostname("example.com") == "example.com"


def test_is_https_returns_true_for_https():
    assert is_https("https://example.com") is True


def test_is_https_returns_false_for_http():
    assert is_https("http://example.com") is False


def test_safe_filename_from_url():
    assert safe_filename_from_url("https://egela.ehu.eus") == "egela_ehu_eus"
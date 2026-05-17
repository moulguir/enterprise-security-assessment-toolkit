from pathlib import Path

import pytest
from pydantic import ValidationError

from sec_assess.config import ReportFormat, load_config


def test_load_valid_config(tmp_path: Path):
    config_file = tmp_path / "web_scan.yml"

    config_file.write_text(
        """
target:
  name: test-target
  url: https://example.com

scan:
  type: web
  timeout: 10

report:
  format: markdown
  output_dir: reports

risk:
  fail_on_high: false
""",
        encoding="utf-8",
    )

    config = load_config(str(config_file))

    assert config.target.name == "test-target"
    assert str(config.target.url) == "https://example.com/"
    assert config.scan.type == "web"
    assert config.scan.timeout == 10
    assert config.report.format == ReportFormat.markdown
    assert config.report.output_dir == "reports"
    assert config.risk.fail_on_high is False


def test_load_missing_config_file_raises_error():
    with pytest.raises(FileNotFoundError):
        load_config("missing-file.yml")


def test_invalid_url_raises_validation_error(tmp_path: Path):
    config_file = tmp_path / "invalid.yml"

    config_file.write_text(
        """
target:
  name: invalid-target
  url: not-a-valid-url

scan:
  type: web
  timeout: 10
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_config(str(config_file))
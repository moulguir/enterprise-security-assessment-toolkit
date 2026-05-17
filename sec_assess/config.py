from enum import Enum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, HttpUrl


class ReportFormat(str, Enum):
    console = "console"
    markdown = "markdown"
    json = "json"


class TargetConfig(BaseModel):
    name: str = Field(..., description="Human-readable target name.")
    url: HttpUrl = Field(..., description="Target URL to scan.")


class ScanConfig(BaseModel):
    type: Literal["web"] = Field(..., description="Scan type.")
    timeout: int = Field(10, ge=1, le=120, description="HTTP timeout in seconds.")


class ReportConfig(BaseModel):
    format: ReportFormat = Field(ReportFormat.console, description="Report output format.")
    output_dir: str = Field("reports", description="Directory where reports are saved.")


class RiskConfig(BaseModel):
    fail_on_high: bool = Field(False, description="Return a failing exit code on high risk.")


class AppConfig(BaseModel):
    target: TargetConfig
    scan: ScanConfig
    report: ReportConfig = Field(default_factory=ReportConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)


def load_config(config_path: str) -> AppConfig:
    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with path.open("r", encoding="utf-8") as file:
        raw_data = yaml.safe_load(file)

    if raw_data is None:
        raise ValueError(f"Configuration file is empty: {config_path}")

    return AppConfig.model_validate(raw_data)
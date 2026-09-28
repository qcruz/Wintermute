import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")


def get_hackerone_credentials() -> tuple[str, str]:
    username = os.environ.get("HACKERONE_API_USERNAME", "")
    token = os.environ.get("HACKERONE_API_TOKEN", "")
    if not username or not token:
        raise ValueError(
            "HACKERONE_API_USERNAME and HACKERONE_API_TOKEN must be set in .env"
        )
    return username, token


def get_scan_config() -> dict:
    return {
        "max_rps": int(os.environ.get("MAX_REQUESTS_PER_SECOND", "5")),
        "timeout": int(os.environ.get("SCAN_TIMEOUT_SECONDS", "30")),
    }

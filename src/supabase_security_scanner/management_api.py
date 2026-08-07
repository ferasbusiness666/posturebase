from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx


class ManagementApiClient:
    """Read-only subset of the Supabase Management API used by the scanner."""

    def __init__(self, timeout_seconds: float = 15.0) -> None:
        self.timeout_seconds = timeout_seconds

    def fetch_auth_config(self, project_ref: str, access_token: str) -> dict[str, Any]:
        safe_ref = quote(project_ref, safe="")
        url = f"https://api.supabase.com/v1/projects/{safe_ref}/config/auth"
        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.get(url, headers={"Authorization": f"Bearer {access_token}"})
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Management API returned an unexpected Auth configuration response.")
        return payload

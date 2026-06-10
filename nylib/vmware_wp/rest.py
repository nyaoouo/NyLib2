from __future__ import annotations

import base64
import json as _json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from nylib.vmware_wp.errors import RestRequestError, VmwareError, VmwareTimeoutError
from nylib.vmware_wp.results import RestResult

_DEFAULT_CONTENT_TYPE = "application/vnd.vmware.vmw.rest-v1+json"


@dataclass(frozen=True)
class RestBackend:
    base_url: str
    auth: tuple[str, str] | None = None
    default_timeout: float = 120.0

    def _build_url(self, endpoint: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        return self.base_url.rstrip("/") + "/" + endpoint.lstrip("/")

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        json_body=None,
        headers: dict[str, str] | None = None,
        data: bytes | str | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> RestResult:
        url = self._build_url(endpoint)
        method = method.upper()
        effective_timeout = self.default_timeout if timeout is None else timeout

        final_headers = {
            "Accept": _DEFAULT_CONTENT_TYPE,
            "Content-Type": _DEFAULT_CONTENT_TYPE,
        }
        if self.auth is not None:
            user, password = self.auth
            token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
            final_headers["Authorization"] = f"Basic {token}"
        if headers:
            final_headers.update(headers)

        if data is not None:
            body_bytes = data.encode("utf-8") if isinstance(data, str) else data
        elif json_body is not None:
            body_bytes = _json.dumps(json_body).encode("utf-8")
        else:
            body_bytes = None

        request = urllib.request.Request(url, data=body_bytes, method=method, headers=final_headers)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=effective_timeout) as response:
                status = response.status
                body = response.read().decode("utf-8", errors="replace")
                resp_headers = {key: value for key, value in response.headers.items()}
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", errors="replace")
            resp_headers = {key: value for key, value in exc.headers.items()} if exc.headers else {}
        except socket.timeout as exc:
            raise VmwareTimeoutError(
                f"rest request timed out after {effective_timeout}s: {method} {url}",
                timeout=effective_timeout,
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, socket.timeout):
                raise VmwareTimeoutError(
                    f"rest request timed out after {effective_timeout}s: {method} {url}",
                    timeout=effective_timeout,
                ) from exc
            raise VmwareError(f"rest request failed: {method} {url}: {exc.reason}") from exc

        duration = time.monotonic() - start
        result = RestResult(
            backend="rest",
            command=(method, url),
            duration=duration,
            status_code=status,
            text=body,
            headers=resp_headers,
        )
        if check and status >= 400:
            raise RestRequestError(result)
        return result

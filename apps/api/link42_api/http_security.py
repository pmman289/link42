from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any


LOGIN_BODY_LIMIT = 16 * 1024
THIRD_PARTY_BODY_LIMIT = 64 * 1024
AGENT_BODY_LIMIT = 1024 * 1024
LOGO_BODY_LIMIT = 3 * 1024 * 1024
GLOBAL_BODY_LIMIT = 4 * 1024 * 1024


def request_body_limit(path: str) -> int:
    """按接口类型返回请求体上限，未匹配接口使用全局上限。"""

    if path == "/api/auth/login":
        return LOGIN_BODY_LIMIT
    if path == "/api/settings/logo":
        return LOGO_BODY_LIMIT
    if path.startswith("/api/agent/"):
        return AGENT_BODY_LIMIT
    if path.startswith("/third-party-api/"):
        return THIRD_PARTY_BODY_LIMIT
    return GLOBAL_BODY_LIMIT


class RequestBodyLimitMiddleware:
    """在框架解析 JSON 或上传内容前有界读取请求体并拒绝超限请求。"""

    def __init__(self, app: Callable[..., Awaitable[Any]]) -> None:
        """保存下层 ASGI 应用。"""

        self.app = app

    async def __call__(self, scope: dict[str, Any], receive, send) -> None:
        """检查 Content-Length，并对分块请求执行流式计数。"""

        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        limit = request_body_limit(str(scope.get("path") or ""))
        headers = {key.lower(): value for key, value in scope.get("headers") or []}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > limit:
                    await self.send_too_large(send)
                    return
            except ValueError:
                await self.send_too_large(send)
                return
        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                await self.send_too_large(send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay_receive() -> dict[str, Any]:
            """向下层应用仅回放一次已通过上限检查的请求体。"""

            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def send_too_large(send) -> None:
        """返回统一的 413 JSON 响应。"""

        payload = b'{"detail":"request body is too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})

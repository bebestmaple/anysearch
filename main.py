#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AnySearch-MCP

运行模式：

    --http
        仅启动 HTTP API

    --mcp-stdio
        启动 MCP STDIO

    --mcp-http
        启动 MCP Streamable HTTP

    --all-http
        同时启动 HTTP API + MCP Streamable HTTP

已移除：

    --mcp-sse
    --all-sse

------------------------------------------------------------
HTTP API
------------------------------------------------------------

GET /health

GET  /v1/search
POST /v1/search

HTTP Token：

    环境变量：
        ANYSEARCH_API_TOKEN

    如果未配置：
        不验证

    如果配置：
        Header:
            X-Api-Token: xxx

------------------------------------------------------------
MCP
------------------------------------------------------------

Streamable HTTP：

    /mcp

默认：

    0.0.0.0:8124

MCP Token：

    环境变量：
        ANYSEARCH_MCP_TOKEN

    如果未配置：
        不验证

    如果配置：
        Header:
            X-Api-Token: xxx

------------------------------------------------------------
代理
------------------------------------------------------------

ANYSEARCH_PROXIES

    例如：

        http://1.2.3.4:8080,
        http://5.6.7.8:8080

如果未配置，则从：

    ANYSEARCH_PROXY_LIST_URL

加载代理。

------------------------------------------------------------
安全说明
------------------------------------------------------------

本版本关闭 MCP DNS rebinding protection。

适用于：

    可信内网
    +
    HTTP
    +
    防火墙限制访问

不要直接将 8124 暴露到公网。
"""


import json
import multiprocessing
import os
import ssl
import sys
import threading
import time
import urllib.request

from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

from typing import (
    Any,
    Optional,
)

import requests
import urllib3

from flask import (
    Flask,
    Response,
    jsonify,
    request,
)

from mcp.server.fastmcp import FastMCP


# ============================================================
# AnySearch
# ============================================================

SEARCH_API = os.environ.get(
    "ANYSEARCH_SEARCH_API",
    "https://api.anysearch.com/v1/search",
)

API_KEY = os.environ.get(
    "ANYSEARCH_API_KEY",
    "",
)


# ============================================================
# HTTP API
# ============================================================

HTTP_BIND = os.environ.get(
    "ANYSEARCH_HTTP_BIND",
    "0.0.0.0",
)

HTTP_PORT = int(
    os.environ.get(
        "ANYSEARCH_HTTP_PORT",
        "8123",
    )
)

HTTP_API_TOKEN = os.environ.get(
    "ANYSEARCH_API_TOKEN",
    "",
).strip()


# ============================================================
# MCP Streamable HTTP
# ============================================================

MCP_HTTP_BIND = os.environ.get(
    "ANYSEARCH_MCP_HTTP_BIND",
    "0.0.0.0",
)

MCP_HTTP_PORT = int(
    os.environ.get(
        "ANYSEARCH_MCP_HTTP_PORT",
        "8124",
    )
)

MCP_HTTP_PATH = os.environ.get(
    "ANYSEARCH_MCP_HTTP_PATH",
    "/mcp",
).strip()

if not MCP_HTTP_PATH:
    MCP_HTTP_PATH = "/mcp"

if not MCP_HTTP_PATH.startswith("/"):
    MCP_HTTP_PATH = "/" + MCP_HTTP_PATH


# ============================================================
# MCP Token
# ============================================================

MCP_TOKEN = os.environ.get(
    "ANYSEARCH_MCP_TOKEN",
    "",
).strip()


# ============================================================
# Proxy
# ============================================================

PROXY_LIST_URL = os.environ.get(
    "ANYSEARCH_PROXY_LIST_URL",
    "https://cdn.jsdelivr.net/gh/parserpp/ip_ports/proxyinfo.json",
)

PROBE_TIMEOUT = int(
    os.environ.get(
        "ANYSEARCH_PROBE_TIMEOUT",
        "5",
    )
)

REQUEST_TIMEOUT = int(
    os.environ.get(
        "ANYSEARCH_REQUEST_TIMEOUT",
        "15",
    )
)


# ============================================================
# Proxy Cache
# ============================================================

PROXY_CACHE_ENABLE = (
    os.environ.get(
        "ANYSEARCH_PROXY_CACHE_ENABLE",
        "true",
    ).lower()
    == "true"
)

PROXY_CACHE_TTL_SEC = int(
    os.environ.get(
        "ANYSEARCH_PROXY_CACHE_TTL_SEC",
        "120",
    )
)


# ============================================================
# SSL Warning
# ============================================================

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# Proxy Cache State
# ============================================================

_proxy_cache_lock = threading.Lock()

_cached_proxy: Optional[str] = None

_cached_proxy_expire_ts = 0.0


# ============================================================
# Proxy Cache - Get
# ============================================================

def _get_cached_proxy() -> Optional[str]:

    if not PROXY_CACHE_ENABLE:
        return None

    with _proxy_cache_lock:

        now = time.time()

        if (
            _cached_proxy
            and now < _cached_proxy_expire_ts
        ):

            sys.stderr.write(
                "[代理缓存] "
                f"使用缓存代理 {_cached_proxy}\n"
            )

            return _cached_proxy

        return None


# ============================================================
# Proxy Cache - Set
# ============================================================

def _set_cached_proxy(
    proxy: Optional[str],
) -> None:

    if not PROXY_CACHE_ENABLE:
        return

    global _cached_proxy
    global _cached_proxy_expire_ts

    with _proxy_cache_lock:

        _cached_proxy = proxy

        _cached_proxy_expire_ts = (
            time.time()
            + PROXY_CACHE_TTL_SEC
        )

        if proxy:

            sys.stderr.write(
                "[代理缓存] "
                f"更新缓存 {proxy}, "
                f"TTL={PROXY_CACHE_TTL_SEC}s\n"
            )

        else:

            sys.stderr.write(
                "[代理缓存] 清空缓存\n"
            )


# ============================================================
# Parse Proxy
# ============================================================

def _parse_proxy_line(
    line: str,
) -> Optional[str]:

    line = line.strip()

    if not line:
        return None

    if line.startswith("#"):
        return None

    line = line.split(
        "#",
        1,
    )[0].strip()

    if not line:
        return None

    if "://" in line:
        return line

    return f"http://{line}"


# ============================================================
# Load Proxies
# ============================================================

def load_proxies() -> list[str]:

    env_proxies = os.environ.get(
        "ANYSEARCH_PROXIES",
        "",
    ).strip()

    # --------------------------------------------------------
    # Environment proxies
    # --------------------------------------------------------

    if env_proxies:

        return [
            proxy.strip()
            for proxy in env_proxies.split(",")
            if proxy.strip()
        ]

    # --------------------------------------------------------
    # Remote proxy list
    # --------------------------------------------------------

    try:

        context = (
            ssl.create_default_context()
        )

        context.check_hostname = False

        context.verify_mode = (
            ssl.CERT_NONE
        )

        req = urllib.request.Request(
            PROXY_LIST_URL,
            headers={
                "User-Agent":
                    "Mozilla/5.0",
            },
        )

        opener = (
            urllib.request.build_opener(
                urllib.request.HTTPSHandler(
                    context=context
                )
            )
        )

        with opener.open(
            req,
            timeout=10,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="ignore",
            )

        # ----------------------------------------------------
        # JSON
        # ----------------------------------------------------

        try:

            data = json.loads(raw)

            if isinstance(
                data,
                dict,
            ):

                entries: list[dict] = []

                for value in data.values():

                    if isinstance(
                        value,
                        list,
                    ):

                        entries.extend(
                            item
                            for item in value
                            if isinstance(
                                item,
                                dict,
                            )
                        )

                entries.sort(
                    key=lambda item:
                        item.get(
                            "response_time",
                            9999,
                        )
                )

                proxies: list[str] = []

                for entry in entries:

                    host = entry.get(
                        "host",
                        "",
                    )

                    port = entry.get(
                        "port",
                        "",
                    )

                    proxy_type = entry.get(
                        "type",
                        "http",
                    )

                    if host and port:

                        proxies.append(
                            f"{proxy_type}://"
                            f"{host}:{port}"
                        )

                sys.stderr.write(
                    "[代理] "
                    f"加载 {len(proxies)} "
                    "条(json)\n"
                )

                return proxies

        except json.JSONDecodeError:

            pass

        # ----------------------------------------------------
        # Text
        # ----------------------------------------------------

        proxies = [
            proxy
            for line in raw.splitlines()
            if (
                proxy :=
                _parse_proxy_line(line)
            )
        ]

        sys.stderr.write(
            "[代理] "
            f"加载 {len(proxies)} "
            "条(text)\n"
        )

        return proxies

    except Exception as exc:

        sys.stderr.write(
            f"[代理加载失败] {exc}\n"
        )

        return []


# ============================================================
# Probe Single Proxy
# ============================================================

def _probe_single_proxy(
    proxy: str,
    stop_event: threading.Event,
) -> Optional[str]:

    if stop_event.is_set():
        return None

    try:

        response = requests.post(
            SEARCH_API,

            json={
                "query": "test",
                "max_results": 1,
            },

            headers={
                "Content-Type":
                    "application/json",
            },

            proxies={
                "http": proxy,
                "https": proxy,
            },

            timeout=PROBE_TIMEOUT,

            verify=False,
        )

        response.raise_for_status()

        response.json()

        return proxy

    except Exception:

        return None


# ============================================================
# Find Alive Proxy
# ============================================================

def find_alive_proxy(
    proxy_list: list[str],
) -> Optional[str]:

    cached = _get_cached_proxy()

    if cached is not None:
        return cached

    if not proxy_list:

        _set_cached_proxy(None)

        return None

    sys.stderr.write(
        "[探测] "
        f"并发探测 {len(proxy_list)} "
        "代理\n"
    )

    stop_event = threading.Event()

    winner: Optional[str] = None

    max_workers = min(
        len(proxy_list),
        50,
    )

    with ThreadPoolExecutor(
        max_workers=max_workers,
    ) as pool:

        futures = [
            pool.submit(
                _probe_single_proxy,
                proxy,
                stop_event,
            )
            for proxy in proxy_list
        ]

        for future in as_completed(
            futures
        ):

            try:

                result = (
                    future.result()
                )

            except Exception:

                continue

            if (
                result
                and not stop_event.is_set()
            ):

                stop_event.set()

                winner = result

                break

    if winner:

        sys.stderr.write(
            f"[探测] "
            f"可用代理 {winner}\n"
        )

        _set_cached_proxy(
            winner
        )

        return winner

    sys.stderr.write(
        "[探测] 无可用代理\n"
    )

    _set_cached_proxy(None)

    return None


# ============================================================
# Request Headers
# ============================================================

def _make_req_headers() -> dict[str, str]:

    headers = {
        "Content-Type":
            "application/json",

        "User-Agent":
            "AnySearch-MCP/2.0",
    }

    if API_KEY:

        headers["Authorization"] = (
            f"Bearer {API_KEY}"
        )

    return headers


# ============================================================
# AnySearch Request
# ============================================================

def do_search_req(
    query: str,
    max_results: int,
    proxy: Optional[str],
    tag: Optional[str] = None,
    zone: Optional[str] = None,
    language: Optional[str] = None,
    params: Optional[dict] = None,
) -> dict:

    payload: dict[str, Any] = {
        "query": query,
        "max_results": max_results,
    }

    if tag is not None:

        payload["tag"] = tag

    if zone is not None:

        payload["zone"] = zone

    if language is not None:

        payload["language"] = language

    if (
        params is not None
        and isinstance(
            params,
            dict,
        )
    ):

        payload["params"] = params

    response = requests.post(
        SEARCH_API,

        json=payload,

        headers=_make_req_headers(),

        proxies=(
            {
                "http": proxy,
                "https": proxy,
            }
            if proxy
            else None
        ),

        timeout=REQUEST_TIMEOUT,

        verify=False,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# Normalize Search Result
# ============================================================

def normalize_search_result(
    raw: dict,
) -> list[dict]:

    if not isinstance(
        raw,
        dict,
    ):
        return []

    data = (
        raw.get("data")
        or raw
    )

    if isinstance(
        data,
        dict,
    ):

        items = (
            data.get("results")
            or data.get("items")
            or []
        )

    elif isinstance(
        data,
        list,
    ):

        items = data

    else:

        items = []

    output: list[dict] = []

    for item in items:

        if not isinstance(
            item,
            dict,
        ):
            continue

        title = str(
            item.get("title")
            or item.get("name")
            or ""
        ).strip()

        url = str(
            item.get("url")
            or item.get("link")
            or ""
        ).strip()

        snippet = str(
            item.get("description")
            or item.get("snippet")
            or ""
        ).strip()[:600]

        if title or url:

            output.append(
                {
                    "title": title,
                    "url": url,
                    "snippet": snippet,
                }
            )

    return output


# ============================================================
# Markdown
# ============================================================

def render_markdown_output(
    result_obj: dict,
) -> str:

    query = result_obj.get(
        "query",
        "",
    )

    error = result_obj.get(
        "error"
    )

    items = result_obj.get(
        "results",
        [],
    )

    via = result_obj.get(
        "via",
        "",
    )

    markdown = (
        f"# AnySearch Query: "
        f"{query}\n\n"
    )

    if error:

        markdown += (
            f"> Error: {error}\n\n"
        )

        return markdown

    markdown += (
        f"> via: {via}\n\n"
    )

    for index, item in enumerate(
        items,
        1,
    ):

        title = item.get(
            "title",
            "",
        )

        url = item.get(
            "url",
            "",
        )

        snippet = item.get(
            "snippet",
            "",
        )

        markdown += (
            f"**{index}. "
            f"[{title}]({url})**\n\n"
            f"{snippet}\n\n"
        )

    return markdown


# ============================================================
# Search
# ============================================================

def search(
    query: str,
    max_results: int = 10,
    tag: Optional[str] = None,
    zone: Optional[str] = None,
    language: Optional[str] = None,
    params: Optional[dict] = None,
) -> dict:

    max_results = max(
        1,
        min(
            10,
            int(max_results),
        ),
    )

    proxies = load_proxies()

    proxy = find_alive_proxy(
        proxies
    )

    # --------------------------------------------------------
    # Attempt
    # --------------------------------------------------------

    def attempt(
        current_proxy: Optional[str],
    ) -> Optional[dict]:

        label = (
            current_proxy
            if current_proxy
            else "direct"
        )

        try:

            sys.stderr.write(
                f"[search] "
                f"try {label}\n"
            )

            raw = do_search_req(
                query=query,
                max_results=max_results,
                proxy=current_proxy,
                tag=tag,
                zone=zone,
                language=language,
                params=params,
            )

            return {
                "query": query,

                "results":
                    normalize_search_result(
                        raw
                    ),

                "error": None,

                "via": label,
            }

        except requests.HTTPError as exc:

            if current_proxy is not None:

                _set_cached_proxy(
                    None
                )

            sys.stderr.write(
                "[HTTP fail] "
                f"{label} {exc}\n"
            )

            return None

        except Exception as exc:

            if current_proxy is not None:

                _set_cached_proxy(
                    None
                )

            sys.stderr.write(
                "[fail] "
                f"{label}: {exc}\n"
            )

            return None

    # --------------------------------------------------------
    # Proxy
    # --------------------------------------------------------

    result = attempt(
        proxy
    )

    if result is not None:
        return result

    # --------------------------------------------------------
    # Direct
    # --------------------------------------------------------

    result = attempt(
        None
    )

    if result is not None:
        return result

    return {
        "query": query,
        "results": [],
        "error": "All request failed",
        "via": None,
    }


# ============================================================
# Flask
# ============================================================

flask_app = Flask(
    __name__
)


# ============================================================
# HTTP Token Middleware
# ============================================================

@flask_app.before_request
def http_auth_middleware():

    # --------------------------------------------------------
    # 未配置 Token
    # --------------------------------------------------------

    if not HTTP_API_TOKEN:

        return None

    # --------------------------------------------------------
    # 配置 Token 后进行验证
    # --------------------------------------------------------

    token = request.headers.get(
        "X-Api-Token",
        "",
    ).strip()

    if token != HTTP_API_TOKEN:

        return (
            jsonify(
                {
                    "error":
                        "unauthorized"
                }
            ),
            401,
        )

    return None


# ============================================================
# Search API
# ============================================================

@flask_app.route(
    "/v1/search",
    methods=[
        "GET",
        "POST",
    ],
)
def api_v1_search():

    query = ""

    max_results = 10

    tag: Optional[str] = None

    zone: Optional[str] = None

    language: Optional[str] = None

    params: Optional[dict] = None

    fmt = "json"

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if (
        request.method == "POST"
        and request.is_json
    ):

        body = request.get_json(
            silent=True
        )

        if not isinstance(
            body,
            dict,
        ):

            body = {}

        query = body.get(
            "query",
            "",
        )

        max_results = body.get(
            "max_results",
            10,
        )

        tag = body.get(
            "tag"
        )

        zone = body.get(
            "zone"
        )

        language = body.get(
            "language"
        )

        params = body.get(
            "params"
        )

        fmt = body.get(
            "format",
            "json",
        )

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    else:

        query = request.args.get(
            "query",
            "",
        )

        try:

            max_results = int(
                request.args.get(
                    "max_results",
                    "10",
                )
            )

        except ValueError:

            return (
                jsonify(
                    {
                        "error":
                            "max_results "
                            "must be integer"
                    }
                ),
                400,
            )

        tag = request.args.get(
            "tag"
        )

        zone = request.args.get(
            "zone"
        )

        language = request.args.get(
            "language"
        )

        fmt = request.args.get(
            "format",
            "json",
        )

        params_string = (
            request.args.get(
                "params"
            )
        )

        if params_string:

            try:

                params = json.loads(
                    params_string
                )

            except Exception:

                params = None

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not isinstance(
        query,
        str,
    ):

        query = str(query)

    query = query.strip()

    if not query:

        return (
            jsonify(
                {
                    "error":
                        "query required"
                }
            ),
            400,
        )

    if fmt not in (
        "json",
        "markdown",
    ):

        return (
            jsonify(
                {
                    "error":
                        "format must be "
                        "json or markdown"
                }
            ),
            400,
        )

    # --------------------------------------------------------
    # Search
    # --------------------------------------------------------

    result = search(
        query=query,
        max_results=max_results,
        tag=tag,
        zone=zone,
        language=language,
        params=params,
    )

    # --------------------------------------------------------
    # Markdown
    # --------------------------------------------------------

    if fmt == "markdown":

        return Response(
            render_markdown_output(
                result
            ),
            mimetype="text/markdown",
        )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    return jsonify(result)


# ============================================================
# Health
# ============================================================

@flask_app.route(
    "/health",
    methods=["GET"],
)
def health():

    return jsonify(
        {
            "status": "ok",

            "proxy_cache_enable":
                PROXY_CACHE_ENABLE,

            "proxy_cache_ttl_sec":
                PROXY_CACHE_TTL_SEC,

            "mcp": {
                "transport":
                    "streamable-http",

                "path":
                    MCP_HTTP_PATH,

                "token_enabled":
                    bool(MCP_TOKEN),

                "dns_rebinding_protection":
                    False,
            },

            "http_api": {
                "token_enabled":
                    bool(HTTP_API_TOKEN),
            },

            "supported_domains": [
                "Finance",
                "academia",
                "code",
                "security",
                "business",
                "medical & health",
                "patents",
                "energy",
                "environment",
                "agriculture",
                "travel",
                "gaming",
            ],
        }
    )


# ============================================================
# Flask Server
# ============================================================

def run_flask():

    sys.stderr.write(
        "[HTTP] starting HTTP API\n"
    )

    sys.stderr.write(
        f"[HTTP] bind="
        f"{HTTP_BIND}:"
        f"{HTTP_PORT}\n"
    )

    if HTTP_API_TOKEN:

        sys.stderr.write(
            "[HTTP] API token enabled\n"
        )

    else:

        sys.stderr.write(
            "[HTTP] API token disabled\n"
        )

    flask_app.run(
        host=HTTP_BIND,
        port=HTTP_PORT,
        debug=False,
        threaded=True,
        use_reloader=False,
    )


# ============================================================
# MCP
# ============================================================

mcp = FastMCP(
    "anysearch-mcp"
)


# ============================================================
# MCP Tool
# ============================================================

@mcp.tool()
def anysearch_web_search(
    query: str,
    max_results: int = 10,
    tag: Optional[str] = None,
    zone: Optional[str] = None,
    language: Optional[str] = None,
    params: Optional[dict] = None,
) -> str:
    """
    AnySearch 联网搜索工具。

    使用代理池访问 AnySearch API。

    支持：

    Finance
    academia
    code
    security
    business
    medical & health
    patents
    energy
    environment
    agriculture
    travel
    gaming

    Args:
        query:
            搜索查询词。

        max_results:
            返回数量，1-10。

        tag:
            子域能力标签。

            例如：

                code.doc

        zone:
            搜索区域：

                cn
                intl

        language:
            偏好语言：

                zh-CN
                en

        params:
            AnySearch 扩展参数。
    """

    result = search(
        query=query,
        max_results=max_results,
        tag=tag,
        zone=zone,
        language=language,
        params=params,
    )

    return json.dumps(
        result,
        ensure_ascii=False,
        indent=2,
    )


# ============================================================
# MCP Token
#
# FastMCP 本身的 Streamable HTTP transport 不提供简单的
# X-Api-Token middleware 配置。
#
# 因此这里使用 Starlette middleware 对 MCP ASGI app
# 进行 Token 验证。
# ============================================================

def _build_mcp_http_app():

    from starlette.middleware.base import (
        BaseHTTPMiddleware,
    )

    class MCPTokenMiddleware(
        BaseHTTPMiddleware
    ):

        async def dispatch(
            self,
            scope,
            receive,
            send,
        ):

            # ------------------------------------------------
            # Token 未配置
            # ------------------------------------------------

            if not MCP_TOKEN:

                await self.app(
                    scope,
                    receive,
                    send,
                )

                return

            # ------------------------------------------------
            # 只验证 HTTP
            # ------------------------------------------------

            if scope.get(
                "type"
            ) != "http":

                await self.app(
                    scope,
                    receive,
                    send,
                )

                return

            # ------------------------------------------------
            # Header
            # ------------------------------------------------

            headers = dict(
                scope.get(
                    "headers",
                    [],
                )
            )

            provided = headers.get(
                b"x-api-token",
                b"",
            ).decode(
                "utf-8",
                errors="ignore",
            ).strip()

            # ------------------------------------------------
            # Token 错误
            # ------------------------------------------------

            if provided != MCP_TOKEN:

                response_body = (
                    b'{"error":"unauthorized"}'
                )

                await send(
                    {
                        "type":
                            "http.response.start",

                        "status": 401,

                        "headers": [
                            (
                                b"content-type",
                                b"application/json",
                            ),

                            (
                                b"content-length",
                                str(
                                    len(
                                        response_body
                                    )
                                ).encode(),
                            ),
                        ],
                    }
                )

                await send(
                    {
                        "type":
                            "http.response.body",

                        "body":
                            response_body,
                    }
                )

                return

            # ------------------------------------------------
            # Token 正确
            # ------------------------------------------------

            await self.app(
                scope,
                receive,
                send,
            )

    # --------------------------------------------------------
    # FastMCP Streamable HTTP
    # --------------------------------------------------------

    app = mcp.streamable_http_app()

    # --------------------------------------------------------
    # Token Middleware
    # --------------------------------------------------------

    if MCP_TOKEN:

        app = MCPTokenMiddleware(
            app
        )

    return app


# ============================================================
# MCP Streamable HTTP Server
# ============================================================

def run_mcp_http():

    import uvicorn

    app = _build_mcp_http_app()

    sys.stderr.write(
        "[MCP] starting "
        "Streamable HTTP\n"
    )

    sys.stderr.write(
        f"[MCP] bind="
        f"{MCP_HTTP_BIND}:"
        f"{MCP_HTTP_PORT}\n"
    )

    sys.stderr.write(
        f"[MCP] endpoint="
        f"{MCP_HTTP_PATH}\n"
    )

    sys.stderr.write(
        "[MCP] DNS rebinding "
        "protection=disabled\n"
    )

    if MCP_TOKEN:

        sys.stderr.write(
            "[MCP] token authentication=enabled\n"
        )

    else:

        sys.stderr.write(
            "[MCP] token authentication=disabled\n"
        )

    # --------------------------------------------------------
    # MCP SDK 1.29.0
    #
    # 使用 ASGI + Uvicorn。
    #
    # MCP endpoint 已由 FastMCP 使用
    # streamable_http_path 控制。
    # --------------------------------------------------------

    mcp.settings.streamable_http_path = (
        MCP_HTTP_PATH
    )

    uvicorn.run(
        app,
        host=MCP_HTTP_BIND,
        port=MCP_HTTP_PORT,
        log_level="info",
        access_log=True,
    )


# ============================================================
# CLI
# ============================================================

def run_cli():

    if len(sys.argv) < 2:

        print(
            json.dumps(
                {
                    "error":
                        "usage: "
                        "main.py "
                        "<query> "
                        "[max_results]",

                    "results": [],
                },
                ensure_ascii=False,
            )
        )

        sys.exit(1)

    parts = sys.argv[1:]

    max_results = 10

    if (
        parts
        and parts[-1].isdigit()
    ):

        max_results = int(
            parts[-1]
        )

        parts = parts[:-1]

    query = " ".join(parts)

    result = search(
        query=query,
        max_results=max_results,
    )

    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )
    )


# ============================================================
# Main
# ============================================================

def main():

    # --------------------------------------------------------
    # Legacy --all
    # --------------------------------------------------------

    if "--all" in sys.argv:

        sys.stderr.write(
            "WARN: --all is deprecated, "
            "use --all-http instead\n"
        )

        sys.argv.remove(
            "--all"
        )

    # --------------------------------------------------------
    # Reject SSE
    # --------------------------------------------------------

    if "--mcp-sse" in sys.argv:

        sys.stderr.write(
            "ERROR: SSE is no longer supported.\n"
            "Use --mcp-http instead.\n"
        )

        sys.exit(2)

    if "--all-sse" in sys.argv:

        sys.stderr.write(
            "ERROR: --all-sse is no longer supported.\n"
            "Use --all-http instead.\n"
        )

        sys.exit(2)

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if "--http" in sys.argv:

        sys.argv.remove(
            "--http"
        )

        run_flask()

        return

    # --------------------------------------------------------
    # MCP STDIO
    # --------------------------------------------------------

    if "--mcp-stdio" in sys.argv:

        sys.argv.remove(
            "--mcp-stdio"
        )

        mcp.run(
            transport="stdio"
        )

        return

    # --------------------------------------------------------
    # MCP Streamable HTTP
    # --------------------------------------------------------

    if "--mcp-http" in sys.argv:

        sys.argv.remove(
            "--mcp-http"
        )

        run_mcp_http()

        return

    # --------------------------------------------------------
    # HTTP + MCP
    # --------------------------------------------------------

    if "--all-http" in sys.argv:

        sys.argv.remove(
            "--all-http"
        )

        http_process = multiprocessing.Process(
            target=run_flask,
            daemon=True,
            name="anysearch-http",
        )

        http_process.start()

        sys.stderr.write(
            "[HTTP] HTTP API process started\n"
        )

        try:

            run_mcp_http()

        except KeyboardInterrupt:

            sys.stderr.write(
                "[main] shutdown requested\n"
            )

        finally:

            if http_process.is_alive():

                sys.stderr.write(
                    "[HTTP] stopping HTTP process\n"
                )

                http_process.terminate()

            http_process.join(
                timeout=5
            )

        return

    # --------------------------------------------------------
    # CLI
    # --------------------------------------------------------

    run_cli()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    main()

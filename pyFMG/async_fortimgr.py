# async_fortimgr.py
import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


class AsyncFMGBaseException(Exception):
    pass


class AsyncFMGValidSessionException(AsyncFMGBaseException):
    pass


class AsyncFortiManager:
    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        passwd: Optional[str] = None,
        apikey: Optional[str] = None,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        timeout: int = 300,
        verbose: bool = False,
        check_adom_workspace: bool = True,
    ) -> None:
        if not host:
            raise ValueError("host is required")

        self._host = host
        self._user = user
        self._passwd = passwd if passwd is not None else apikey
        self._apikeyused = passwd is None and apikey is not None
        self._forticloudused = host.endswith(
            ("fortimanager.forticloud.com", "fortianalyzer.forticloud.com")
        )
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._verbose = verbose
        self._check_adom_workspace = check_adom_workspace

        self._sid: Optional[str] = None
        self._req_id = 0
        self._url: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.logout()
        await self.close()

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _headers(self) -> Dict[str, str]:
        h = {"content-type": "application/json"}
        if self._apikeyused:
            h["Authorization"] = f"Bearer {self._passwd}"
        return h

    def _build_params(self, method_type: str, url: str, **kwargs) -> List[Dict[str, Any]]:
        params = [{"url": url}]
        if kwargs:
            normalized = {
                k.replace("___", " ").replace("__", "-"): v
                for k, v in kwargs.items()
            }
            if method_type in ("get", "clone"):
                params[0].update(normalized)
            else:
                params[0]["data"] = normalized.get("data", normalized)
        return params

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
            self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self._session

    async def _post_jsonrpc(
        self,
        method: str,
        params: List[Dict[str, Any]],
        free_form: bool = False,
        create_task: Optional[bool] = None,
    ) -> Tuple[int, Any]:
        if self._sid is None:
            raise AsyncFMGValidSessionException("No valid session. Call login() first.")

        session = await self._ensure_session()
        payload: Dict[str, Any] = {
            "method": method,
            "params": params,
            "session": self._sid,
            "id": self._next_id(),
        }
        if method == "get" and self._verbose:
            payload["verbose"] = 1
        if create_task:
            payload["create task"] = create_task

        async with session.post(self._url, data=json.dumps(payload), headers=self._headers()) as r:
            raw = await r.json(content_type=None)

        result = raw["result"] if free_form else raw["result"][0] if isinstance(raw["result"], list) else raw["result"]
        if free_form:
            return 200, result
        return result["status"]["code"], result.get("data", result)

    async def login(self) -> Tuple[int, Dict[str, Any]]:
        self._url = f'{"https" if self._use_ssl else "http"}://{self._host}/jsonrpc'
        await self._ensure_session()

        if self._apikeyused:
            self._sid = f"{uuid.uuid4()}-{self._passwd[-4:]}" if self._passwd else str(uuid.uuid4())
        else:
            code, _ = await self._post_login("exec", self._build_params("execute", "sys/login/user", user=self._user, passwd=self._passwd))
            if code != 0:
                return -1, {"status": {"message": "Login failed", "code": -1}, "url": "sys/login/user"}

        if self._check_adom_workspace:
            await self._check_mode()
        return 0, {"status": {"message": "OK", "code": 0}, "url": "sys/login/user"}

    async def _post_login(self, method: str, params: Optional[List[Dict[str, Any]]]) -> Tuple[int, Any]:
        session = await self._ensure_session()
        payload = {"method": method, "params": params, "session": self._sid, "id": self._next_id()}
        async with session.post(self._url, data=json.dumps(payload), headers={"content-type": "application/json"}) as r:
            raw = await r.json(content_type=None)

        if self._sid is None and "session" in raw:
            self._sid = raw["session"]

        result = raw["result"][0] if isinstance(raw["result"], list) else raw["result"]
        return result["status"]["code"], result.get("data", result)

    async def logout(self) -> Optional[Tuple[int, Any]]:
        if self._sid is None:
            return None
        code, data = await self.execute("sys/logout")
        self._sid = None
        return code, data

    async def _check_mode(self) -> None:
        await self.get("/cli/global/system/global", fields=["workspace-mode", "adom-status"])

    async def get(self, url: str, **kwargs): return await self._post_jsonrpc("get", self._build_params("get", url, **kwargs))
    async def add(self, url: str, **kwargs): return await self._post_jsonrpc("add", self._build_params("add", url, **kwargs))
    async def update(self, url: str, **kwargs): return await self._post_jsonrpc("update", self._build_params("update", url, **kwargs))
    async def set(self, url: str, **kwargs): return await self._post_jsonrpc("set", self._build_params("set", url, **kwargs))
    async def delete(self, url: str, **kwargs): return await self._post_jsonrpc("delete", self._build_params("delete", url, **kwargs))
    async def replace(self, url: str, **kwargs): return await self._post_jsonrpc("replace", self._build_params("replace", url, **kwargs))
    async def clone(self, url: str, **kwargs): return await self._post_jsonrpc("clone", self._build_params("clone", url, **kwargs))
    async def execute(self, url: str, **kwargs): return await self._post_jsonrpc("exec", self._build_params("execute", url, **kwargs))
    async def move(self, url: str, **kwargs): return await self._post_jsonrpc("move", self._build_params("move", url, **kwargs))
    async def unset(self, url: str, **kwargs): return await self._post_jsonrpc("unset", self._build_params("unset", url, **kwargs))

    async def free_form(self, method: str, data: List[Dict[str, Any]], create_task: Optional[bool] = None):
        if not isinstance(data, list):
            raise AsyncFMGBaseException("free_form requires data as list[dict]")
        return await self._post_jsonrpc(method, data, free_form=True, create_task=create_task)

    async def track_task(
        self,
        task_id: int,
        sleep_time: int = 3,
        retrieval_fail_gate: int = 10,
        timeout: int = 120,
    ) -> Tuple[int, Dict[str, Any]]:
        begin = datetime.now()
        failures = 0
        start_monotonic = asyncio.get_running_loop().time()

        while True:
            code, task_info = await self.get(f"/task/task/{task_id}")
            if code == 0:
                percent = int(task_info.get("percent", 0))
                if percent >= 100:
                    task_info["total_task_time"] = str(datetime.now() - begin)
                    return 0, task_info
            else:
                failures += 1
                if failures >= retrieval_fail_gate:
                    return code, task_info

            if asyncio.get_running_loop().time() - start_monotonic >= timeout:
                return 1, {"msg": f"Task {task_id} timed out after {timeout}s"}

            await asyncio.sleep(sleep_time)

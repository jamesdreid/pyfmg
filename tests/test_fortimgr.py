import json
import time

import pytest
from requests.exceptions import ConnectionError as ReqConnError

from pyFMG.fortimgr import (
    FMGBaseException,
    FMGConnectTimeout,
    FMGConnectionError,
    FMGLockContext,
    FMGOAuthTokenError,
    FMGRequestNotFormedCorrect,
    FMGResponseNotFormedCorrect,
    FMGValidSessionException,
    FMGValueError,
    FortiManager,
    RequestResponse,
)


class DummyResponse:
    def __init__(self, payload=None, status_code=200, exc=None):
        self._payload = payload
        self.status_code = status_code
        self._exc = exc

    def json(self):
        if self._exc is not None:
            raise self._exc
        return self._payload


class DummyLogger:
    def __init__(self):
        self.entries = []
        self.handlers = []

    def log(self, level, msg):
        self.entries.append((level, msg))

    def addHandler(self, h):
        self.handlers.append(h)

    def removeHandler(self, h):
        self.handlers.remove(h)


@pytest.fixture
def fmg():
    return FortiManager(host="fmg.local", user="admin", passwd="secret")


def test_exception_classes_construct():
    assert str(FMGBaseException("x")) == "x"
    assert "valid session" in str(FMGValidSessionException("get", [{"url": "/x"}])).lower()
    assert isinstance(FMGValueError("x"), ValueError)
    assert isinstance(FMGResponseNotFormedCorrect("x"), KeyError)
    assert isinstance(FMGConnectionError("x"), Exception)
    assert isinstance(FMGConnectTimeout("x"), Exception)
    assert isinstance(FMGRequestNotFormedCorrect("x"), FMGBaseException)
    assert isinstance(FMGOAuthTokenError("x"), FMGBaseException)


def test_request_response_properties_and_reset():
    rr = RequestResponse()
    rr.request_string = "REQ"
    rr.request_json = {"a": 1}
    rr.response_json = {"b": 2}
    rr.error_msg = "boom"
    assert rr.request_string == "REQ"
    assert rr.response_string == "RESPONSE:"
    assert rr.request_json == {"a": 1}
    assert rr.response_json == {"b": 2}
    assert rr.error_msg == "boom"
    rr.reset()
    assert rr.request_string == "REQUEST:"
    assert rr.request_json is None
    assert rr.response_json is None
    assert rr.error_msg is None


def test_lock_context_props_and_list_management():
    class FakeFMG:
        check_adom_workspace = True

    ctx = FMGLockContext(FakeFMG())
    ctx.uses_workspace = True
    ctx.uses_adoms = True
    assert ctx.uses_workspace is True
    assert ctx.uses_adoms is True

    ctx.add_adom_to_lock_list("a")
    ctx.add_adom_to_lock_list("a")
    assert ctx._locked_adom_list == ["a"]
    ctx.remove_adom_from_lock_list("a")
    assert ctx._locked_adom_list == []


def test_lock_context_check_mode_disabled():
    class FakeFMG:
        check_adom_workspace = False

    ctx = FMGLockContext(FakeFMG())
    ctx.uses_workspace = True
    ctx.uses_adoms = True
    ctx.check_mode()
    assert ctx.uses_workspace is False
    assert ctx.uses_adoms is False


def test_lock_context_check_mode_reads_fields():
    class FakeFMG:
        check_adom_workspace = True

        @staticmethod
        def get(url, fields):
            assert url == "/cli/global/system/global"
            assert fields == ["workspace-mode", "adom-status"]
            return 0, {"workspace-mode": "workspace", "adom-status": "enable"}

    ctx = FMGLockContext(FakeFMG())
    ctx.check_mode()
    assert ctx.uses_workspace is True
    assert ctx.uses_adoms is True


def test_lock_unlock_commit_paths_and_run_unlock():
    calls = []

    class FakeFMG:
        @staticmethod
        def execute(url, data, *args, **kwargs):
            calls.append((url, data))
            return 0, {"status": {"message": "OK"}}

    ctx = FMGLockContext(FakeFMG())
    ctx.lock_adom("global")
    ctx.lock_adom("root")
    assert "global" in ctx._locked_adom_list
    assert "root" in ctx._locked_adom_list

    ctx.unlock_adom("global")
    assert "global" not in ctx._locked_adom_list

    ctx.commit_changes("global")
    ctx.commit_changes("adom1", aux=True)

    # Ensures function executes with existing locks.
    ctx.run_unlock()
    assert any("/workspace/lock" in c[0] for c in calls)
    assert any("/workspace/unlock" in c[0] for c in calls)
    assert any("/workspace/commit" in c[0] for c in calls)


def test_fortimanager_init_requires_host():
    with pytest.raises(ValueError, match="Host is required"):
        FortiManager(host="")


def test_fortimanager_property_getters_setters(fmg):
    fmg.api_key_used = True
    fmg.forticloud_used = True
    fmg.check_adom_workspace = False
    fmg.debug = True
    fmg.req_id = 12
    fmg.sid = "sid"
    fmg.verify_ssl = True
    fmg.timeout = 10
    fmg.verbose = True

    assert fmg.api_key_used is True
    assert fmg.forticloud_used is True
    assert fmg.check_adom_workspace is False
    assert fmg.debug is True
    assert fmg.req_id == 12
    assert fmg.sid == "sid"
    assert fmg.verify_ssl is True
    assert fmg.timeout == 10
    assert fmg.verbose is True
    assert fmg.sess is not None
    assert isinstance(fmg.track_task_disable_connerr, bool)
    assert isinstance(fmg.req_resp_object, RequestResponse)


def test_update_request_id(fmg):
    fmg.req_id = 0
    fmg._update_request_id()
    assert fmg.req_id == 1
    fmg._update_request_id(99)
    assert fmg.req_id == 99


def test_logging_helpers(monkeypatch, fmg, capsys):
    logger = DummyLogger()
    monkeypatch.setattr("pyFMG.fortimgr.logging.getLogger", lambda *_: logger)

    assert fmg.getLog("x") is logger
    handler = object()
    fmg.addHandler(handler)
    assert handler in logger.handlers
    fmg.removeHandler(handler)
    assert handler not in logger.handlers

    fmg.req_resp_object.request_json = {"a": 1}
    fmg.req_resp_object.response_json = {"b": 2}
    fmg.dlog()
    assert logger.entries

    fmg.debug = True
    fmg.dprint()
    out = capsys.readouterr().out
    assert "REQUEST:" in out

    fmg.resetLog()
    assert fmg._logger is None


def test_jprint_handles_non_serializable():
    out = FortiManager.jprint({"x": object()})
    assert "Type Information" in out


def test_set_sid_paths(fmg):
    fmg._apikeyused = True
    fmg._passwd = "abcd1234"
    fmg.sid = None
    fmg._set_sid(None)
    assert fmg.sid.endswith("1234")

    fmg._apikeyused = False
    fmg.sid = None
    fmg._set_sid({"session": "S1"})
    assert fmg.sid == "S1"


def test_lock_delegation_methods(fmg, monkeypatch):
    monkeypatch.setattr(fmg._lock_ctx, "lock_adom", lambda *a, **k: (1, "l"))
    monkeypatch.setattr(fmg._lock_ctx, "unlock_adom", lambda *a, **k: (2, "u"))
    monkeypatch.setattr(fmg._lock_ctx, "commit_changes", lambda *a, **k: (3, "c"))
    assert fmg.lock_adom("x") == (1, "l")
    assert fmg.unlock_adom("x") == (2, "u")
    assert fmg.commit_changes("x") == (3, "c")


def test_handle_response_variants(fmg):
    code, resp = fmg._handle_response(DummyResponse(exc=ValueError("bad")))
    assert code == 100
    assert isinstance(resp, DummyResponse)

    fmg.forticloud_used = True
    code, data = fmg._handle_response(
        DummyResponse(payload={"session": "s", "result": [{"status": {"code": 0}}]}, status_code=201),
        login=True,
    )
    assert code == 201 and data == {}

    fmg.forticloud_used = False
    code, data = fmg._handle_response(
        DummyResponse(payload={"result": [{"status": {"code": 0}, "data": {"k": 1}}]})
    )
    assert code == 0 and data == {"k": 1}

    code, data = fmg._handle_response(
        DummyResponse(payload={"result": {"status": {"code": -2}, "m": 1}})
    )
    assert code == -2 and data["m"] == 1


def test_freeform_response(fmg):
    code, resp = fmg._freeform_response(DummyResponse(exc=ValueError("x")))
    assert code == 100
    assert isinstance(resp, DummyResponse)

    code, data = fmg._freeform_response(DummyResponse(payload={"result": [{"status": {"code": 0}}]}))
    assert code == 200
    assert isinstance(data, list)


def test_get_oauth_token_paths(monkeypatch):
    class R:
        def __init__(self, status, text=""):
            self.status_code = status
            self.text = text

    monkeypatch.setattr("pyFMG.fortimgr.requests.post", lambda *a, **k: R(200, '{"access_token":"t"}'))
    code, data = FortiManager._get_oauth_token("u", {}, {})
    assert code == 200 and data["access_token"] == "t"

    monkeypatch.setattr("pyFMG.fortimgr.requests.post", lambda *a, **k: R(401, "bad"))
    code, data = FortiManager._get_oauth_token("u", {}, {})
    assert code == 100
    assert data.status_code == 401


def test_revoke_oauth_token_posts(monkeypatch, fmg):
    called = {}

    def fake_post(url, headers=None, json=None):
        called["url"] = url
        called["headers"] = headers
        called["json"] = json
        return object()

    monkeypatch.setattr("pyFMG.fortimgr.requests.post", fake_post)
    fmg._revoke_oauth_token("https://x", {"h": 1}, "tok")
    assert called["url"] == "https://x"
    assert called["json"]["token"] == "tok"


def test_post_login_request_non_forticloud(monkeypatch, fmg):
    captured = {}

    def fake_post(url, data=None, headers=None, verify=None, timeout=None):
        captured["url"] = url
        captured["data"] = json.loads(data)
        captured["headers"] = headers
        captured["verify"] = verify
        captured["timeout"] = timeout
        return DummyResponse(payload={"result": [{"status": {"code": 0}}]})

    monkeypatch.setattr(fmg.sess, "post", fake_post)
    monkeypatch.setattr(fmg, "_handle_response", lambda *a, **k: (0, {}))
    fmg._url = "https://fmg.local/jsonrpc"
    fmg._post_login_request("exec", [{"url": "sys/login/user"}])

    assert captured["data"]["method"] == "exec"
    assert captured["data"]["params"][0]["url"] == "sys/login/user"


def test_post_login_request_forticloud(monkeypatch):
    fmg = FortiManager(host="x.fortimanager.forticloud.com", user="u", passwd="p")
    fmg._url = "https://x/p/forticloud_jsonrpc_login/"

    monkeypatch.setattr(fmg, "_get_oauth_token", lambda *a, **k: (200, {"access_token": "tok"}))

    revoked = {"called": False}

    def fake_revoke(*a, **k):
        revoked["called"] = True

    monkeypatch.setattr(fmg, "_revoke_oauth_token", fake_revoke)
    monkeypatch.setattr(fmg.sess, "post", lambda *a, **k: DummyResponse(payload={"result": [{"status": {"code": 0}}]}))
    monkeypatch.setattr(fmg, "_handle_response", lambda *a, **k: (0, {}))

    code, data = fmg._post_login_request("post", None)
    assert code == 0 and data == {}
    assert revoked["called"] is True


def test_post_request_main_paths(monkeypatch, fmg):
    with pytest.raises(FMGValidSessionException):
        fmg._post_request("get", [{"url": "/x"}])

    fmg.sid = "sid"
    fmg._url = "https://fmg.local/jsonrpc"

    monkeypatch.setattr(fmg.sess, "post", lambda *a, **k: DummyResponse(payload={"result": [{"status": {"code": 0}}]}))
    monkeypatch.setattr(fmg, "_handle_response", lambda *a, **k: (0, {"ok": 1}))
    monkeypatch.setattr(fmg, "_freeform_response", lambda *a, **k: (200, [{"ok": 1}]))

    assert fmg._post_request("get", [{"url": "/x"}]) == (0, {"ok": 1})
    assert fmg._post_request("get", [{"url": "/x"}], free_form=True) == (200, [{"ok": 1}])
    assert fmg._post_request("get", [{"url": "/x"}], create_task=True) == (0, {"ok": 1})


def test_post_request_connection_error(monkeypatch, fmg):
    fmg.sid = "sid"
    fmg._url = "https://fmg.local/jsonrpc"

    def raise_conn(*a, **k):
        raise ReqConnError("boom")

    monkeypatch.setattr(fmg.sess, "post", raise_conn)
    with pytest.raises(FMGConnectionError):
        fmg._post_request("get", [{"url": "/x"}])


def test_delete_task(fmg, monkeypatch):
    called = {}
    monkeypatch.setattr(fmg, "delete", lambda url: called.setdefault("url", url) or (0, {}))
    fmg._delete_task(9)
    assert called["url"].endswith("/9")


def test_track_task_success(monkeypatch, fmg):
    now = int(time.time()) - 1
    responses = [
        (0, {"percent": "50", "num_done": "1", "num_err": "0", "num_lines": "2", "start_tm": str(now)}),
        (0, {"percent": "100", "num_done": "2", "num_err": "0", "num_lines": "2", "start_tm": str(now)}),
    ]

    def fake_get(_):
        return responses.pop(0)

    monkeypatch.setattr(fmg, "get", fake_get)
    monkeypatch.setattr("pyFMG.fortimgr.time.sleep", lambda *_: None)

    code, data = fmg.track_task(task_id=1, sleep_time=0)
    assert code == 0
    assert "total_task_time" in data


def test_track_task_fail_gate_with_connerr(monkeypatch):
    fmg = FortiManager(host="fmg.local", user="u", passwd="p", track_task_disable_connerr=True)

    def fake_get(_):
        raise FMGConnectionError("disconnect")

    monkeypatch.setattr(fmg, "get", fake_get)
    monkeypatch.setattr("pyFMG.fortimgr.time.sleep", lambda *_: None)

    code, data = fmg.track_task(task_id=1, retrieval_fail_gate=1, sleep_time=0)
    assert code == -99


def test_track_task_timeout(monkeypatch, fmg):
    old = int(time.time()) - 500

    monkeypatch.setattr(
        fmg,
        "get",
        lambda _: (0, {"percent": "0", "num_done": "0", "num_err": "0", "num_lines": "0", "start_tm": str(old)}),
    )
    monkeypatch.setattr("pyFMG.fortimgr.time.sleep", lambda *_: None)

    code, data = fmg.track_task(task_id=1, timeout=1, sleep_time=0)
    assert code == 1
    assert "timed out" in data["msg"]


def test_login_paths(monkeypatch):
    # API key login
    api_fmg = FortiManager(host="fmg.local", apikey="k")
    monkeypatch.setattr(api_fmg._lock_ctx, "check_mode", lambda: None)
    code, _ = api_fmg.login()
    assert code == 0
    assert api_fmg.sid is not None

    # Standard login
    std = FortiManager(host="fmg.local", user="u", passwd="p")

    def fake_post_login(method, params):
        std.sid = "sid"
        return 0, {}

    monkeypatch.setattr(std, "_post_login_request", fake_post_login)
    monkeypatch.setattr(std._lock_ctx, "check_mode", lambda: None)
    code, _ = std.login()
    assert code == 0

    # Forticloud login branch
    fc = FortiManager(host="x.fortimanager.forticloud.com", user="u", passwd="p")

    def fake_post_login_fc(method, params):
        fc.sid = "sid"
        return 0, {}

    monkeypatch.setattr(fc, "_post_login_request", fake_post_login_fc)
    monkeypatch.setattr(fc._lock_ctx, "check_mode", lambda: None)
    code, _ = fc.login()
    assert code == 0
    assert fc._url.endswith("/jsonrpc")


def test_logout_and_context_manager(monkeypatch, fmg):
    calls = {"unlock": 0, "logout": 0, "login": 0}
    fmg.sid = "sid"

    fmg._lock_ctx.uses_workspace = True
    monkeypatch.setattr(fmg._lock_ctx, "run_unlock", lambda: calls.__setitem__("unlock", calls["unlock"] + 1))
    monkeypatch.setattr(fmg, "execute", lambda url: (0, {"url": url}))

    code, data = fmg.logout()
    assert code == 0
    assert calls["unlock"] == 1
    assert fmg.sid is None

    cm = FortiManager(host="fmg.local", user="u", passwd="p")
    monkeypatch.setattr(cm, "login", lambda: calls.__setitem__("login", calls["login"] + 1))
    monkeypatch.setattr(cm, "logout", lambda: calls.__setitem__("logout", calls["logout"] + 1))
    with cm:
        pass
    assert calls["login"] == 1
    assert calls["logout"] == 1


def test_common_datagram_params():
    p = FortiManager.common_datagram_params("get", "/x", {"foo": 1}, bar__baz=2, alpha___beta=3)
    assert p[0]["foo"] == 1
    assert p[0]["bar-baz"] == 2
    assert p[0]["alpha beta"] == 3

    p2 = FortiManager.common_datagram_params("add", "/x", hello="world")
    assert p2[0]["data"]["hello"] == "world"

    p3 = FortiManager.common_datagram_params("set", "/x", data={"a": 1})
    assert p3[0]["data"] == {"a": 1}


@pytest.mark.parametrize(
    "func_name,method_name,method_type",
    [
        ("get", "get", "get"),
        ("add", "add", "add"),
        ("update", "update", "update"),
        ("set", "set", "set"),
        ("delete", "delete", "delete"),
        ("replace", "replace", "replace"),
        ("clone", "clone", "clone"),
        ("execute", "exec", "execute"),
        ("move", "move", "move"),
        ("unset", "unset", "unset"),
    ],
)
def test_http_verb_wrappers(monkeypatch, fmg, func_name, method_name, method_type):
    called = {}

    def fake_post(method, params):
        called["method"] = method
        called["params"] = params
        return 0, {"ok": True}

    monkeypatch.setattr(fmg, "_post_request", fake_post)
    out = getattr(fmg, func_name)("/x", a=1)
    assert out == (0, {"ok": True})
    assert called["method"] == method_name
    assert called["params"][0]["url"] == "/x"


def test_free_form(monkeypatch, fmg):
    monkeypatch.setattr(fmg, "_post_request", lambda *a, **k: (200, [{"ok": 1}]))
    assert fmg.free_form("exec", data=[{"url": "/x"}], create_task=True)[0] == 200

    with pytest.raises(FMGRequestNotFormedCorrect):
        fmg.free_form("exec")

    with pytest.raises(FMGRequestNotFormedCorrect):
        fmg.free_form("exec", foo=1)


def test_str_and_repr(fmg):
    fmg.sid = None
    assert "no valid connection" in str(fmg).lower()
    assert "no valid connection" in repr(fmg).lower()

    fmg.sid = "sid"
    assert "connected to fmg.local" in str(fmg).lower()
    assert "FortiManager(" in repr(fmg)

import importlib.util
import ipaddress
import pathlib
import socket
import sys
import tempfile
import threading
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module_repository():
    pkg = types.ModuleType("tec_tac")
    pkg.__path__ = []
    sys.modules["tec_tac"] = pkg
    mm = types.ModuleType("tec_tac.module_manager")
    mm.MAX_PACKAGE_BYTES = 1024
    mm.STAGED_ROOT = pathlib.Path("/tmp")
    mm._atomic_json = lambda *a, **k: None
    mm._load_stage = lambda *a, **k: {}
    sys.modules[mm.__name__] = mm
    mv = types.ModuleType("tec_tac.module_manager_v2")
    class E(Exception):
        pass
    mv.LicensingRequirementError = E
    mv.ModuleManagerV2Error = E
    mv._check_runtime_requirements = lambda *a, **k: []
    mv.installed_catalog_v2 = lambda: []
    mv.stage_uploaded_artifact = lambda *a, **k: {}
    mv.discard_v2_stage = lambda *a, **k: None
    mv.attach_source_provenance = lambda *a, **k: None
    sys.modules[mv.__name__] = mv
    ms = types.ModuleType("tec_tac.module_state")
    ms.ModuleStateError = E
    ms.version_satisfies = lambda *a, **k: True
    sys.modules[ms.__name__] = ms
    spec = importlib.util.spec_from_file_location("tec_tac.module_repository", ROOT / "framwork/tec_tac/module_repository.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_repository_proxy_and_invalid_ports():
    repo = load_module_repository()
    for bad in (
        "http://[2001:db8::1]:notaport/repository.json",
        "http://192.0.2.10:70000/repository.json",
        "http://192.0.2.10:0/repository.json",
    ):
        try:
            repo._clean_url(bad)
        except repo.ModuleRepositoryError as exc:
            assert "invalid port" in str(exc).lower()
        else:
            raise AssertionError(f"invalid repository port accepted: {bad}")

    calls = []
    real_proxy_get = repo._pinned_proxy_get
    repo.urllib.request.getproxies = lambda: {"https": "http://proxy.example:8080"}
    repo.urllib.request.proxy_bypass = lambda host: False
    address = ipaddress.ip_address("8.8.8.8")
    repo._resolve_remote_url = lambda value, trust="custom": (
        value, repo.urllib.parse.urlparse(value), (address,)
    )
    repo._pinned_get = lambda *a, **k: (_ for _ in ()).throw(AssertionError("direct fetch used despite HTTPS_PROXY"))
    def proxy_get(url, pinned, proxy_url, **kwargs):
        calls.append((url, pinned, proxy_url))
        return 200, None, b"proxied"
    repo._pinned_proxy_get = proxy_get
    assert repo._fetch("https://repo.example/index.json", 1024) == b"proxied"
    assert calls == [("https://repo.example/index.json", address, "http://proxy.example:8080")]

    # Exercise the actual HTTP proxy transport. The proxy sees the pinned IP in
    # the absolute request URI while the original repository hostname remains
    # in Host, so proxy use does not hand destination selection back to DNS.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    proxy_port = listener.getsockname()[1]
    observed = {}
    def serve_proxy():
        conn, _ = listener.accept()
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                data += conn.recv(4096)
            observed["request"] = data.decode("iso-8859-1")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-proxy")
        listener.close()
    thread = threading.Thread(target=serve_proxy, daemon=True)
    thread.start()
    body = real_proxy_get(
        "http://repo.example/file.json", ipaddress.ip_address("8.8.8.8"),
        f"http://127.0.0.1:{proxy_port}", maximum=1024, timeout=3,
    )[2]
    thread.join(timeout=3)
    assert body == b"via-proxy"
    assert observed["request"].startswith("GET http://8.8.8.8:80/file.json HTTP/1.1")
    assert "Host: repo.example\r\n" in observed["request"]


def test_hotfix_runtime_uses_tactical_python_for_syntax():
    spec = importlib.util.spec_from_file_location("hotfix_runtime", ROOT / "scripts/module-hotfix-job-helper.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    calls = []
    class Result:
        returncode = 0
    helper.subprocess.run = lambda argv, **kwargs: (calls.append((list(argv), kwargs)) or Result())
    helper.privileged_env = lambda *args, **kwargs: {}
    with tempfile.TemporaryDirectory() as td:
        target = pathlib.Path(td) / "module.py"
        target.write_text("x = 1\n", encoding="utf-8")
        helper.validate_runtime(
            {
                "TACTICAL_PYTHON": "/rmm/api/env/bin/python",
                "TACTICAL_USER": "tactical",
                "TACTICAL_BACKEND_ROOT": td,
            },
            [{"component": "extension", "path": "module.py", "target_path": target}],
            {"python_compile": True, "django_check": False},
            open(pathlib.Path(td) / "log.txt", "w", encoding="utf-8"),
        )
    argv = calls[0][0]
    assert argv[:5] == ["runuser", "-u", "tactical", "--", "/rmm/api/env/bin/python"]
    assert "/usr/bin/python3" not in argv
    assert "ast.PyCF_ONLY_AST" in argv[argv.index("-c") + 1]


if __name__ == "__main__":
    test_repository_proxy_and_invalid_ports()
    test_hotfix_runtime_uses_tactical_python_for_syntax()
    print("M15 low-batch behavioral regressions: PASS")

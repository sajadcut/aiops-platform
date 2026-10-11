"""AIOps font integration contract with no assumptions about proprietary binaries."""
from importlib import import_module
from pathlib import Path

from fastapi.testclient import TestClient
import pytest


ROOT = Path(__file__).resolve().parents[2]
main = import_module("apps.api.main")
client = TestClient(main.app)

WEIGHTS = {
    "Thin": 100,
    "UltraLight": 200,
    "Light": 300,
    "Regular": 400,
    "Medium": 500,
    "DemiBold": 600,
    "Bold": 700,
    "ExtraBold": 800,
    "Black": 900,
}


def test_all_three_main_pages_load_one_shared_font_stylesheet():
    for url in ("/dashboard", "/chatbot", "/dashboard/incidents/11111111-1111-4111-8111-111111111111"):
        resp = client.get(url)
        assert resp.status_code == 200
        assert "/dashboard/fonts.css?v=1" in resp.text


def test_shared_font_stylesheet_declares_nine_weights_and_safe_fallbacks():
    response = client.get("/dashboard/fonts.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    css = response.text
    assert css.count("@font-face") == 9
    for name, weight in WEIGHTS.items():
        assert f"IRANSansX{name}.ttf" in css
        assert f"font-weight: {weight};" in css
    assert "font-display: swap" in css
    assert "Vazirmatn" in css and "Tahoma" in css
    assert "font-family: var(--aiops-font-family)" in css
    for file in ("control-center.css", "chatbot.css", "incident-command-room.css"):
        ui = (ROOT / "dashboards" / file).read_text(encoding="utf-8")
        assert "--aiops-font-family" in ui, file


def test_font_http_route_rejects_unknown_paths_and_absent_font(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "_FONT_DIR", tmp_path)
    assert client.get("/assets/fonts/Unauthorized.ttf").status_code == 404
    assert client.get("/assets/fonts/IRANSansXRegular.otf").status_code == 404
    assert client.get("/assets/fonts/IRANSansXRegular.ttf").status_code == 404
    assert client.get("/assets/fonts/..%2Fsecret.txt").status_code == 404


def test_font_http_route_serves_only_approved_files(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "_FONT_DIR", tmp_path)
    source = tmp_path / "IRANSansXRegular.ttf"
    payload = b"\x00\x01\x00\x00" + b"test-font-placeholder"
    source.write_bytes(payload)
    response = client.get("/assets/fonts/IRANSansXRegular.ttf")
    assert response.status_code == 200
    assert response.content == payload
    assert response.headers["content-type"].startswith("font/ttf")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "public" in response.headers["cache-control"]


def test_symlink_is_never_served_as_font(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "_FONT_DIR", tmp_path)
    secret = tmp_path / "outside-secrets"
    secret.write_text("secret", encoding="utf-8")
    link = tmp_path / "IRANSansXRegular.ttf"
    try:
        link.symlink_to(secret)
    except (NotImplementedError, PermissionError, OSError):
        pytest.skip("Symlinks not available in this runtime")
    assert client.get("/assets/fonts/IRANSansXRegular.ttf").status_code == 404


def test_public_repository_publishing_script_requires_redistribution_permission():
    script = (ROOT / "scripts" / "publish-iransansx-fonts.ps1").read_text(encoding="utf-8")
    assert "ConfirmPublicRedistribution" in script
    assert "if (-not $ConfirmPublicRedistribution)" in script
    assert "sajadcut/aiops-platform" in script
    assert "git -C $root" in script
    assert "push', 'origin', 'main" in script
    assert "push --force" not in script
    assert "font/$_" in script
    assert (ROOT / "font" / "README.md").is_file()

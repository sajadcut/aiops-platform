"""Real Chromium acceptance of section 01. Synthetic fixture; no live infrastructure.

Run: python -m playwright install chromium
     python scripts/acceptance/incident_sre_browser.py
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
INCIDENT_ID = "11111111-1111-4111-8111-111111111111"

BRIEF = {
    "snapshot_id": "sre-playwright-snapshot",
    "incident_summary": {"incident_id": INCIDENT_ID, "service": "gfpapi",
                         "status": "analyzing", "severity": "critical",
                         "total_evidence_count": 40, "valid_evidence_count": 25},
    "localized_narrative": {"fa": "توضیح مستند", "en": "Evidence-backed summary"},
    "approval_readiness": {"status": "not_pending", "binding_complete": False},
    "remediation_recommendation": {"risk_level": "high"},
    "configuration_diagnostic": {
        "status": "json_syntax_valid", "path_source": "dotnet_config_syntax",
        "validator_location": "aiops_worker", "remote_python_required": False,
        "evidence_refs": ["dotnet-syntax-evidence-01"],
        "files": [
            {"file": "appsettings.json", "path": "/data/gfp/gfpapi/appsettings.json",
             "path_verified": True, "status": "valid_json_syntax",
             "evidence_ref": "dotnet-syntax-evidence-01"},
            {"file": "appsettings.Production.json",
             "path": "/data/gfp/gfpapi/appsettings.Production.json",
             "path_verified": True, "status": "valid_json_syntax",
             "evidence_ref": "dotnet-syntax-evidence-01"},
            {"file": "GFP.Endpoints.API.runtimeconfig.json",
             "path": "/data/gfp/gfpapi/GFP.Endpoints.API.runtimeconfig.json",
             "path_verified": True, "status": "valid_json_syntax",
             "evidence_ref": "dotnet-syntax-evidence-01"},
        ],
    },
    "operator_explanation": {
        "headline_fa": "توقف سرویس gfpapi تأیید شد؛ علت قطعی هنوز کامل نشده است.",
        "confirmed_findings": [], "uncertainties_fa": [], "next_steps_fa": [],
    },
    "monitoring_sources": [], "mcp_evidence": [], "agent_findings": [],
    "timeline": [], "source_references": [], "rca_assessment": {"rca_confidence": 0.2},
    "technical_investigation": {
        "read_only": True,
        "executive_lines": [
            "gfpapi روی VM 10.248.16.82 متوقف شده است.",
            "systemd Result=timeout",
            "Journal جمع‌آوری نشده است",
            "ELK Match=0",
            "CPU/RAM not recorded",
            "Disk not recorded",
            "مرحله بعد: بررسی Read-only Journal",
        ],
        "domains": [
            {"key": "systemd", "title": "سرویس و systemd", "status": "investigated",
             "technical_result": "ActiveState=failed; Result=timeout; MainPID=0",
             "importance": "بحرانی", "source": "vm_mcp",
             "observed_at": "2026-10-14T10:00:00+00:00",
             "evidence": [{"id": "sys-evidence-001", "tool": "service_status",
                           "freshness": "fresh", "observed_at": "2026-10-14T10:00:00+00:00",
                           "facts": {"active_state": "failed", "result": "timeout", "main_pid": 0}}]},
            {"key": "elastic", "title": "Elasticsearch / ELK",
             "status": "queried_zero_results",
             "technical_result": "Query موفق؛ Match=0؛ صفر نتیجه به معنی سالم بودن نیست",
             "importance": "بالا", "source": "elasticsearch", "evidence": []},
            {"key": "journal", "title": "لاگ سیستم‌عامل و Journal",
             "status": "not_queried", "technical_result": "نتیجه ثبت نشده است.",
             "missing_reason": "جمع‌آوری نشده", "collection_hint": "VM MCP: service_logs",
             "importance": "بالا", "source": "vm_mcp", "evidence": []},
        ],
        "rca": {
            "confirmed_facts": [{"text": "توقف systemd تأیید شده است.",
                                 "evidence_refs": ["sys-evidence-001"]}],
            "likely_hypotheses": [{"title": "تأخیر Dependency",
                                    "kind": "فرضیه", "supporting": ["sys-evidence-001"],
                                    "opposing": [], "check": "Correlation with Journal"}],
            "ruled_out": [],
            "remaining_unknowns": [{"domain": "Journal", "reason": "جمع‌آوری نشده",
                                    "next_check": "service_logs"}],
            "note": "Timeout علت ریشه‌ای را به‌تنهایی ثابت نمی‌کند.",
        },
        "actions": {
            "read_only": [{"title": "Journal", "goal": "بررسی Startup",
                           "tool": "vm_mcp", "prerequisite": "Read-only access",
                           "status": "proposed_not_executed", "expected": "service_logs",
                           "if_positive": "Correlate", "if_negative": "Escalate",
                           "approval_required": False}],
            "conditional": [{"title": "Restart", "goal": "Recovery",
                             "tool": "Governed", "prerequisite": "Approval",
                             "status": "proposed_not_executed", "expected": "Verification",
                             "if_positive": "Verify", "if_negative": "Escalate",
                             "approval_required": True}],
            "prohibited": ["حذف syslog بدون بررسی مجاز نیست."],
        },
    },
}


def main() -> None:
    writes = []
    errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1420, "height": 950})
        page.add_init_script("localStorage.setItem('aiops_api_key','ci-test-key')")
        page.on("pageerror", lambda error: errors.append(str(error)))

        def respond(route):
            req = route.request
            path = urlparse(req.url).path
            if req.method not in {"GET", "HEAD"}:
                writes.append((req.method, path))
                route.fulfill(status=403, body="Read-only acceptance")
                return
            if path.startswith("/dashboard/incidents/"):
                route.fulfill(status=200, content_type="text/html; charset=utf-8",
                              body=(ROOT / "dashboards/incident-command-room.html").read_text())
                return
            if path.startswith("/dashboard/"):
                file = ROOT / "dashboards" / path.rsplit("/", 1)[-1]
                if file.is_file():
                    content_type = ("text/javascript" if file.suffix == ".js" else
                                    "text/css" if file.suffix == ".css" else "text/plain")
                    route.fulfill(status=200, content_type=content_type,
                                  body=file.read_bytes())
                    return
            if path.endswith("/decision-brief"):
                data = BRIEF
            elif path.endswith("/lifecycle"):
                data = {"approval": {"status": "not_pending"}}
            elif path.endswith("/progress/stream"):
                route.fulfill(status=503, body="stream disabled in synthetic acceptance")
                return
            elif "/narrative" in path:
                data = {"snapshot_id": BRIEF["snapshot_id"], "language": "fa",
                        "status": "fallback", "sections": []}
            else:
                data = {}
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps(data, ensure_ascii=False))

        page.route("**/*", respond)
        page.goto(f"http://aiops.test/dashboard/incidents/{INCIDENT_ID}")
        # The detailed audit is intentionally behind progressive disclosure;
        # confirm the operator can still open it deliberately in Chromium.
        page.locator(".ic-overview-details > summary").click(timeout=15000)
        page.locator("#ic-technical-report > details > summary").click(timeout=15000)
        page.locator("#ic-technical-report .ic-sre-table tbody tr").first.wait_for(timeout=15000)
        html = page.locator("#ic-technical-report").inner_text()
        for expected in ("Result=timeout", "Elasticsearch / ELK", "Root Cause Analysis",
                         "تأخیر Dependency", "Match=0", "Read-only", "Approval REQUIRED"):
            assert expected in html, f"missing browser report content: {expected}"
        page.locator("#ic-technical-report .ic-sre-drilldown summary").first.click()
        assert page.get_by_text("sys-evidence-001").count() > 0
        files = page.locator("#ic-diagnosis .ic-config-verified-files")
        files.wait_for(timeout=10000)
        visible_checks = files.inner_text()
        for name in (
            "/data/gfp/gfpapi/appsettings.json",
            "/data/gfp/gfpapi/appsettings.Production.json",
            "/data/gfp/gfpapi/GFP.Endpoints.API.runtimeconfig.json",
            "dotnet-syntax-evidence-01",
        ):
            assert name in visible_checks, "Missing exact checked JSON file: " + name
        assert "سینتکس معتبر" in visible_checks
        assert "password=" not in visible_checks
        assert not writes, f"Opening section 01 executed a write: {writes}"
        assert not errors, f"Chromium console errors: {errors}"
        print("PASS: real Chromium SRE report rendering, evidence drilldown and read-only boundary")
        browser.close()


if __name__ == "__main__":
    main()

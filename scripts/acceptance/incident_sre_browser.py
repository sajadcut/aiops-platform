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
    review_requests = []
    preview_requests = []
    review_state = {"status": "not_responded", "execution_authority": False}
    errors = []
    brief_state = {"current": BRIEF}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1420, "height": 950})
        page.add_init_script("localStorage.setItem('aiops_api_key','ci-test-key')")
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("dialog", lambda dialog: dialog.accept())

        def respond(route):
            req = route.request
            path = urlparse(req.url).path
            if req.method == "POST" and path.endswith("/chat"):
                message = str((req.post_data_json or {}).get("message") or "")
                assert message.startswith("nginx_config_review:"), message
                preview_requests.append(message)
                from copy import deepcopy
                refreshed = deepcopy(brief_state["current"])
                refreshed["snapshot_id"] = "nginx-diff-after-mcp-preview"
                refreshed["dynamic_investigation"]["config_proposal"].update({
                    "status": "candidate_proposed",
                    "service": "nginx", "config_file": "/etc/nginx/nginx.conf",
                    "error_line": 103, "original_sha256": "a" * 64,
                    "candidate_sha256": "b" * 64,
                    "redacted_diff": {
                        "line": 103,
                        "before": "server [arguments redacted] {{",
                        "after": "server [arguments redacted] {",
                    },
                    "current_excerpt": [{"line": 103, "content": "server [arguments redacted] {{"}],
                    "proposed_excerpt": [{"line": 103, "content": "server [arguments redacted] {"}],
                })
                brief_state["current"] = refreshed
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps({"followup_integration": {
                                  "evidence_ref": "nginx-review-from-mcp",
                                  "reassessed": True,
                              }}, ensure_ascii=False))
                return
            if req.method == "POST" and path.endswith("/configuration-review-response"):
                intent = req.post_data_json
                assert intent["decision"] == "request_change_approval"
                assert len(intent["expected_original_sha256"]) == 64
                assert len(intent["expected_candidate_sha256"]) == 64
                review_requests.append(intent)
                review_state.update({
                    "status": "pending_validation",
                    "decision": "request_change_approval",
                    "approval_status": "pending_validation",
                    "approval_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "approval_queue_registered": True,
                    "execution_authority": False,
                    "production_write_performed": False,
                })
                route.fulfill(status=200, content_type="application/json",
                              body=json.dumps(review_state))
                return
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
                data = brief_state["current"]
            elif path.endswith("/lifecycle"):
                data = ({"approval": {
                    "status": "pending_validation",
                    "approval_id": review_state["approval_id"],
                    "metadata": {"target": "10.248.16.82", "binding_complete": True},
                }, "checkpoint_status": "completed"}
                if review_state.get("approval_queue_registered")
                else {"approval": {"status": "not_pending"},
                      # Candidate preview is generated only after the
                      # incident analysis checkpoint has completed; otherwise
                      # the real UI correctly keeps Approval actions disabled.
                      "checkpoint_status": ("completed" if
                          brief_state["current"].get("incident_summary", {}).get("service") == "nginx"
                          else "analyzing")})
            elif path.endswith("/configuration-review-response"):
                data = review_state
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
        # Second read-only Chromium fixture: a real Nginx candidate exists
        # but staging failed (as in the captured production-like log).
        from copy import deepcopy
        next_brief = deepcopy(BRIEF)
        next_brief["snapshot_id"] = "nginx-stage-permission-denied"
        next_brief["incident_summary"]["service"] = "nginx"
        next_brief["configuration_diagnostic"] = {
            "status": "invalid", "config_file": "/etc/nginx/nginx.conf",
            "error_line": 103, "syntax_error": 'unexpected "{"',
            "evidence_refs": ["validator-103"],
        }
        next_brief["dynamic_investigation"] = {
            "status": "advisory", "checks": [], "questions": [],
            "config_proposal": {
                "status": "candidate_proposed", "config_file": "/etc/nginx/nginx.conf",
                "error_line": 103, "validation_status": "STAGED_FAILED",
                "stage_failure_reason": "permission_denied",
                "original_sha256": "a" * 64, "candidate_sha256": "b" * 64,
                "redacted_diff": {"line": 103, "before": "server [arguments redacted] {{",
                                  "after": "server [arguments redacted] {"},
                "source_evidence_refs": ["validator-103", "candidate-103"],
                "execution_authority": False, "apply_eligible": False,
            },
        }
        brief_state["current"] = next_brief
        page.reload()
        banner = page.locator("#ic-config-action-banner")
        banner.wait_for(state="visible", timeout=15000)
        preview = banner.inner_text()
        assert "/etc/nginx/nginx.conf" in preview
        assert "۱۰۳" in preview or "103" in preview
        assert "permission_denied" in preview
        assert "ارسال درخواست به Approval" not in preview
        assert banner.locator("button[data-config-intent]").count() == 0
        assert banner.locator("button:disabled").count() == 0
        assert page.locator(".ic-section-nav a[href='#ic-ai-proposed-fix']").count() == 1
        banner.locator("a[href='#ic-ai-proposed-fix']").click()
        assert page.locator("#ic-ai-proposed-fix #ic-proposed-fix").is_visible()
        assert not writes, f"Opening config proposal executed an unexpected write: {writes}"
        # Exactly one click beneath the reviewed diff queues a governed
        # pending-validation Approval; no executable authority is created.
        submit = page.locator("#ic-ai-proposed-fix button[data-config-intent='request_change_approval']")
        assert submit.count() == 1 and submit.is_enabled()
        assert "ارسال درخواست به Approval" in submit.inner_text()
        submit.click()
        banner.locator("[data-config-request-status='recorded']").wait_for(timeout=15000)
        assert len(review_requests) == 1
        assert "pending_validation" in banner.inner_text()
        assert banner.locator("button[data-config-intent]").count() == 0
        # The same incident displays the durable request but never exposes
        # Approve/Apply until an isolated validator has passed.
        page.locator("#ic-action-state").get_by_text(
            "درخواست تغییر در صف Approval", exact=False
        ).wait_for(timeout=15000)
        assert page.locator("#ic-approve").count() == 0
        assert page.locator("#ic-resume").count() == 0
        assert not writes, f"Requesting config review reached an execution endpoint: {writes}"
        assert not errors, f"Chromium page errors: {errors}"
        # Third fixture: the user's actual screenshot had a failed nginx
        # validator but NO candidate. A deliberate read-only MCP preview
        # action must still be discoverable without executing on page load.
        missing = deepcopy(next_brief)
        missing["snapshot_id"] = "nginx-no-candidate-yet"
        missing["dynamic_investigation"]["config_proposal"] = {
            "status": "needs_read_only_config",
            "config_file": "/etc/nginx/nginx.conf", "error_line": 103,
            "validation_status": "UNVERIFIED", "stage_failure_reason": "not_recorded",
            "execution_authority": False, "apply_eligible": False,
        }
        brief_state["current"] = missing
        review_state = {"status": "not_responded", "execution_authority": False}
        page.reload()
        banner = page.locator("#ic-config-action-banner")
        banner.wait_for(state="visible", timeout=15000)
        assert banner.locator("button[data-config-preview='nginx']:not([data-preview-open-diff])").is_enabled()
        assert banner.locator("button[data-config-intent]").count() == 0
        assert "ساخت پیش‌نمایش اصلاح" in banner.inner_text()
        assert "Diff هنوز ساخته نشده" in banner.inner_text()
        assert "ارسال درخواست به Approval" not in banner.inner_text()
        assert not preview_requests
        banner.locator("button[data-preview-open-diff='1']").click()
        page.locator("#ic-proposed-fix pre").filter(has_text="@@ line 103").wait_for(timeout=15000)
        assert len(preview_requests) == 1
        assert "nginx_config_review:" in preview_requests[0]
        assert banner.locator("a[href='#ic-ai-proposed-fix']").count() == 1
        assert not writes, "Preview Diff unexpectedly triggered an execution write"
        assert not errors, f"Chromium page errors: {errors}"
        print("PASS: SRE evidence, missing-candidate diagnostic, safe preview CTA and no automatic apply")
        browser.close()


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "FILE_INDEX_FA.md"


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True
    )
    paths = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    # هنگام اولین generation خود فایل خروجی هنوز track نشده است؛ با اضافه‌کردن
    # صریح آن، شمارش نوشته‌شده در سند با وضعیت repository بعد از commit یکی می‌ماند.
    paths.add("docs/FILE_INDEX_FA.md")
    return sorted(paths)


def classify(path: str) -> tuple[str, str, str, str, str, str]:
    name = Path(path).name
    suffix = Path(path).suffix.lower()

    if path == ".env":
        return ("ENV", "قرارداد مرکزی تنظیمات runtime و placeholderهای غیرمحرمانه", "Settings", "Pydantic Settings / همه سرویس‌ها", "Runtime", "secret واقعی نباید commit شود")
    if path == "MASTER.md":
        return ("SSoT", "قرارداد معماری، Requirementها و Acceptance اصلی پروژه", "تیم و CI", "کل معماری", "Docs", "Single Source of Truth")
    if path == "FINAL_ACCEPTANCE_REPORT.md":
        return ("Report", "گزارش acceptance بر پایه evidence", "تیم", "MASTER و tests", "Docs", "جای MASTER را نمی‌گیرد")
    if path.startswith(".github/workflows/"):
        return ("CI", "Workflow اتوماسیون GitHub Actions", "GitHub Actions", "repo/tests/deployment", "CI", "کیفیت، hygiene یا supply chain")
    if path == ".gitignore":
        return ("Git", "قواعد عدم track فایل‌های generated/local", "Git", "repository hygiene", "Tooling", "رفتار runtime ندارد")
    if path == "requirements.txt":
        return ("Deps", "فهرست dependencyهای Python", "pip/CI/Docker", "runtime packages", "Build", "ورودی نصب dependency")

    if path.startswith("agents/"):
        if name == "README.md":
            return ("Docs", "راهنمای Agent layer و نقش Agentها", "توسعه‌دهنده", "agents/*", "Docs", "مرجع لایه Agent")
        if "/shared/" in path:
            return ("Python", "زیرساخت مشترک Agentها: contract، coordination، registry یا telemetry", "Orchestrator/Agentها", "domain, LLM, evidence", "Runtime", "Agent write authority ندارد")
        if name == "__init__.py" and path.count("/") >= 2:
            agent = path.split("/")[1]
            return ("Python", f"Agent تخصصی {agent} برای تحلیل و تولید Finding/Evidence request", "Agent registry/orchestrator", "agents.shared + evidence", "Runtime", "تحلیل/پیشنهاد؛ بدون اجرای مستقیم")
        return ("Python", "تعریف package لایه Agent", "Python imports", "agents/*", "Runtime", "package marker")

    if path.startswith("apps/api/"):
        return ("Python", "Route/API سطح کنترل پلتفرم", "FastAPI / Dashboard / clients", "services, security, database", "Runtime", "مرز HTTP و RBAC")
    app_rules = {
        "apps/approval_service/": ("Approval", "منطق و persistence Approval با expiry و transition", "Workflow/API execution", "PostgreSQL/audit", "security gate قبل از execution"),
        "apps/audit_service/": ("Audit", "ثبت، redaction و persistence Audit", "boundaryهای حساس", "PostgreSQL", "برای traceability و forensic"),
        "apps/context_service/": ("Context", "Asset Resolution، Context و Evidence collection", "Orchestrator/signal flow", "MCP integrations/domain", "live evidence مرجع عملیات است"),
        "apps/decision_engine/": ("Decision", "تبدیل RCA/evaluation به تصمیم و risk", "Orchestrator", "evaluation/policy", "LLM authority نیست"),
        "apps/evaluator/": ("Evaluator", "Critic/evaluator gate برای کیفیت RCA", "Orchestrator", "agent findings/thresholds", "قبل از decision"),
        "apps/execution_service/": ("Execution", "مرز اجرای governed، tool registry، idempotency و policy", "API/workflow", "Approval/tools/MCP", "write boundary؛ fail-closed"),
        "apps/incident_service/": ("Persistence", "Repository durable Incident/Evidence/Finding", "signal/workflow/dashboard", "SQLAlchemy/PostgreSQL", "هسته persistence incident"),
        "apps/mcp_server/": ("MCP", "MCP server داخلی برای expose ابزارهای کنترل‌شده", "MCP clients", "provider adapters/security", "capability boundary"),
        "apps/memory_service/": ("Memory", "Operational Memory retrieval/write-back", "Workflow/agents/API", "pgvector/embeddings", "جای live evidence را نمی‌گیرد"),
        "apps/orchestrator/": ("Workflow", "LangGraph orchestration، routing، resume و collaboration", "API/signal gateway", "agents/context/decision/approval", "مسیر E2E durable"),
        "apps/rag_service/": ("RAG", "Knowledge RAG با governance و vector retrieval", "Workflow/agents/API", "pgvector/embedding", "دانش رسمی، جدا از memory"),
        "apps/runbook_service/": ("Runbook", "Registry/Executor runbookهای allow-listed", "API/execution workflow", "domain/runbooks/execution", "اجرای کنترل‌شده"),
        "apps/security/": ("Security", "Authentication، OIDC/JWT و RBAC", "FastAPI dependencies", "OIDC/config", "security boundary"),
        "apps/signal_gateway/": ("Signal", "ورود، normalization، correlation و dedupe سیگنال", "API/webhooks", "incident repository/context", "ابتدای Incident flow"),
        "apps/verification_service/": ("Verify", "Verification مستقل پس از remediation", "Workflow/execution", "live evidence/audit", "tool success برابر recovery نیست"),
        "apps/database/": ("DB", "قرارداد/validation pgvector runtime", "startup/CI", "PostgreSQL", "schema/dimension guard"),
    }
    for prefix, (kind, purpose, called_by, deps, notes) in app_rules.items():
        if path.startswith(prefix):
            return ("Python", f"{kind}: {purpose}", called_by, deps, "Runtime", notes)
    if path.startswith("apps/"):
        return ("Python", "ماژول service لایه application", "Runtime", "domain/integrations", "Runtime", "جزء Control Plane")

    if path.startswith("dashboards/"):
        if suffix == ".css":
            return ("CSS", "استایل Control Center و کنترل‌های عملیاتی", "Browser", "HTML classes", "Runtime UI", "بدون داده fake")
        if suffix == ".js":
            return ("JS", "state، API binding و interaction داشبورد", "Browser", "/api/v1 endpoints", "Runtime UI", "action حساس backend-governed است")
        if suffix == ".html":
            return ("HTML", "پوسته و layout داشبورد", "FastAPI static route", "CSS/JS/API", "Runtime UI", "صفحه اپراتوری")
        return ("Python", "package marker dashboard", "Python", "—", "Tooling", "رفتار مستقل ندارد")

    if path.startswith("database/migrations/versions/"):
        return ("Alembic", "Migration نسخه‌دار schema PostgreSQL", "Alembic/CI", "domain models/pgvector", "DB", "canonical migration chain")
    if path.startswith("database/migrations/") and suffix == ".sql":
        return ("SQL", "SQL قدیمی/مرجع migration legacy", "اپراتور legacy", "PostgreSQL", "Legacy", "روی DB جدید جداگانه اجرا نشود")
    if path.startswith("database/migrations/"):
        return ("Alembic", "تنظیمات و runtime migration", "Alembic", "SQLAlchemy/.env", "DB", "زیرساخت migration")
    if path == "database/__init__.py":
        return ("Python", "Engine/session factory پایگاه‌داده", "repository/storeها", "SQLAlchemy/.env", "Runtime", "اتصال مرکزی PostgreSQL")

    if path.startswith("deployment/"):
        if name == "Dockerfile":
            return ("Docker", "ساخت image آفلاین پلتفرم", "Docker/CI", "requirements/repo", "Deploy", "برای شبکه محدود")
        if suffix in {".yaml", ".yml"}:
            return ("K8s", "Manifest/نمونه config استقرار", "Kubernetes/OpenShift", "image/.env/secrets", "Deploy", "runtime deployment")
        return ("Docs", "راهنما یا artifact manifest استقرار", "اپراتور", "deployment files", "Deploy", "offline/supply-chain")

    if path.startswith("docs/"):
        if name == "__init__.py":
            return ("Python", "package marker docs", "Python", "—", "Docs", "رفتار runtime ندارد")
        return ("Docs", "مستند معماری/عملیات/وضعیت پروژه", "تیم", "کد و MASTER", "Docs", "SSoT نیست مگر MASTER root")

    if path.startswith("domain/contracts/"):
        return ("Python", "Contract مشترک config/context/error/log/retry/rate-limit", "کل runtime", "Pydantic/FastAPI", "Runtime", "قرارداد زیرساختی")
    if path.startswith("domain/"):
        return ("Python", "مدل/Schema/قواعد دامنه AIOps", "apps/*", "Pydantic/SQLAlchemy", "Runtime", "مدل مشترک لایه‌ها")

    if path.startswith("integrations/"):
        if "mcp_client" in path:
            return ("Python", "MCP client برای ارتباط governed با ابزار بیرونی", "Evidence/Tool layer", "MCP transport/.env", "Runtime", "canonical external-tool path")
        if "/llm/" in path:
            return ("Python", "Adapter provider LLM", "Agents/evaluator", "HTTP/provider config", "Runtime", "LLM فقط reasoning")
        return ("Python", "Adapter provider/read-only integration", "MCP server/test helper", "external API/.env", "Runtime/Helper", "Control Plane production ترجیحاً MCP")

    if path.startswith("knowledge/"):
        return ("Python", "Contract/helper لایه Knowledge RAG", "RAG service", "metadata/ACL", "Runtime", "دانش رسمی governed")
    if path.startswith("memory/"):
        return ("Python", "Namespace/contract Operational Memory", "Memory service", "pgvector", "Runtime", "تجربه incidentهای قبلی")

    if path.startswith("runbooks/"):
        if suffix in {".yaml", ".yml"}:
            return ("Runbook", "تعریف عملیات allow-listed و verification/rollback", "Runbook registry", "execution policy", "Runtime data", "نباید arbitrary command باشد")
        return ("Docs", "راهنما/package runbooks", "توسعه‌دهنده", "runbooks/*", "Docs", "تعریف runbookها")

    if path.startswith("scripts/"):
        return ("Python", "ابزار maintenance/validation/seed/build", "Developer/CI", "repo/database", "Tooling", "مسیر اپراتوری کمکی")

    if path.startswith("tests/"):
        if suffix == ".json":
            return ("Fixture", "داده سناریوی تست", "scenario tests", "Agent/workflow contracts", "Test", "production path نیست")
        return ("Test", "تست regression/contract برای بخش متناظر", "pytest/CI", "کد production", "Test", "شواهد repository-level")

    return ("File", "فایل پروژه", "—", "—", "Other", "")


def render() -> str:
    paths = tracked_files()
    lines = [
        "# FILE INDEX فارسی — aiops-platform",
        "",
        "> این فایل فهرست فایل‌به‌فایل repository است. توضیح معماری و flow در `CODEBASE_GUIDE_FA.md` آمده است.",
        "> این فایل با `scripts/generate_file_index_fa.py` ساخته و در CI کنترل می‌شود.",
        "",
        f"**تعداد فایل‌های track‌شده و پوشش‌داده‌شده: {len(paths)}**",
        "",
        "| Path | Type | Purpose | Called By | Calls/Depends On | Runtime/Test/Docs | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for path in paths:
        values = [str(value).replace("|", "/") for value in classify(path)]
        lines.append(f"| `{path}` | " + " | ".join(values) + " |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check Persian repository file index")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print("FILE_INDEX_FA.md is stale or incomplete; run scripts/generate_file_index_fa.py")
            return 1
        print(f"FILE_INDEX_FA.md covers {len(tracked_files())} tracked files")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} with {len(tracked_files())} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

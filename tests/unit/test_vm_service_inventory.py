import pytest
from integrations.vm.service_inventory import parse_systemd_services

RAW = """nginx.service loaded active running A web server
● gfpapi.service loaded failed failed GFP API backend
postgresql.service loaded active running PostgreSQL RDBMS
some.service not-found inactive dead Some service
"""


def test_lists_services_and_failed_filter():
    assert parse_systemd_services(RAW)["matching_count"] == 4
    assert [x["name"] for x in parse_systemd_services(RAW, state="failed")["services"]] == ["gfpapi.service"]


def test_allowlist_restricts_inventory_and_explicit_scope():
    report = parse_systemd_services(RAW, allowed_services={"nginx", "gfpapi.service"})
    assert [x["name"] for x in report["services"]] == ["nginx.service", "gfpapi.service"]
    assert report["scope_restricted"] and report["scope"] == "allowlisted_services"
    assert parse_systemd_services(RAW, allowed_services=set())["services"] == []


def test_search_and_validation():
    assert parse_systemd_services(RAW, query="GFP")["matching_count"] == 1
    with pytest.raises(ValueError):
        parse_systemd_services(RAW, state="other")
    with pytest.raises(ValueError):
        parse_systemd_services(RAW, query="x" * 81)


def test_truncation_is_not_silent():
    report = parse_systemd_services(RAW, limit=1)
    assert len(report["services"]) == 1 and report["truncated"]
    assert report["matching_count"] == 4


def test_injection_looking_unit_is_not_a_service():
    report = parse_systemd_services(RAW + "evil;rm.service loaded active running ignored\n")
    assert report["matching_count"] == 4

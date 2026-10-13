"""No remote Python: syntax stays on the AIOps worker, secrets stay out of MCP."""
import base64
import json

import pytest

from integrations.vm.dotnet_local_validator import (
    remote_file_listing_command, remote_file_read_command,
    safe_json_files, validate_encoded_file,
)


def encoded(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


@pytest.mark.parametrize(("content", "expected"), [
    ('{"Enabled": true, "ApiKey": "SECRET_PASSWORD"}', "valid_json_syntax"),
    ('{"A":1,}', "invalid_json_syntax"),
    ('{\n "Logging": true,\n "Bad": }\n', "invalid_json_syntax"),
    ('{"x": 1, "x": 2}', "invalid_json_syntax"),
])
def test_parse_is_local_and_never_returns_credentials(content, expected):
    result = validate_encoded_file("appsettings.json", encoded(content))
    assert result["status"] == expected
    serialized = json.dumps(result, ensure_ascii=False)
    assert "SECRET_PASSWORD" not in serialized
    assert '"Logging": true' not in serialized
    assert '"Bad"' not in serialized
    assert "ApiKey" not in serialized


def test_safe_error_explains_location_and_possible_fix_without_source_line():
    row = validate_encoded_file("appsettings.json", encoded('{\n  "A": 1,\n  "Bad": }\n'))
    assert row["error_code"] == "json_value_missing"
    assert row["line"] == 3
    assert row["column"] == 10
    assert "مقدار" in row["explanation_fa"]
    assert "Bad" not in json.dumps(row)


def test_target_needs_only_coreutils_no_python_or_dotnet_sdk():
    for command in (remote_file_listing_command("/data/gfp/gfpapi"),
                    remote_file_read_command("/data/gfp/gfpapi", "appsettings.json")):
        assert "python3" not in command and "jq " not in command and "dotnet " not in command
        assert not any(x in command for x in ("rm -", "mv ", "sed -i", "systemctl start"))
    assert "base64 -w 0" in remote_file_read_command("/data/gfp/gfpapi", "appsettings.json")


@pytest.mark.parametrize("filename", [
    "../../etc/shadow", "appsettings.json;touch /tmp/pwned",
    ".env", "secrets.json", "appsettings.Production.json/../../secret",
])
def test_untrusted_file_names_cannot_be_read(filename):
    with pytest.raises(ValueError):
        remote_file_read_command("/data/gfp/gfpapi", filename)


def test_symlinks_and_incomplete_listing_fail_closed():
    names, incomplete = safe_json_files("appsettings.json\tf\nappsettings.Production.json\tl\n")
    assert names == ["appsettings.json"]
    assert incomplete is True
    names, incomplete = safe_json_files("appsettings.json\tf\n")
    assert names == ["appsettings.json"] and incomplete is False
    names, incomplete = safe_json_files("appsettings.json\n")
    assert names == [] and incomplete is True


def test_oversized_and_malformed_payloads_never_report_valid():
    row = validate_encoded_file("appsettings.json", "Y" * 2_000_000)
    assert row["status"] == "unavailable"
    row = validate_encoded_file("appsettings.json", "this is not base64?")
    assert row["status"] != "valid_json_syntax"

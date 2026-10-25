"""CLI smoke tests that do not touch the network."""

from __future__ import annotations

import json

from click.testing import CliRunner

from sascan.cli import cli


def invoke(*args: str):
    return CliRunner().invoke(
        cli,
        ["--no-banner", "--no-color", *args],
        catch_exceptions=False,
    )


def test_help_lists_all_commands() -> None:
    result = invoke("--help")
    assert result.exit_code == 0
    for command in ("scan", "user", "email", "phone", "sites", "version"):
        assert command in result.output


def test_scan_help_contains_key_options() -> None:
    result = invoke("scan", "--help")
    assert result.exit_code == 0
    for option in ("--deep", "--engine", "--only", "--output", "--json"):
        assert option in result.output


def test_sites_json_has_nineteen_rules() -> None:
    result = invoke("sites", "--json")
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert len(payload) == 19
    assert any(item["name"] == "GitHub" for item in payload)


def test_sites_search_filter() -> None:
    result = invoke("sites", "--search", "github", "--json")
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert [item["name"] for item in payload] == ["GitHub"]


def test_version_command_runs() -> None:
    result = invoke("version")
    assert result.exit_code == 0
    assert "sAScan" in result.output
    assert "stateless" in result.output
    assert "Sherlock" in result.output


def test_global_version_flag() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "2.0.0" in result.output


def test_global_flags_work_after_subcommand() -> None:
    result = CliRunner().invoke(
        cli,
        ["version", "--no-banner"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "Runtime" in result.output


def test_no_color_works_after_sites_subcommand() -> None:
    result = CliRunner().invoke(
        cli,
        ["sites", "--json", "--no-color"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert json.loads(result.output)

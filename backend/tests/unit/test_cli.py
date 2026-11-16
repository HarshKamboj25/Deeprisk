import json
from pathlib import Path

import httpx
import pytest

from deprisk.cli import main


def test_cli_success_writes_json_report(tmp_path: Path, monkeypatch) -> None:
    async def fake_scan(repository: Path) -> str:
        return '{"schema_version": "1.0", "findings": []}'

    monkeypatch.setattr("deprisk.cli._run_scan", fake_scan)

    repository = tmp_path / "project"
    repository.mkdir()
    output = tmp_path / "reports" / "report.json"

    exit_code = main(["scan", str(repository), "--output", str(output)])

    assert exit_code == 0
    assert output.exists()

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.0"
    assert report["findings"] == []


def test_cli_creates_output_directory(tmp_path: Path, monkeypatch) -> None:
    async def fake_scan(repository: Path) -> str:
        return '{"status": "ok"}'

    monkeypatch.setattr("deprisk.cli._run_scan", fake_scan)

    repository = tmp_path / "project"
    repository.mkdir()
    output = tmp_path / "nested" / "reports" / "report.json"

    exit_code = main(["scan", str(repository), "--output", str(output)])

    assert exit_code == 0
    assert output.exists()


def test_cli_invalid_repository_returns_error(tmp_path: Path, capsys) -> None:
    missing_repository = tmp_path / "does-not-exist"
    output = tmp_path / "report.json"

    exit_code = main(["scan", str(missing_repository), "--output", str(output)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "DepRisk scan failed:" in captured.err
    assert not output.exists()


def test_cli_handles_osv_network_error(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    async def failing_scan(repository: Path) -> str:
        raise httpx.ConnectError("OSV unavailable")

    monkeypatch.setattr("deprisk.cli._run_scan", failing_scan)

    repository = tmp_path / "project"
    repository.mkdir()
    output = tmp_path / "report.json"

    exit_code = main(["scan", str(repository), "--output", str(output)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "DepRisk scan failed:" in captured.err
    assert not output.exists()


def test_cli_help_displays_scan_command(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "scan" in captured.out
    assert "Explainable software supply-chain vulnerability scanner" in captured.out


def test_cli_github_success_writes_json_report(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    async def fake_github_scan(repository_url: str) -> str:
        assert repository_url == "https://github.com/example/sample-repo"
        return '{"schema_version": "1.1", "findings": []}'

    async def unexpected_local_scan(repository: Path) -> str:
        raise AssertionError("GitHub URL was routed to local scanning")

    monkeypatch.setattr("deprisk.cli._run_github_scan", fake_github_scan)
    monkeypatch.setattr("deprisk.cli._run_scan", unexpected_local_scan)

    output = tmp_path / "reports" / "github-report.json"
    repository_url = "https://github.com/example/sample-repo"

    exit_code = main(["scan", repository_url, "--output", str(output)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert output.exists()
    assert "Scan completed: https://github.com/example/sample-repo" in captured.out

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.1"
    assert report["findings"] == []


def test_cli_local_path_preserves_local_scanning(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = tmp_path / "project"
    repository.mkdir()
    output = tmp_path / "report.json"

    async def fake_local_scan(received_repository: Path) -> str:
        assert received_repository == repository
        return '{"status": "local"}'

    async def unexpected_github_scan(repository_url: str) -> str:
        raise AssertionError("Local path was routed to GitHub scanning")

    monkeypatch.setattr("deprisk.cli._run_scan", fake_local_scan)
    monkeypatch.setattr("deprisk.cli._run_github_scan", unexpected_github_scan)

    exit_code = main(["scan", str(repository), "--output", str(output)])

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8")) == {"status": "local"}


def test_cli_github_scan_failure_does_not_write_report(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    async def failing_github_scan(repository_url: str) -> str:
        raise ValueError("GitHub repository unavailable")

    monkeypatch.setattr("deprisk.cli._run_github_scan", failing_github_scan)

    output = tmp_path / "report.json"

    exit_code = main(
        [
            "scan",
            "https://github.com/example/sample-repo",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "DepRisk scan failed: GitHub repository unavailable" in captured.err
    assert not output.exists()

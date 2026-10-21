from pathlib import Path

import pytest

from php2shell_audit.cli import main


def test_affected_version_exit_code(capsys) -> None:
    assert main(["version", "8.5.11"]) == 2
    assert "[AFFECTED]" in capsys.readouterr().out


def test_patched_version_json(capsys) -> None:
    assert main(["version", "8.5.12", "--format", "json"]) == 0
    assert '"patched": 1' in capsys.readouterr().out


def test_remote_dry_run_needs_no_acknowledgement(capsys) -> None:
    assert main(["remote", "--target", "https://example.test", "--dry-run"]) == 0
    assert "no traffic sent" in capsys.readouterr().out


def test_output_file(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    assert main(["version", "8.4.27", "--format", "json", "--output", str(output)]) == 0
    assert '"php_version"' in output.read_text(encoding="utf-8")


def test_target_file_dry_run(tmp_path: Path, capsys) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("# comment\nexample.test\nexample.test\n", encoding="utf-8")
    assert main(["remote", "--target-file", str(targets), "--dry-run"]) == 0
    assert "1 unique targets" in capsys.readouterr().out


@pytest.mark.parametrize(
    "arguments",
    [
        ["remote", "--target", "example.test"],
        ["remote", "--target", "example.test", "--timeout", "0", "--dry-run"],
        ["remote", "--target", "example.test", "--workers", "99", "--dry-run"],
        ["version", "invalid"],
    ],
)
def test_invalid_configuration_exits(arguments) -> None:
    with pytest.raises(SystemExit) as raised:
        main(arguments)
    assert raised.value.code == 2


def test_target_limit_exits() -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "remote",
                "--target",
                "one.test",
                "--target",
                "two.test",
                "--max-targets",
                "1",
                "--dry-run",
            ]
        )

import pytest
from find_evil.tools.command import assemble_command, load_metadata, CommandBuildError
from find_evil.engine.schemas import ToolParams, Evidence

META = load_metadata("src/find_evil/tools/metadata.yaml")
ALLOW = ["/mnt/evidence/"]
EV = {
    "ev1": Evidence(
        evidence_id="ev1",
        path="/mnt/evidence/win10.E01",
        type="disk_image",
        sha256="x",
        size_bytes=1,
    )
}


def test_clean_command_assembles():
    cmd = assemble_command(
        META, ToolParams(tool="mmls", params={"image": "ev1"}), EV, ALLOW
    )
    assert cmd == "sudo mmls /mnt/evidence/win10.E01"


def test_narration_cannot_become_a_command():
    # The OLD failure mode: model returns prose. Here the model can only fill slots,
    # and prose in a slot is rejected, never executed.
    bad = ToolParams(
        tool="mmls", params={"image": "Since no files were provided I will; rm -rf /"}
    )
    with pytest.raises(CommandBuildError):
        assemble_command(META, bad, EV, ALLOW)


def test_unknown_evidence_id_rejected():
    with pytest.raises(CommandBuildError):
        assemble_command(
            META, ToolParams(tool="mmls", params={"image": "ghost"}), EV, ALLOW
        )


def test_path_outside_allowlist_rejected():
    ev = {
        "ev1": Evidence(
            evidence_id="ev1", path="/etc/shadow", type="file", sha256="x", size_bytes=1
        )
    }
    with pytest.raises(CommandBuildError):
        assemble_command(
            META, ToolParams(tool="mmls", params={"image": "ev1"}), ev, ALLOW
        )

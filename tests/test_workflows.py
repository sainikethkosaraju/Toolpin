"""Every GitHub Actions workflow must be valid YAML with triggers and jobs. (GitHub reports an invalid file as a
failed run named after its path, which is easy to miss.)"""
from pathlib import Path

import pytest
import yaml

FILES = sorted((Path(__file__).parent.parent / ".github" / "workflows").glob("*.yml"))


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_workflow_is_valid(path):
    doc = yaml.safe_load(path.read_text())
    assert isinstance(doc, dict) and doc.get("jobs"), f"{path.name}: no jobs"
    assert doc.get("on") or doc.get(True), f"{path.name}: no triggers"   # PyYAML parses the bare key `on` as True
    for name, job in doc["jobs"].items():
        assert job.get("steps"), f"{path.name}:{name}: no steps"

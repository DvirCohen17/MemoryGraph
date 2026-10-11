"""'Load existing' given a memory image (or any non-investigation file) must say so at once, without reading the whole file."""
import gzip
import json

import pytest

from app.models import NotAnInvestigationFile, load_analysis_result, sniff_investigation_file


def test_memory_image_is_recognised_by_extension(tmp_path):
    image = tmp_path / "physmem.raw"
    image.write_bytes(b"\x00" * 4096 + b"\xff\xfe\xfd")
    with pytest.raises(NotAnInvestigationFile) as info:
        load_analysis_result(str(image))
    assert info.value.memory_image
    assert "Run analysis" in str(info.value)


def test_large_binary_file_counts_as_memory_image(tmp_path):
    image = tmp_path / "capture.dat"
    image.write_bytes(b"MZ\x00\x01" * (300 * 1024))
    with pytest.raises(NotAnInvestigationFile) as info:
        sniff_investigation_file(str(image))
    assert info.value.memory_image


def test_other_text_file_is_not_an_investigation(tmp_path):
    other = tmp_path / "notes.txt"
    other.write_text("hello")
    with pytest.raises(NotAnInvestigationFile) as info:
        sniff_investigation_file(str(other))
    assert not info.value.memory_image


def test_saved_investigations_pass_the_check(tmp_path):
    plain = tmp_path / "a.json"
    plain.write_text("﻿  " + json.dumps({"processes": []}), encoding="utf-8")
    sniff_investigation_file(str(plain))
    packed = tmp_path / "a.json.gz"
    with gzip.open(packed, "wt", encoding="utf-8") as handle:
        handle.write("{}")
    sniff_investigation_file(str(packed))

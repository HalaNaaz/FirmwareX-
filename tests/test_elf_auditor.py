"""Unit tests for ELF parser, architecture detection, and hardening mitigation matrix."""

import pytest
from pathlib import Path

from firmwarex.core.elf_auditor import ELFAuditor, summarize_mitigations
from tests.fixtures_helper import create_minimal_elf


def test_elf_nx_enabled(tmp_path):
    """Test ELF binary with NX stack protection enabled (PT_GNU_STACK without PF_X)."""
    elf_data = create_minimal_elf(
        arch="x86_64",
        bitness=64,
        endianness="little",
        enable_nx=True,
        has_relro=True,
        is_pie=True,
    )
    elf_file = tmp_path / "test_nx_on.elf"
    elf_file.write_bytes(elf_data)

    auditor = ELFAuditor()
    report = auditor.audit_binary(elf_file)

    assert report.is_valid_elf is True
    assert report.architecture == "x86_64"
    assert report.bitness == 64
    assert report.endianness == "little"
    assert report.nx.status == "enabled"
    assert "Non-executable stack" in report.nx.evidence
    assert report.pie.status == "enabled"
    assert report.relro.status == "enabled"


def test_elf_nx_disabled(tmp_path):
    """Test ELF binary with executable stack (PT_GNU_STACK with PF_X flag)."""
    elf_data = create_minimal_elf(
        arch="arm",
        bitness=32,
        endianness="little",
        enable_nx=False,
        has_relro=False,
        is_pie=False,
    )
    elf_file = tmp_path / "test_nx_off.elf"
    elf_file.write_bytes(elf_data)

    auditor = ELFAuditor()
    report = auditor.audit_binary(elf_file)

    assert report.is_valid_elf is True
    assert report.architecture == "ARM32"
    assert report.bitness == 32
    assert report.nx.status == "not_detected"
    assert "execute flag enabled" in report.nx.evidence
    assert report.relro.status == "not_detected"
    assert report.pie.status == "not_detected"


def test_elf_mips_big_endian(tmp_path):
    """Test MIPS 32-bit big-endian ELF parsing."""
    elf_data = create_minimal_elf(
        arch="mips",
        bitness=32,
        endianness="big",
        enable_nx=True,
    )
    elf_file = tmp_path / "test_mips.elf"
    elf_file.write_bytes(elf_data)

    auditor = ELFAuditor()
    report = auditor.audit_binary(elf_file)

    assert report.is_valid_elf is True
    assert report.architecture == "MIPS"
    assert report.bitness == 32
    assert report.endianness == "big"


def test_non_elf_handling(tmp_path):
    """Test graceful handling of a non-ELF file."""
    text_file = tmp_path / "not_an_elf.txt"
    text_file.write_text("Hello world, this is a plain text file")

    auditor = ELFAuditor()
    report = auditor.audit_binary(text_file)

    assert report.is_valid_elf is False
    assert "Not an ELF binary" in report.error_message


def test_summarize_mitigations(tmp_path):
    """Test aggregate percentage and count calculations across multiple binaries."""
    elf1 = tmp_path / "elf1.bin"
    elf1.write_bytes(create_minimal_elf(enable_nx=True, has_relro=True))

    elf2 = tmp_path / "elf2.bin"
    elf2.write_bytes(create_minimal_elf(enable_nx=False, has_relro=False))

    auditor = ELFAuditor()
    reports = auditor.audit_all_in_directory(tmp_path)
    summary = summarize_mitigations(reports)

    assert summary["total_binaries"] == 2
    assert summary["nx_enabled"] == 1
    assert summary["nx_percentage"] == 50.0


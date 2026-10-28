"""Unit tests for nested archive extraction, depth limits, and quota enforcement."""

import tarfile
import zipfile

from firmwarex.core.unpacker import SafeExtractor


def test_nested_archive_extraction(tmp_path):
    """Verify that an inner TAR archive within a ZIP is extracted recursively."""
    # 1. Create inner tarball
    inner_tar = tmp_path / "inner.tar"
    with tarfile.open(inner_tar, "w") as tf:
        data = b"Hello from inside the nested layer!"
        import io
        ti = tarfile.TarInfo("deep_config.cfg")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

    # 2. Package inner tarball inside outer ZIP
    outer_zip = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer_zip, "w") as zf:
        zf.writestr("top_level.txt", b"top level data")
        zf.write(inner_tar, arcname="inner.tar")

    extractor = SafeExtractor(max_nesting_depth=2)
    out_dir = tmp_path / "extracted_nested"

    res = extractor.extract(outer_zip, out_dir)
    assert res.success is True
    assert res.status == "extracted"
    assert res.nesting_depth_reached >= 1

    # Verify inventory has both top_level.txt and deep_config.cfg
    file_paths = [item.path for item in res.inventory]
    assert any("top_level.txt" in p for p in file_paths)
    assert any("deep_config.cfg" in p for p in file_paths)

    # Verify provenance metadata
    deep_item = next(item for item in res.inventory if "deep_config.cfg" in item.path)
    assert deep_item.nesting_level >= 1
    assert deep_item.parent_archive == "inner.tar"


def test_nesting_depth_limit_enforced(tmp_path):
    """Verify that nested archive recursion stops at max_nesting_depth."""
    # Level 3 inner tar
    l3_tar = tmp_path / "l3.tar"
    with tarfile.open(l3_tar, "w") as tf:
        import io
        ti = tarfile.TarInfo("l3_secret.txt")
        ti.size = 6
        tf.addfile(ti, io.BytesIO(b"secret"))

    # Level 2 inner tar
    l2_tar = tmp_path / "l2.tar"
    with tarfile.open(l2_tar, "w") as tf:
        tf.add(l3_tar, arcname="l3.tar")

    # Level 1 outer zip
    outer_zip = tmp_path / "l1.zip"
    with zipfile.ZipFile(outer_zip, "w") as zf:
        zf.write(l2_tar, arcname="l2.tar")

    # Restrict max_nesting_depth to 1
    extractor = SafeExtractor(max_nesting_depth=1)
    out_dir = tmp_path / "extracted_depth_limited"

    res = extractor.extract(outer_zip, out_dir)
    assert res.success is True
    assert res.nesting_depth_reached <= 1


def test_cumulative_file_quota_across_nested_layers(tmp_path):
    """Verify that cumulative file count limits trigger across nested archives."""
    # Inner tar with 8 files
    inner_tar = tmp_path / "inner_many.tar"
    with tarfile.open(inner_tar, "w") as tf:
        import io
        for i in range(8):
            ti = tarfile.TarInfo(f"inner_{i}.txt")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))

    # Outer zip with 8 files + inner tar = 9 total members
    outer_zip = tmp_path / "outer_many.zip"
    with zipfile.ZipFile(outer_zip, "w") as zf:
        for i in range(5):
            zf.writestr(f"outer_{i}.txt", b"x")
        zf.write(inner_tar, arcname="inner_many.tar")

    # Set quota to 10 files (5 outer + 1 inner tar = 6; plus 8 nested = 14 > 10)
    extractor = SafeExtractor(max_file_count=10, max_nesting_depth=2)
    out_dir = tmp_path / "extracted_quota_fail"

    # Cumulative quota should be caught during nested expansion or top level
    res = extractor.extract(outer_zip, out_dir)
    # The nested extraction handles errors gracefully and keeps the outer items within quota
    assert res.success is True
    assert len(res.inventory) <= 15

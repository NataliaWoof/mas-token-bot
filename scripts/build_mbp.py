#!/usr/bin/env python3
"""Build a .mbp archive for this maubot plugin without external tooling."""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

ROOT = Path(__file__).resolve().parent.parent
META_FILE = ROOT / "maubot.yaml"


def _parse_maubot_metadata(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Metadata file not found: {path}")
    data: Dict[str, Any] = {}
    current_list: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            if current_list is not None:
                data.setdefault(current_list, []).append(
                    line[1:].strip().strip('"'))
            continue
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value:
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            data[key] = value
            current_list = None
        else:
            current_list = key
            data.setdefault(current_list, [])
    for required in ("id", "version"):
        if required not in data:
            raise ValueError(f"Missing '{required}' in {path}")
    data.setdefault("modules", [])
    data.setdefault("extra_files", [])
    return data


def _collect_module_paths(modules: Iterable[str]) -> Set[Path]:
    paths: Set[Path] = set()
    for module in modules:
        module = module.strip()
        if not module:
            continue
        module_path = module.replace(".", "/")
        file_candidate = ROOT / f"{module_path}.py"
        dir_candidate = ROOT / module_path
        if file_candidate.exists():
            paths.add(file_candidate)
            continue
        if dir_candidate.exists():
            for item in dir_candidate.rglob("*"):
                if item.is_file() and "__pycache__" not in item.parts:
                    paths.add(item)
            continue
        raise FileNotFoundError(
            f"Unable to locate module '{module}' at "
            f"'{file_candidate}' or '{dir_candidate}'")
    return paths


def _collect_extra_paths(extra_files: Iterable[str]) -> Set[Path]:
    paths: Set[Path] = set()
    for entry in extra_files:
        entry = entry.strip()
        if not entry:
            continue
        candidate = ROOT / entry
        if not candidate.exists():
            raise FileNotFoundError(f"Extra file not found: {candidate}")
        if candidate.is_dir():
            for item in candidate.rglob("*"):
                if item.is_file() and "__pycache__" not in item.parts:
                    paths.add(item)
        else:
            paths.add(candidate)
    return paths


def build_archive(output_dir: Path) -> Path:
    metadata = _parse_maubot_metadata(META_FILE)
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_id = metadata["id"].replace("/", "_")
    archive_name = f"{safe_id}-{metadata['version']}.mbp"
    archive_path = output_dir / archive_name

    files_to_package: Set[Path] = {META_FILE}
    files_to_package |= _collect_module_paths(metadata.get("modules", []))
    files_to_package |= _collect_extra_paths(metadata.get("extra_files", []))

    with zipfile.ZipFile(archive_path,
                         mode="w",
                         compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files_to_package):
            archive.write(path, arcname=str(path.relative_to(ROOT)))
    return archive_path


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the maubot plugin archive (.mbp).")
    parser.add_argument("--out",
                        default="dist",
                        help="Output directory for the generated archive "
                        "(default: %(default)s)")
    args = parser.parse_args(argv)
    output_dir = (ROOT / args.out).resolve()
    archive_path = build_archive(output_dir)
    print(f"Built plugin archive at {archive_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

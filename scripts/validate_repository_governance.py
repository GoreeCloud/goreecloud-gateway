#!/usr/bin/env python3
"""Fail-closed validation for GoreeCloud Gateway repository governance records."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_RECORDS = {
    "README.md": "# GoreeCloud Gateway",
    "PROJECT-SPECIFICATIONS.md": "# GoreeCloud Gateway — Project Specifications",
    "PROJECT-RECORD.md": "# GoreeCloud Gateway — Project Record",
    "FEATURES.md": "# GoreeCloud Gateway Features",
    "BENEFITS.md": "# GoreeCloud Gateway Benefits",
    "COMPETITIVE-OBJECTIVES.md": "# GoreeCloud Gateway Competitive Objectives",
    "BRANDING.md": "# GoreeCloud Gateway Branding",
    "IMPLEMENTED-FEATURES.md": "# GoreeCloud Gateway Implemented Features",
    "PLANNED-FEATURES.md": "# GoreeCloud Gateway Planned Features",
    "CHANGELOGS.md": "# GoreeCloud Gateway Changelogs",
}

RETIRED_RECORDS = (
    "FEATURE-ROADMAP.md",
    "SPECIFICATIONS.md",
)

LICENSE_MARKERS = (
    "GNU AFFERO GENERAL PUBLIC LICENSE",
    "Version 3, 19 November 2007",
)


def read_required(relative: str, errors: list[str]) -> str | None:
    path = ROOT / relative
    if not path.is_file() or path.is_symlink():
        errors.append(f"missing, non-regular, or symlinked required root file: {relative}")
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"required root file is not readable UTF-8: {relative}: {exc.__class__.__name__}")
        return None


def main() -> int:
    errors: list[str] = []

    for relative, heading in REQUIRED_RECORDS.items():
        text = read_required(relative, errors)
        if text is None:
            continue
        lines = text.splitlines()
        if not lines or lines[0] != heading:
            errors.append(f"unexpected governance identity heading in {relative}; expected {heading!r}")
        if len(text.strip()) < len(heading) + 80:
            errors.append(f"governance record is unexpectedly skeletal: {relative}")

    for relative in RETIRED_RECORDS:
        path = ROOT / relative
        if path.exists() or path.is_symlink():
            errors.append(f"retired repository control must not exist: {relative}")

    license_text = read_required("LICENSE", errors)
    if license_text is not None:
        for marker in LICENSE_MARKERS:
            if marker not in license_text:
                errors.append(f"LICENSE does not contain expected AGPL-3.0 marker: {marker!r}")

    if errors:
        print("GoreeCloud Gateway repository governance validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(
        "GoreeCloud Gateway repository governance validation passed: mandatory root governance records, "
        "Git-native feature/change authorities, retirement guards, and explicit AGPL-3.0 license material "
        "are structurally valid."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

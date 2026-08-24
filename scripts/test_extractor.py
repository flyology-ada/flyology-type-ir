#!/usr/bin/env python3
"""Host-toolchain integration checks for the process-owned extractor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "python"))

from flyology_type_ir.extractor import (  # noqa: E402
    canonical_bytes,
    ExtractionError,
    ExtractionRequest,
    extract_checked,
)
from flyology_type_ir import extractor as extractor_module  # noqa: E402
from flyology_type_ir import load_checked  # noqa: E402


def _replace_strings(value: object, replacements: tuple[tuple[str, str], ...]) -> object:
    if isinstance(value, dict):
        return {key: _replace_strings(child, replacements) for key, child in value.items()}
    if isinstance(value, list):
        return [_replace_strings(child, replacements) for child in value]
    if isinstance(value, str):
        for original, placeholder in replacements:
            value = value.replace(original, placeholder)
    return value


def _refresh_audit_digests(document: dict[str, object]) -> None:
    context = document["context"]
    context["effective_project"]["closure_digest"] = (
        extractor_module.checker.effective_closure_digest(document)
    )
    legality = context["legality_check"]
    legality["command_fingerprint"] = hashlib.sha256(
        canonical_bytes(legality["command"])
    ).hexdigest()


def portable_audit_bytes(document: object) -> bytes:
    """Retain all audit data while replacing only three host-root prefixes."""
    mutable = json.loads(canonical_bytes(document))
    context = mutable["context"]
    checkout_root = Path(context["canonical_gpr_path"]).parents[2]
    gprbuild_root = Path(context["compiler_path"]).parent.parent
    path_entry = next(
        item["value"]
        for item in context["legality_check"]["command"]["environment"]
        if item["name"] == "PATH"
    )
    path_parts = path_entry.split(os.pathsep)
    if len(path_parts) != 2:
        raise AssertionError("audit PATH is not the exact GPRbuild/GNAT pair")
    gnat_root = Path(path_parts[1]).parent
    replacements = tuple(
        sorted(
            (
                (str(checkout_root), "${TYPE_IR_ROOT}"),
                (str(gprbuild_root), "${GPRBUILD_ROOT}"),
                (str(gnat_root), "${GNAT_ROOT}"),
            ),
            key=lambda item: len(item[0]),
            reverse=True,
        )
    )
    normalized = _replace_strings(mutable, replacements)
    _refresh_audit_digests(normalized)
    return canonical_bytes(normalized)


def relocated_audit(document: object, destination: Path) -> dict[str, object]:
    """Model the exact audit change caused only by moving the checkout root."""
    mutable = json.loads(canonical_bytes(document))
    old_root = str(Path(mutable["context"]["canonical_gpr_path"]).parents[2])
    relocated = _replace_strings(mutable, ((old_root, str(destination)),))
    _refresh_audit_digests(relocated)
    return relocated


def request(arguments: argparse.Namespace, project: Path, source: Path) -> ExtractionRequest:
    return ExtractionRequest(
        project=project,
        source=source,
        unit_name="Production_Shapes",
        gprbuild=arguments.gprbuild,
        gnatls=arguments.gnatls,
        lal_probe=arguments.lal_probe,
        target=arguments.target,
        runtime=arguments.runtime,
        environment_path=tuple(arguments.path),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gprbuild", required=True, type=Path)
    parser.add_argument("--gnatls", required=True, type=Path)
    parser.add_argument("--lal-probe", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--path", action="append", default=[], type=Path)
    arguments = parser.parse_args()
    project = ROOT / "fixtures/extraction/production_shapes.gpr"
    source = ROOT / "fixtures/extraction/src/production_shapes.ads"
    first = extract_checked(request(arguments, project, source))
    second = extract_checked(request(arguments, project, source))
    if first.profile != "strict" or first.semantic_fingerprint != second.semantic_fingerprint:
        raise AssertionError("owned extraction was not deterministic and production-strict")
    if canonical_bytes(first.document) != canonical_bytes(second.document):
        raise AssertionError("owned extraction audit context was not deterministic")
    golden = load_checked(ROOT / "fixtures/production-extraction.json", "structural")
    if first.semantic_fingerprint != golden.semantic_fingerprint:
        raise AssertionError("production extraction semantic golden is stale")
    if portable_audit_bytes(first.document) != portable_audit_bytes(golden.document):
        raise AssertionError("production extraction portable audit golden is stale")
    simulated_clone = relocated_audit(
        golden.document, Path("/example/relocated/flyology-type-ir")
    )
    if portable_audit_bytes(simulated_clone) != portable_audit_bytes(golden.document):
        raise AssertionError("clone relocation changed the portable audit golden")
    command = first.document["context"]["legality_check"]["command"]
    configuration = (ROOT / "fixtures/extraction/no_config.adc").resolve()
    if f"-gnatec={configuration}" not in command["argv"]:
        raise AssertionError("GNAT legality did not force the reviewed configuration")
    configurations = first.document["context"]["effective_project"][
        "configuration_pragmas"
    ]
    if len(configurations) != 1 or configurations[0]["logical_name"] != str(
        configuration
    ):
        raise AssertionError("effective configuration manifest is not exact")
    checker = extractor_module.checker
    for attribute in ("SCHEMA_SHA256", "__flyology_source_sha256__"):
        with mock.patch.object(checker, attribute, "0" * 64):
            try:
                extract_checked(request(arguments, project, source))
            except ExtractionError:
                pass
            else:
                raise AssertionError(f"stale loaded {attribute} identity was accepted")
    for constant in ("EXPECTED_CHECKER_SHA256", "EXPECTED_SCHEMA_SHA256"):
        with mock.patch.object(extractor_module, constant, "0" * 64):
            try:
                extract_checked(request(arguments, project, source))
            except ExtractionError:
                pass
            else:
                raise AssertionError(f"{constant} drift was accepted")

    resolved = extractor_module.resolve_request(request(arguments, project, source))
    runtime_manifest = extractor_module.runtime_closure(resolved.runtime)
    gprbuild_manifest = extractor_module.tree_manifest(
        resolved.gprbuild.parent.parent
    )
    gnat_manifest = extractor_module.tree_manifest(resolved.gnatls.parent.parent)
    native_path = Path(extractor_module.approved_toolchain(ROOT)["gmp_path"])
    native_identity = extractor_module.path_identity(native_path)
    stable_paths = (resolved.project, resolved.source)
    stable_snapshot = extractor_module.snapshot(stable_paths)
    with mock.patch.object(extractor_module, "runtime_closure", return_value=((), ())):
        try:
            extractor_module.assert_unchanged(
                resolved,
                runtime_manifest,
                gprbuild_manifest,
                gnat_manifest,
                native_identity,
                native_path,
                stable_paths,
                stable_snapshot,
                "membership regression",
            )
        except ExtractionError:
            pass
        else:
            raise AssertionError("runtime membership drift was not rejected")
    with mock.patch.object(extractor_module, "MAX_COMMAND_OUTPUT", 1024):
        try:
            extractor_module.run_checked(
                [sys.executable, "-c", "print('x' * 2048)"],
                cwd=ROOT,
                environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
        except ExtractionError:
            pass
        else:
            raise AssertionError("subprocess output bound was not enforced")
    with mock.patch.object(extractor_module, "COMMAND_TIMEOUT_SECONDS", 0.05):
        try:
            extractor_module.run_checked(
                [sys.executable, "-c", "import time; time.sleep(1)"],
                cwd=ROOT,
                environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
        except ExtractionError:
            pass
        else:
            raise AssertionError("subprocess timeout was not enforced")

    with tempfile.TemporaryDirectory(prefix="flyology-type-ir-negative-") as directory:
        copied = Path(directory)
        tree = copied / "tree"
        tree.mkdir()
        (tree / "first").write_bytes(b"same reviewed bytes")
        (tree / "second").write_bytes(b"same reviewed bytes")
        link = tree / "selected"
        link.symlink_to("first")
        before_link = extractor_module.tree_manifest(tree)
        link.unlink()
        link.symlink_to("second")
        if extractor_module.tree_manifest(tree) == before_link:
            raise AssertionError("symlink retargeting did not change the tree manifest")
        before_file_mode = extractor_module.tree_manifest(tree)
        (tree / "first").chmod(0o600)
        if extractor_module.tree_manifest(tree) == before_file_mode:
            raise AssertionError("file mode drift did not change the tree manifest")
        before_root_mode = extractor_module.tree_manifest(tree)
        tree.chmod((tree.stat().st_mode & 0o777) ^ 0o001)
        if extractor_module.tree_manifest(tree) == before_root_mode:
            raise AssertionError("directory mode drift did not change the tree manifest")
        link.unlink()
        link.symlink_to(source)
        try:
            extractor_module.tree_manifest(tree)
        except ExtractionError:
            pass
        else:
            raise AssertionError("external tool/runtime symlink was accepted")

        native = copied / "native"
        for version in ("a", "b"):
            library = native / "cellar" / version / "lib"
            library.mkdir(parents=True)
            (library / "libdependency").write_bytes(b"same native bytes")
        current = native / "opt" / "current"
        current.parent.mkdir()
        current.symlink_to("../cellar/a")
        dependency = current / "lib/libdependency"
        before_native = extractor_module.path_identity(dependency)
        current.unlink()
        current.symlink_to("../cellar/b")
        if extractor_module.path_identity(dependency) == before_native:
            raise AssertionError("native dependency path retargeting was not detected")

        copied_source_dir = copied / "src"
        copied_source_dir.mkdir()
        copied_project = copied / "production_shapes.gpr"
        copied_source = copied_source_dir / "production_shapes.ads"
        shutil.copy2(project, copied_project)
        text = source.read_text(encoding="utf-8").replace(
            "end Production_Shapes;",
            "   Extra : constant := 1;\nend Production_Shapes;",
        )
        copied_source.write_text(text, encoding="utf-8")
        try:
            extract_checked(request(arguments, project, copied_source))
        except ExtractionError:
            pass
        else:
            raise AssertionError("project/source split was accepted")
        try:
            extract_checked(request(arguments, copied_project, copied_source))
        except ExtractionError:
            pass
        else:
            raise AssertionError("unsupported public declaration emitted an IR document")

        aliased_source = copied_source_dir / "aliased_shapes.ads"
        aliased_source.write_text(
            source.read_text(encoding="utf-8").replace(
                "array (Position) of Color", "array (Position) of aliased Color"
            ),
            encoding="utf-8",
        )
        probe = subprocess.run(
            (
                str(arguments.lal_probe),
                "-P",
                str(copied_project),
                f"--target={arguments.target}",
                f"--RTS={arguments.runtime}",
                str(aliased_source),
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.pathsep.join(map(str, arguments.path))},
            timeout=120,
        )
        if probe.returncode == 0 or b"aliased array components" not in probe.stderr:
            raise AssertionError("direct LAL probe admitted aliased array components")

        fake = copied / "gprbuild"
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o755)
        fake_request = request(arguments, project, source)
        try:
            extract_checked(
                ExtractionRequest(
                    project=fake_request.project,
                    source=fake_request.source,
                    unit_name=fake_request.unit_name,
                    gprbuild=fake,
                    gnatls=fake_request.gnatls,
                    lal_probe=fake_request.lal_probe,
                    target=fake_request.target,
                    runtime=fake_request.runtime,
                    environment_path=(copied, *fake_request.environment_path),
                )
            )
        except ExtractionError:
            pass
        else:
            raise AssertionError("unapproved compiler executable was accepted")

    print(
        "extractor integration passed: "
        f"{first.semantic_fingerprint} ({len(first.document['context']['effective_project']['runtime_sources'])} runtime sources)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

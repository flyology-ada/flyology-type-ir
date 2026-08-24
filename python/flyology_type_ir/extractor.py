"""Process-owned GNAT legality and Libadalang extraction transaction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from ._bootstrap import checker_module

checker = checker_module()

FEATURES = sorted(checker.KNOWN_FEATURES)
EXPECTED_TYPES = {
    "production_shapes.color": "enumeration",
    "production_shapes.packet": "record",
    "production_shapes.palette": "array",
    "production_shapes.position": "enumeration",
}
EXPECTED_LITERALS = {
    "production_shapes.color": ["Red", "Green", "Blue"],
    "production_shapes.position": ["First", "Second", "Third"],
}
EXPECTED_ARRAYS = {
    "production_shapes.palette": (
        "production_shapes.position",
        "production_shapes.color",
    )
}
EXPECTED_COMPONENTS = {
    "production_shapes.packet": [
        ("Shade", "production_shapes.color"),
        ("Samples", "production_shapes.palette"),
    ]
}
SCENARIO = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
EXPECTED_PROJECT_SHA256 = "6211766b727d1d6a8bd39908853325cc61eb6fd9df0c286f86ec4095f63fee1f"
EXPECTED_SOURCE_SHA256 = "4fae657ea15a994ae641a87cdb118d73fd311d49bb4ba80c850cee81d45bc338"
EXPECTED_APPROVAL_SHA256 = "73756b3787a48cbee4aa67797e92fcf2faaca5f7b04b5413cd9c003a8df43b4a"
EXPECTED_CONFIG_SHA256 = "cb432c7b041f0647b257f31b73440d78bad1ef90016dfe8933c216b013cb8808"
EXPECTED_CHECKER_SHA256 = "fc3fab995022625e2db82b83797a8fbeb6b33ae7154f043d2a4b6b71f227c17f"
EXPECTED_SCHEMA_SHA256 = "1318d40affd3a7316f79ea3ec61eada70265942bfa41fb2b6ea0f8357348bf49"
EXPECTED_BOUNDARY = {
    "python/flyology_type_ir/__init__.py": "6a318cbdee3a948a5e97eaa9a9a7a8b594ec605a346317238ba344da8b7e7a92",
    "python/flyology_type_ir/_bootstrap.py": "82ca8d3a243373d60b761a05c29b135594c73c91f7a504a0e4a438e33eb4be07",
    "python/flyology_type_ir/attestation.py": "c9ec0c188fe3449360f152793d8be64a3b978ccdae0cc6d0b5e3d9f64f9f96ff",
    "python/flyology_type_ir/index.py": "267021bbdaeca80e36e3836d1b6dd598ed5f040ceea1f70fb47350033b5bfd89",
    "python/flyology_type_ir/v1.py": "7f4a49952446f0a3b1f9ad7dccf7a00ab48987ea7cb9b49fd39d1564d3fd9ef2",
    "tools/extractor/alire.toml": "07b040c62334c8a0ae140d06e27c59d17a4b2f8129ec2d0303669d5d51c504af",
    "tools/extractor/alire/alire.lock": "b31c39f6b908cbd7b4b9b17e6e02a10046d95f69fa54b299467a71e689c067c9",
    "tools/extractor/flyology_type_ir_extractor.gpr": "ec422e3e0d67b8c18ebd3bcb9408efa55605ab95198456f5d1e100b60eb9c1fe",
    "tools/extractor/src/flyology_type_ir_lal_probe.adb": "e82e00906d1fe61ef776001fc822bc248e62f6c7b25b6748c6dee4b79895a277",
}
APPROVED_KEYS = {
    "format",
    "gmp_path",
    "gmp_sha256",
    "gnat_tree_sha256",
    "gnat_version",
    "gprbuild_sha256",
    "gprbuild_tree_sha256",
    "gnatls_sha256",
    "libadalang_version",
    "probe_sha256",
    "target",
}
MAX_COMMAND_OUTPUT = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 120
Tree_Entry = tuple[str, str, str, str, str]
Tree_Manifest = tuple[Tree_Entry, ...]
Runtime_Closure = tuple[Tree_Manifest, Tree_Manifest]


class ExtractionError(RuntimeError):
    """The transaction could not prove an exact supported extraction."""


@dataclass(frozen=True)
class ExtractionRequest:
    project: Path
    source: Path
    unit_name: str
    gprbuild: Path
    gnatls: Path
    lal_probe: Path
    target: str
    runtime: Path
    scenario: tuple[tuple[str, str], ...] = ()
    environment_path: tuple[Path, ...] = ()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            checker.thaw(value),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        .encode("utf-8")
        + b"\n"
    )


def source_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    if not (root / "tools/extractor/approved-toolchain-v1.json").is_file():
        raise ExtractionError("owned extraction requires a Type IR source checkout")
    return root


def tree_manifest(root: Path) -> Tree_Manifest:
    """Bind logical names, entry kinds, link text, and final file content."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ExtractionError("tool/runtime tree root must be a directory")
    rows: list[Tree_Entry] = [
        (
            ".",
            "directory",
            format(stat.S_IMODE(root.stat().st_mode), "04o"),
            "",
            "",
        )
    ]
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        mode = format(stat.S_IMODE(path.lstat().st_mode), "04o")
        if path.is_symlink():
            target_text = os.readlink(path)
            target = path.resolve(strict=True)
            try:
                target.relative_to(root)
            except ValueError as error:
                raise ExtractionError(
                    f"tool/runtime symlink escapes its reviewed root: {relative}"
                ) from error
            if not target.is_file():
                raise ExtractionError(
                    f"tool/runtime symlink does not resolve to a file: {relative}"
                )
            rows.append((relative, "symlink", mode, target_text, file_digest(target)))
        elif path.is_file():
            rows.append((relative, "file", mode, "", file_digest(path)))
        elif path.is_dir():
            rows.append((relative, "directory", mode, "", ""))
        else:
            raise ExtractionError(f"unsupported tool/runtime entry: {relative}")
    return tuple(sorted(rows))


def manifest_paths(root: Path, manifest: Tree_Manifest) -> tuple[Path, ...]:
    return tuple(
        root / relative
        for relative, kind, _, _, _ in manifest
        if kind in {"file", "symlink"}
    )


def tree_digest(manifest: Tree_Manifest) -> str:
    rows = [
        {
            "content_sha256": digest,
            "kind": kind,
            "mode": mode,
            "path": path,
            "target": target,
        }
        for path, kind, mode, target, digest in manifest
    ]
    return sha256_bytes(canonical_bytes(rows))


def path_identity(path: Path) -> tuple[tuple[str, str, str], ...]:
    """Capture every symlink in an absolute path plus final file identity."""
    if not path.is_absolute():
        raise ExtractionError("native dependency path must be absolute")
    current = Path(path.anchor)
    rows: list[tuple[str, str, str]] = []
    for part in path.parts[1:]:
        current /= part
        try:
            mode = format(stat.S_IMODE(current.lstat().st_mode), "04o")
        except OSError as error:
            raise ExtractionError(f"native dependency path is unavailable: {current}") from error
        if current.is_symlink():
            rows.append((str(current), mode, os.readlink(current)))
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ExtractionError("native dependency does not resolve to a file")
    rows.append((str(resolved), format(stat.S_IMODE(resolved.stat().st_mode), "04o"), file_digest(resolved)))
    return tuple(rows)


def approved_toolchain(root: Path) -> dict[str, str]:
    path = root / "tools/extractor/approved-toolchain-v1.json"
    try:
        raw = path.read_bytes()
        if sha256_bytes(raw) != EXPECTED_APPROVAL_SHA256:
            raise ExtractionError("approved toolchain lock bytes are not reviewed")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ExtractionError(f"cannot read the approved toolchain lock: {error}") from error
    if not isinstance(value, dict) or set(value) != APPROVED_KEYS:
        raise ExtractionError("approved toolchain lock has unknown or missing keys")
    if any(not isinstance(item, str) or not item for item in value.values()):
        raise ExtractionError("approved toolchain lock values must be nonempty strings")
    if value["format"] != "flyology-type-ir-approved-toolchain":
        raise ExtractionError("approved toolchain lock format is unsupported")
    return value


def resolve_tool(name: str, path_entries: tuple[Path, ...]) -> Path:
    resolved = shutil.which(name, path=os.pathsep.join(map(str, path_entries)))
    if resolved is None:
        raise ExtractionError(f"sanitized PATH does not resolve {name}")
    return Path(resolved).resolve(strict=True)


def known_boolean(value: bool) -> dict[str, object]:
    return {
        "detail": "",
        "status": "known",
        "value": {"kind": "boolean", "value": value},
    }


def known_integer(value: int) -> dict[str, object]:
    return {
        "detail": "",
        "status": "known",
        "value": {"kind": "decimal_integer", "value": str(value)},
    }


def type_ref(canonical_name: str) -> dict[str, object]:
    return {
        "constraint": {"kind": "none"},
        "declaration_id": f"decl:{canonical_name}#public",
    }


def risk_facts(*, definite: bool) -> dict[str, object]:
    result = {
        name: known_boolean(False)
        for name in (
            "abstract",
            "class_wide",
            "contains_access",
            "contains_controlled",
            "controlled",
            "limited",
            "protected",
            "tagged",
            "task",
        )
    }
    result["definite"] = known_boolean(definite)
    return result


def scalar_range(high: int) -> dict[str, object]:
    return {
        "high": {"kind": "integer_literal", "syntax": str(high), "value": str(high)},
        "kind": "scalar_range",
        "low": {"kind": "integer_literal", "syntax": "0", "value": "0"},
        "predicate": known_boolean(False),
        "provenance": "inherited_base",
        "static_high": known_integer(high),
        "static_low": known_integer(0),
        "staticness": known_boolean(True),
    }


def resolve_request(request: ExtractionRequest) -> ExtractionRequest:
    root = source_root()
    paths = {
        "project": request.project,
        "source": request.source,
        "gprbuild": request.gprbuild,
        "gnatls": request.gnatls,
        "lal_probe": request.lal_probe,
        "runtime": request.runtime,
    }
    resolved: dict[str, Path] = {}
    for name, path in paths.items():
        candidate = path.expanduser().resolve(strict=True)
        if name == "runtime":
            if not candidate.is_dir():
                raise ExtractionError("runtime must be an existing absolute directory")
        elif not candidate.is_file():
            raise ExtractionError(f"{name} must be an existing absolute file")
        resolved[name] = candidate
    if not request.target or any(character.isspace() for character in request.target):
        raise ExtractionError("target must be a nonempty token")
    if request.unit_name != "Production_Shapes":
        raise ExtractionError("the v1 extraction slice admits only Production_Shapes")
    project_selected_source = (
        resolved["project"].parent / "src/production_shapes.ads"
    ).resolve(strict=True)
    if resolved["source"] != project_selected_source:
        raise ExtractionError("source must be the exact unit selected by the root project")
    expected_project = (root / "fixtures/extraction/production_shapes.gpr").resolve()
    expected_source = (root / "fixtures/extraction/src/production_shapes.ads").resolve()
    expected_probe = (root / "tools/extractor/bin/flyology_type_ir_lal_probe").resolve()
    if resolved["project"] != expected_project or resolved["source"] != expected_source:
        raise ExtractionError("the v1 extractor admits only the repository-owned fixture unit")
    if resolved["lal_probe"] != expected_probe:
        raise ExtractionError("LAL probe must be the repository-owned reviewed executable")
    scenario = tuple(sorted(request.scenario))
    if len({name for name, _ in scenario}) != len(scenario):
        raise ExtractionError("scenario variable names must be unique")
    if any(SCENARIO.fullmatch(name) is None for name, _ in scenario):
        raise ExtractionError("scenario variable name is invalid")
    if any("\0" in value for _, value in scenario):
        raise ExtractionError("scenario variable value contains NUL")
    if scenario:
        raise ExtractionError("the v1 fixture project admits no scenario variables")
    environment_path = tuple(
        path.expanduser().resolve(strict=True) for path in request.environment_path
    )
    if any(not path.is_dir() for path in environment_path):
        raise ExtractionError("every environment PATH entry must be a directory")
    if not environment_path:
        raise ExtractionError("the sanitized environment PATH must not be empty")
    expected_path = (resolved["gprbuild"].parent, resolved["gnatls"].parent)
    if environment_path != expected_path:
        raise ExtractionError("sanitized PATH differs from the exact reviewed tuple")
    if resolve_tool("gprbuild", environment_path) != resolved["gprbuild"]:
        raise ExtractionError("gprbuild differs from sanitized PATH resolution")
    if resolve_tool("gnatls", environment_path) != resolved["gnatls"]:
        raise ExtractionError("gnatls differs from sanitized PATH resolution")
    if resolve_tool("gcc", environment_path) != resolved["gnatls"].parent / "gcc":
        raise ExtractionError("Ada compiler child differs from the approved GNAT tree")
    return ExtractionRequest(
        project=resolved["project"],
        source=resolved["source"],
        unit_name=request.unit_name,
        gprbuild=resolved["gprbuild"],
        gnatls=resolved["gnatls"],
        lal_probe=resolved["lal_probe"],
        target=request.target,
        runtime=resolved["runtime"],
        scenario=scenario,
        environment_path=environment_path,
    )


def runtime_closure(runtime: Path) -> Runtime_Closure:
    include = runtime / "adainclude"
    library = runtime / "adalib"
    if not include.is_dir() or not library.is_dir():
        raise ExtractionError("runtime must contain adainclude and adalib")
    return tree_manifest(include), tree_manifest(library)


def runtime_sources(
    runtime: Path,
    closure: Runtime_Closure | None = None,
) -> tuple[Path, ...]:
    include_manifest, library_manifest = closure or runtime_closure(runtime)
    result = tuple(
        sorted(
            (
                *manifest_paths(runtime / "adainclude", include_manifest),
                *manifest_paths(runtime / "adalib", library_manifest),
            ),
            key=str,
        )
    )
    if not result:
        raise ExtractionError("runtime contains no Ada sources")
    return result


def snapshot(paths: tuple[Path, ...]) -> dict[Path, str]:
    return {path: file_digest(path) for path in paths}


def assert_unchanged(
    request: ExtractionRequest,
    runtime_manifest: Runtime_Closure,
    gprbuild_manifest: Tree_Manifest,
    gnat_manifest: Tree_Manifest,
    native_identity: tuple[tuple[str, str, str], ...],
    native_path: Path,
    input_paths: tuple[Path, ...],
    expected: dict[Path, str],
    stage: str,
) -> None:
    if runtime_closure(request.runtime) != runtime_manifest:
        raise ExtractionError(f"runtime membership changed during {stage}")
    if tree_manifest(request.gprbuild.parent.parent) != gprbuild_manifest:
        raise ExtractionError(f"gprbuild toolchain membership changed during {stage}")
    if tree_manifest(request.gnatls.parent.parent) != gnat_manifest:
        raise ExtractionError(f"GNAT toolchain membership changed during {stage}")
    if path_identity(native_path) != native_identity:
        raise ExtractionError(f"native dependency path changed during {stage}")
    if snapshot(input_paths) != expected:
        raise ExtractionError(f"project/runtime/tool inputs changed during {stage}")


def run_checked(argv: list[str], *, cwd: Path, environment: dict[str, str]) -> bytes:
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise ExtractionError(f"cannot execute {argv[0]}: {error}") from error

    def terminate() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    sizes = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate()
                raise ExtractionError(f"command timed out: {argv[0]}")
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                label = key.data
                sizes[label] += len(chunk)
                if sizes[label] > MAX_COMMAND_OUTPUT:
                    terminate()
                    raise ExtractionError(
                        "command output exceeded the one-MiB audit bound"
                    )
                chunks[label].append(chunk)
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        terminate()
        raise ExtractionError(f"command timed out: {argv[0]}") from error
    finally:
        selector.close()
    stdout = b"".join(chunks["stdout"])
    stderr = b"".join(chunks["stderr"])
    if returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        raise ExtractionError(f"command failed ({returncode}): {detail}")
    return stdout


def parse_probe(raw: bytes, expected_source: Path) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ExtractionError("LAL probe output is not UTF-8") from error
    if not text.endswith("\n") or "\r" in text:
        raise ExtractionError("LAL probe output is not canonical line evidence")
    types: dict[str, dict[str, object]] = {}
    literals: dict[str, list[tuple[int, str]]] = {}
    arrays: dict[str, tuple[str, str]] = {}
    components: dict[str, list[tuple[int, str, str]]] = {}
    saw_probe = False
    for line in text[:-1].split("\n"):
        fields = line.split("\t")
        kind = fields[0]
        if kind == "PROBE" and len(fields) == 3 and not saw_probe:
            if fields[1] != "1" or Path(fields[2]).resolve() != expected_source:
                raise ExtractionError("LAL probe identity/source mismatch")
            saw_probe = True
        elif kind == "TYPE" and len(fields) == 6:
            owner, display, shape, line_number, column = fields[1:]
            if owner in types:
                raise ExtractionError("duplicate LAL type evidence")
            types[owner] = {
                "display": display,
                "kind": shape,
                "line": int(line_number),
                "column": int(column),
            }
        elif kind == "LITERAL" and len(fields) == 4:
            literals.setdefault(fields[1], []).append((int(fields[2]), fields[3]))
        elif kind == "ARRAY" and len(fields) == 4:
            if fields[1] in arrays:
                raise ExtractionError("duplicate LAL array evidence")
            arrays[fields[1]] = (fields[2], fields[3])
        elif kind == "COMPONENT" and len(fields) == 5:
            components.setdefault(fields[1], []).append(
                (int(fields[2]), fields[3], fields[4])
            )
        else:
            raise ExtractionError("unknown or malformed LAL evidence")
    if not saw_probe:
        raise ExtractionError("LAL probe header is absent")
    if {name: value["kind"] for name, value in types.items()} != EXPECTED_TYPES:
        raise ExtractionError("declaration set is outside the fixture-proven v1 slice")
    if arrays != EXPECTED_ARRAYS:
        raise ExtractionError("resolved array edges are outside the v1 slice")
    actual_literals = {
        owner: [name for _, name in sorted(items)] for owner, items in literals.items()
    }
    if actual_literals != EXPECTED_LITERALS:
        raise ExtractionError("enumeration literals are outside the v1 slice")
    actual_components = {
        owner: [(name, target) for _, name, target in sorted(items)]
        for owner, items in components.items()
    }
    if actual_components != EXPECTED_COMPONENTS:
        raise ExtractionError("record components are outside the v1 slice")
    return {"types": types, "literals": literals, "arrays": arrays, "components": components}


def make_document(
    request: ExtractionRequest,
    evidence: dict[str, object],
    runtime_files: tuple[Path, ...],
    compiler_identity: str,
    gnat_version: str,
    libadalang_version: str,
    environment: dict[str, str],
    input_digests: dict[Path, str],
) -> dict[str, object]:
    configuration = source_root() / "fixtures/extraction/no_config.adc"
    source_digest = input_digests[request.source]
    types = evidence["types"]
    declarations: list[dict[str, object]] = []
    enum_literals: list[dict[str, object]] = []
    components: list[dict[str, object]] = []
    source_order = {
        owner: index
        for index, owner in enumerate(
            sorted(types, key=lambda name: (types[name]["line"], types[name]["column"]))
        )
    }
    for owner, item in types.items():
        kind = item["kind"]
        if kind == "enumeration":
            literal_items = sorted(evidence["literals"][owner])
            literal_ids = [
                f"decl:{owner}.{name.lower()}#public" for _, name in literal_items
            ]
            shape = {
                "kind": "enumeration",
                "literal_ids": literal_ids,
                "predicate": known_boolean(False),
                "range": scalar_range(len(literal_items) - 1),
            }
            for position, name in literal_items:
                enum_literals.append(
                    {
                        "canonical_name": name.lower(),
                        "declaration_order": position,
                        "name": name,
                        "owner_id": f"decl:{owner}#public",
                        "position": str(position),
                        "stable_id": f"decl:{owner}.{name.lower()}#public",
                    }
                )
        elif kind == "array":
            index_name, component_name = evidence["arrays"][owner]
            shape = {
                "component_type": type_ref(component_name),
                "constrained": known_boolean(True),
                "dimensions": [
                    {
                        "constraint": scalar_range(
                            len(evidence["literals"][index_name]) - 1
                        ),
                        "index_subtype": type_ref(index_name),
                        "position": 1,
                    }
                ],
                "kind": "array",
                "rank": 1,
            }
        else:
            shape = {"constraint": {"kind": "none"}, "kind": "record"}
            for position, name, target in sorted(evidence["components"][owner]):
                components.append(
                    {
                        "aliased": known_boolean(False),
                        "canonical_name": name.lower(),
                        "constant": known_boolean(False),
                        "declaration_order": position,
                        "default": {"present": False},
                        "name": name,
                        "owner_id": f"decl:{owner}#public",
                        "stable_id": f"decl:{owner}.{name.lower()}#public",
                        "type": type_ref(target),
                        "variant_path": [],
                    }
                )
        declarations.append(
            {
                "canonical_name": owner,
                "declaration_form": "type",
                "declaration_order": source_order[owner],
                "display_name": item["display"],
                "facts": risk_facts(definite=True),
                "location": {
                    "column": item["column"],
                    "file": str(request.source),
                    "line": item["line"],
                    "unit_name": request.unit_name,
                },
                "references": [],
                "related_view_ids": [],
                "shape": shape,
                "stable_id": f"decl:{owner}#public",
                "view": "public",
                "view_access": {
                    "consumer_can_name_components": known_boolean(kind == "record"),
                    "representation_available": known_boolean(True),
                },
            }
        )

    command = {
        "argv": [
            str(request.gprbuild),
            "-P",
            str(request.project),
            "-c",
            "-f",
            "-gnatc",
            f"-gnatec={configuration}",
            f"--target={request.target}",
            f"--RTS={request.runtime}",
            *[f"-X{name}={value}" for name, value in request.scenario],
            str(request.source),
        ],
        "environment": [
            {"name": name, "value": value} for name, value in sorted(environment.items())
        ],
        "tool_identity": compiler_identity,
        "working_directory": str(request.project.parent),
    }
    effective_project = {
        "algorithm": "sha256",
        "closure_digest": "0" * 64,
        "compiler_switches": ["-c", "-f", "-gnatc", f"-gnatec={configuration}"],
        "configuration_pragmas": [
            {
                "content_digest": input_digests[configuration],
                "logical_name": str(configuration),
            }
        ],
        "project_files": [
            {"content_digest": input_digests[request.project], "logical_name": str(request.project)}
        ],
        "runtime_sources": [
            {"content_digest": input_digests[path], "logical_name": str(path)}
            for path in runtime_files
        ],
        "selected_units": [
            {
                "content_digest": source_digest,
                "logical_name": str(request.source),
                "source_kind": "spec",
                "unit_name": request.unit_name,
            }
        ],
    }
    runtime_projection = canonical_bytes(effective_project["runtime_sources"])
    document = {
        "annotations": [],
        "components": sorted(components, key=lambda item: item["stable_id"]),
        "context": {
            "accessibility_context": {
                "consumer_unit": "flyology.generated",
                "derivation_unit": "production_shapes",
                "region": "public_spec",
            },
            "canonical_gpr_path": str(request.project),
            "compiler_identity": compiler_identity,
            "compiler_path": str(request.gprbuild),
            "context_kind": "extraction",
            "effective_project": effective_project,
            "extractor_version": (
                "flyology-type-ir-python-0.1.0-dev;"
                f"module-sha256={input_digests[Path(__file__).resolve()]};"
                f"checker-sha256={input_digests[source_root() / 'scripts/check_fixtures.py']};"
                f"schema-sha256={input_digests[source_root() / 'schema/type-ir-v1.schema.json']};"
                f"probe-sha256={input_digests[request.lal_probe]}"
            ),
            "gnat_version": gnat_version,
            "legality_check": {
                "command": command,
                "command_fingerprint": sha256_bytes(canonical_bytes(command)),
                "succeeded": True,
            },
            "libadalang_version": libadalang_version,
            "project_closure": [request.unit_name],
            "project_name": request.project.stem,
            "requested_units": [request.unit_name],
            "runtime_identity": f"sha256:{sha256_bytes(runtime_projection)}",
            "scenario": [
                {"name": name, "value": value} for name, value in request.scenario
            ],
            "target": request.target,
        },
        "declarations": sorted(declarations, key=lambda item: item["stable_id"]),
        "discriminants": [],
        "entities": [],
        "enum_literals": sorted(enum_literals, key=lambda item: item["stable_id"]),
        "extensions": {},
        "generic_actuals": [],
        "ir_version": 1,
        "optional_features": [],
        "required_features": FEATURES,
        "variants": [],
    }
    effective_project["closure_digest"] = checker.effective_closure_digest(document)
    return document


def extract_checked(request: ExtractionRequest) -> checker.CheckedDocument:
    """Run one owned legality/LAL transaction and retain its checked bytes."""
    request = resolve_request(request)
    root = source_root()
    checker_path = root / "scripts/check_fixtures.py"
    schema_path = root / "schema/type-ir-v1.schema.json"
    if (
        Path(checker.__file__).resolve() != checker_path
        or getattr(checker, "__flyology_source_sha256__", None)
        != EXPECTED_CHECKER_SHA256
        or getattr(checker, "SCHEMA_SHA256", None) != EXPECTED_SCHEMA_SHA256
    ):
        raise ExtractionError("loaded checker/schema identity is outside the reviewed slice")
    approval = approved_toolchain(root)
    runtime_manifest = runtime_closure(request.runtime)
    runtime_files = runtime_sources(request.runtime, runtime_manifest)
    gprbuild_root = request.gprbuild.parent.parent
    gnat_root = request.gnatls.parent.parent
    gprbuild_manifest = tree_manifest(gprbuild_root)
    gnat_manifest = tree_manifest(gnat_root)
    gprbuild_files = manifest_paths(gprbuild_root, gprbuild_manifest)
    gnat_files = manifest_paths(gnat_root, gnat_manifest)
    path_value = os.pathsep.join(str(path) for path in request.environment_path)
    environment = {"PATH": path_value}
    configuration = root / "fixtures/extraction/no_config.adc"
    gmp_path = Path(approval["gmp_path"])
    native_identity = path_identity(gmp_path)
    gmp = gmp_path.resolve(strict=True)
    boundary_files = tuple(root / relative for relative in EXPECTED_BOUNDARY)
    input_paths = tuple(dict.fromkeys((
        request.project,
        request.source,
        configuration,
        request.gprbuild,
        request.gnatls,
        request.lal_probe,
        gmp,
        Path(__file__).resolve(),
        root / "tools/extractor/approved-toolchain-v1.json",
        checker_path,
        schema_path,
        *boundary_files,
        *runtime_files,
        *gprbuild_files,
        *gnat_files,
    )))
    before = snapshot(input_paths)
    if before[request.project] != EXPECTED_PROJECT_SHA256:
        raise ExtractionError("the root project is outside the exact fixture-proven slice")
    if before[request.source] != EXPECTED_SOURCE_SHA256:
        raise ExtractionError("the selected source is outside the exact fixture-proven slice")
    if before[configuration] != EXPECTED_CONFIG_SHA256:
        raise ExtractionError("the explicit GNAT configuration is outside the reviewed slice")
    if before[checker_path] != EXPECTED_CHECKER_SHA256:
        raise ExtractionError("strict checker bytes are outside the reviewed slice")
    if before[schema_path] != EXPECTED_SCHEMA_SHA256:
        raise ExtractionError("v1 schema bytes are outside the reviewed slice")
    for relative, expected in EXPECTED_BOUNDARY.items():
        if before[root / relative] != expected:
            raise ExtractionError(f"extractor boundary source drifted: {relative}")
    if request.target != approval["target"]:
        raise ExtractionError("target differs from the approved toolchain lock")
    if before[request.gprbuild] != approval["gprbuild_sha256"]:
        raise ExtractionError("gprbuild differs from the approved toolchain lock")
    if before[request.gnatls] != approval["gnatls_sha256"]:
        raise ExtractionError("gnatls differs from the approved toolchain lock")
    if before[request.lal_probe] != approval["probe_sha256"]:
        raise ExtractionError("LAL probe differs from the approved toolchain lock")
    if gmp not in input_paths or before[gmp] != approval["gmp_sha256"]:
        raise ExtractionError("probe GMP dependency differs from the approved lock")
    gprbuild_tree = tree_digest(gprbuild_manifest)
    gnat_tree = tree_digest(gnat_manifest)
    if gprbuild_tree != approval["gprbuild_tree_sha256"]:
        raise ExtractionError("gprbuild installation differs from the approved closure")
    if gnat_tree != approval["gnat_tree_sha256"]:
        raise ExtractionError("GNAT installation differs from the approved closure")
    if not request.runtime.is_relative_to(gnat_root):
        raise ExtractionError("runtime is outside the approved GNAT installation")
    gnat_version = run_checked(
        [str(request.gnatls), "--version"], cwd=request.project.parent, environment=environment
    ).decode("utf-8", "strict").splitlines()[0]
    if gnat_version != approval["gnat_version"]:
        raise ExtractionError("GNAT identity differs from the approved toolchain lock")
    assert_unchanged(
        request, runtime_manifest, gprbuild_manifest, gnat_manifest,
        native_identity, gmp_path, input_paths, before,
        "identity capture",
    )
    compiler_identity = (
        f"{gnat_version};gprbuild-sha256={before[request.gprbuild]};"
        f"gnatls-sha256={before[request.gnatls]};"
        f"gprbuild-tree-sha256={gprbuild_tree};gnat-tree-sha256={gnat_tree};"
        f"gmp-sha256={before[gmp]}"
    )
    scenario_args = [f"-X{name}={value}" for name, value in request.scenario]
    legality_argv = [
        str(request.gprbuild),
        "-P",
        str(request.project),
        "-c",
        "-f",
        "-gnatc",
        f"-gnatec={configuration}",
        f"--target={request.target}",
        f"--RTS={request.runtime}",
        *scenario_args,
        str(request.source),
    ]
    run_checked(legality_argv, cwd=request.project.parent, environment=environment)
    assert_unchanged(
        request, runtime_manifest, gprbuild_manifest, gnat_manifest,
        native_identity, gmp_path, input_paths, before,
        "GNAT legality",
    )
    probe_argv = [
        str(request.lal_probe),
        "-P",
        str(request.project),
        f"--target={request.target}",
        f"--RTS={request.runtime}",
        *scenario_args,
        str(request.source),
    ]
    probe_output = run_checked(probe_argv, cwd=request.project.parent, environment=environment)
    assert_unchanged(
        request, runtime_manifest, gprbuild_manifest, gnat_manifest,
        native_identity, gmp_path, input_paths, before,
        "LAL extraction",
    )
    evidence = parse_probe(probe_output, request.source)
    document = make_document(
        request,
        evidence,
        runtime_files,
        compiler_identity,
        gnat_version,
        approval["libadalang_version"],
        environment,
        before,
    )
    assert_unchanged(
        request, runtime_manifest, gprbuild_manifest, gnat_manifest,
        native_identity, gmp_path, input_paths, before,
        "model construction",
    )
    raw = canonical_bytes(document)
    checked = checker._checked_bytes(
        raw, "strict", extraction_authority=checker._EXTRACTION_AUTHORITY
    )
    assert_unchanged(
        request, runtime_manifest, gprbuild_manifest, gnat_manifest,
        native_identity, gmp_path, input_paths, before,
        "strict validation",
    )
    return checked


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--gprbuild", required=True, type=Path)
    parser.add_argument("--gnatls", required=True, type=Path)
    parser.add_argument("--lal-probe", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--path", action="append", default=[], type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    scenario = []
    for item in arguments.scenario:
        if "=" not in item:
            parser.error("--scenario must be NAME=VALUE")
        scenario.append(tuple(item.split("=", 1)))
    try:
        checked = extract_checked(
            ExtractionRequest(
                project=arguments.project,
                source=arguments.source,
                unit_name=arguments.unit,
                gprbuild=arguments.gprbuild,
                gnatls=arguments.gnatls,
                lal_probe=arguments.lal_probe,
                target=arguments.target,
                runtime=arguments.runtime,
                scenario=tuple(scenario),
                environment_path=tuple(arguments.path),
            )
        )
    except (ExtractionError, checker.Rejected, OSError, ValueError) as error:
        print(f"extraction rejected: {error}", file=sys.stderr)
        return 1
    output = canonical_bytes(checked.document)
    if arguments.output is None:
        sys.stdout.buffer.write(output)
    else:
        requested = arguments.output.expanduser()
        if requested.is_symlink():
            print("extraction rejected: output path must not be a symlink", file=sys.stderr)
            return 1
        requested.parent.mkdir(parents=True, exist_ok=True)
        destination = requested.parent.resolve(strict=True) / requested.name
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(output)
                temporary.flush()
                os.fsync(temporary.fileno())
            temporary_path.replace(destination)
            directory = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

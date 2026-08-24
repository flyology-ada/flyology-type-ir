"""Exact-byte attestation for a reviewed Type IR checkout.

This module knows nothing about consumer overlays or lowering. A consumer owns
its lock format and passes only the closed Type IR dependency tuple below.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Mapping

from .index import CheckedIndex, index_checked

HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY = "https://github.com/flyology-ada/flyology-type-ir"
CHECKER_PATH = "scripts/check_fixtures.py"
SCHEMA_PATH = "schema/type-ir-v1.schema.json"
REPOSITORY_REMOTES = {
    REPOSITORY,
    "git@github.com:flyology-ada/flyology-type-ir.git",
    f"{REPOSITORY}.git",
}
REQUIRED_FEATURES = (
    "ada-type-ir/core",
    "ada-type-ir/decimal-strings",
    "ada-type-ir/exact-variants",
    "ada-type-ir/graph-refs",
    "ada-type-ir/typed-shapes",
)


class AttestationError(ValueError):
    """A reviewed dependency tuple or checkout does not match exact bytes."""


@dataclass(frozen=True)
class LockedFile:
    path: str
    sha256: str


@dataclass(frozen=True)
class ReviewedDependency:
    repository: str
    commit: str
    ir_version: int
    required_features: tuple[str, ...]
    checker: LockedFile
    schema: LockedFile
    resources: tuple[LockedFile, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReviewedDependency:
        if not isinstance(value, Mapping):
            raise AttestationError("reviewed dependency must be an object")
        expected = {
            "checker",
            "commit",
            "ir_version",
            "repository",
            "required_features",
            "resources",
            "schema",
        }
        if set(value) != expected:
            raise AttestationError("reviewed dependency has unknown or missing keys")
        if value["repository"] != REPOSITORY:
            raise AttestationError("reviewed dependency repository is unsupported")
        if not isinstance(value["commit"], str) or HEX_40.fullmatch(value["commit"]) is None:
            raise AttestationError("reviewed dependency commit is not lowercase SHA-1")
        if type(value["ir_version"]) is not int or value["ir_version"] != 1:
            raise AttestationError("reviewed dependency IR version must be integer 1")
        features = value["required_features"]
        if (
            not isinstance(features, (list, tuple))
            or any(not isinstance(item, str) for item in features)
            or tuple(features) != REQUIRED_FEATURES
        ):
            raise AttestationError("reviewed dependency feature set differs from v1")
        checker = _locked_file(value["checker"], "checker")
        schema = _locked_file(value["schema"], "schema")
        if checker.path != CHECKER_PATH or schema.path != SCHEMA_PATH:
            raise AttestationError("checker or schema path differs from the v1 boundary")
        resources = tuple(
            _locked_file(item, f"resources[{index}]")
            for index, item in enumerate(value["resources"])
        )
        paths = (checker.path, schema.path, *(item.path for item in resources))
        if len(set(paths)) != len(paths):
            raise AttestationError("reviewed dependency paths must be distinct")
        return cls(
            repository=value["repository"],
            commit=value["commit"],
            ir_version=value["ir_version"],
            required_features=tuple(features),
            checker=checker,
            schema=schema,
            resources=resources,
        )


def _locked_file(value: Any, label: str) -> LockedFile:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
        raise AttestationError(f"{label} lock has unknown or missing keys")
    path = value["path"]
    if not isinstance(path, str) or not path:
        raise AttestationError(f"{label} path must be nonempty")
    normalized = PurePosixPath(path)
    if (
        not normalized.parts
        or normalized.is_absolute()
        or ".." in normalized.parts
        or normalized.as_posix() != path
    ):
        raise AttestationError(f"{label} path must be normalized and repository-relative")
    digest = value["sha256"]
    if not isinstance(digest, str) or HEX_64.fullmatch(digest) is None:
        raise AttestationError(f"{label} digest must be lowercase SHA-256")
    return LockedFile(path, digest)


def _git(root: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AttestationError(f"cannot inspect reviewed checkout: {error}") from error
    if len(result.stdout) > 2 * 1024 * 1024 or len(result.stderr) > 2 * 1024 * 1024:
        raise AttestationError("git checkout inspection exceeded the output bound")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise AttestationError(f"cannot inspect reviewed checkout: {detail}")
    return result.stdout


def _attested_bytes(
    root: Path, commit: str, locked: LockedFile, label: str
) -> bytes:
    try:
        resolved_root = root.resolve(strict=True)
        candidate = (resolved_root / locked.path).resolve(strict=True)
    except OSError as error:
        raise AttestationError(f"{label} path is unavailable: {error}") from error
    try:
        candidate.relative_to(resolved_root)
    except ValueError as error:
        raise AttestationError(f"{label} path escapes the reviewed checkout") from error
    try:
        content = candidate.read_bytes()
    except OSError as error:
        raise AttestationError(f"{label} cannot be read: {error}") from error
    actual = hashlib.sha256(content).hexdigest()
    if actual != locked.sha256:
        raise AttestationError(
            f"{label} digest mismatch: expected {locked.sha256}, found {actual}"
        )
    tree_entry = _git(root, "ls-tree", commit, "--", locked.path).decode(
        "utf-8", "strict"
    ).strip()
    if not tree_entry.startswith("100644 blob "):
        raise AttestationError(f"{label} is absent, executable, or a symlink in the commit")
    committed = _git(root, "show", f"{commit}:{locked.path}")
    if committed != content:
        raise AttestationError(f"{label} bytes differ from the locked commit")
    return content


def _verify_checkout(root: Path, expected_commit: str) -> None:
    if _git(root, "rev-parse", "HEAD").decode("ascii", "strict").strip() != expected_commit:
        raise AttestationError("reviewed checkout HEAD differs from the locked commit")
    remote = _git(root, "remote", "get-url", "origin").decode("utf-8", "strict").strip()
    if remote not in REPOSITORY_REMOTES:
        raise AttestationError("reviewed checkout origin differs from the supported repository")


class AttestedChecker:
    """Scoped exact-byte checker import; call ``load_checked`` only inside it."""

    def __init__(self, root: Path, dependency: ReviewedDependency):
        self._source_root = root.resolve(strict=True)
        self._dependency = dependency
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._module: ModuleType | None = None

    def __enter__(self) -> AttestedChecker:
        if self._temporary is not None or self._module is not None:
            raise AttestationError("AttestedChecker context is already active")
        _verify_checkout(self._source_root, self._dependency.commit)
        checker_bytes = _attested_bytes(
            self._source_root,
            self._dependency.commit,
            self._dependency.checker,
            "checker",
        )
        schema_bytes = _attested_bytes(
            self._source_root,
            self._dependency.commit,
            self._dependency.schema,
            "schema",
        )
        temporary = tempfile.TemporaryDirectory(prefix="flyology-type-ir-attested-")
        try:
            isolated = Path(temporary.name)
            checker_path = isolated / self._dependency.checker.path
            schema_path = isolated / self._dependency.schema.path
            checker_path.parent.mkdir(parents=True)
            schema_path.parent.mkdir(parents=True)
            checker_path.write_bytes(checker_bytes)
            schema_path.write_bytes(schema_bytes)
            for index, resource in enumerate(self._dependency.resources):
                content = _attested_bytes(
                    self._source_root,
                    self._dependency.commit,
                    resource,
                    f"resources[{index}]",
                )
                destination = isolated / resource.path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            name = f"flyology_type_ir_attested_{self._dependency.checker.sha256}"
            module = ModuleType(name)
            module.__file__ = str(checker_path)
            module.__package__ = ""
            previous = sys.modules.get(name)
            sys.modules[name] = module
            try:
                code = compile(checker_bytes, str(checker_path), "exec", dont_inherit=True)
                exec(code, module.__dict__)
            except Exception as error:
                raise AttestationError(
                    f"cannot import the attested checker: {error}"
                ) from error
            finally:
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous
            if not callable(getattr(module, "load_checked", None)):
                raise AttestationError("attested checker has no load_checked entry point")
        except BaseException:
            temporary.cleanup()
            raise
        self._temporary = temporary
        self._module = module
        return self

    def __exit__(self, *_: object) -> None:
        self._module = None
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    def load_checked(self, path: Path, profile: str) -> Any:
        if self._module is None:
            raise AttestationError("AttestedChecker is not inside its context")
        return self._module.load_checked(path, profile)

    def load_indexed(self, path: Path, profile: str) -> CheckedIndex:
        """Load once through the attested checker and freeze stable-ID indexes."""
        return index_checked(self.load_checked(path, profile))


__all__ = [
    "AttestationError",
    "AttestedChecker",
    "LockedFile",
    "REPOSITORY",
    "REQUIRED_FEATURES",
    "ReviewedDependency",
]

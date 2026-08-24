from __future__ import annotations

import hashlib
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "python"))

from flyology_type_ir import (  # noqa: E402
    AttestedChecker,
    ReviewedDependency,
    index_checked,
    load_checked,
)
from flyology_type_ir.attestation import AttestationError  # noqa: E402
from flyology_type_ir import attestation as attestation_module  # noqa: E402
from flyology_type_ir.v1 import Rejected  # noqa: E402


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SupportedApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="type-ir-reviewed-")
        self.reviewed_root = Path(self._temporary.name)
        for relative in (
            "scripts/check_fixtures.py",
            "schema/type-ir-v1.schema.json",
            "fixtures/ada/wire_shape.ads",
            "fixtures/fixtures.gpr",
        ):
            destination = self.reviewed_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        malicious = self.reviewed_root / "poisoned_checker.py"
        malicious.write_text(
            "def load_checked(path, profile):\n    return 'poisoned bytecode'\n",
            encoding="utf-8",
        )
        self.poisoned_pyc = (
            self.reviewed_root
            / f"scripts/__pycache__/check_fixtures.{sys.implementation.cache_tag}.pyc"
        )
        self.poisoned_pyc.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(
            str(malicious),
            cfile=str(self.poisoned_pyc),
            dfile=str(self.reviewed_root / "scripts/check_fixtures.py"),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        malicious.unlink()
        commands = (
            ("init", "-b", "main"),
            ("config", "user.email", "type-ir-test@example.invalid"),
            ("config", "user.name", "Type IR Test"),
            ("add", "."),
            ("commit", "-m", "test reviewed tuple"),
            ("remote", "add", "origin", "https://github.com/flyology-ada/flyology-type-ir"),
        )
        for arguments in commands:
            subprocess.run(
                ("git", "-C", str(self.reviewed_root), *arguments),
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        self.commit = subprocess.check_output(
            ("git", "-C", str(self.reviewed_root), "rev-parse", "HEAD"),
            text=True,
        ).strip()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def dependency(
        self,
        checker_digest: str | None = None,
        commit: str | None = None,
        include_poisoned_pyc: bool = False,
    ) -> ReviewedDependency:
        resources = [
            {
                "path": "fixtures/ada/wire_shape.ads",
                "sha256": digest(self.reviewed_root / "fixtures/ada/wire_shape.ads"),
            },
            {
                "path": "fixtures/fixtures.gpr",
                "sha256": digest(self.reviewed_root / "fixtures/fixtures.gpr"),
            },
        ]
        if include_poisoned_pyc:
            resources.append(
                {
                    "path": self.poisoned_pyc.relative_to(self.reviewed_root).as_posix(),
                    "sha256": digest(self.poisoned_pyc),
                }
            )
        return ReviewedDependency.from_mapping(
            {
                "checker": {
                    "path": "scripts/check_fixtures.py",
                    "sha256": checker_digest
                    or digest(self.reviewed_root / "scripts/check_fixtures.py"),
                },
                "commit": commit or self.commit,
                "ir_version": 1,
                "repository": "https://github.com/flyology-ada/flyology-type-ir",
                "required_features": [
                    "ada-type-ir/core",
                    "ada-type-ir/decimal-strings",
                    "ada-type-ir/exact-variants",
                    "ada-type-ir/graph-refs",
                    "ada-type-ir/typed-shapes",
                ],
                "resources": resources,
                "schema": {
                    "path": "schema/type-ir-v1.schema.json",
                    "sha256": digest(self.reviewed_root / "schema/type-ir-v1.schema.json"),
                },
            }
        )

    def test_same_read_load_and_immutable_index(self) -> None:
        checked = load_checked(ROOT / "fixtures/wire-record-shape.json", "fixture_shape")
        indexed = index_checked(checked)
        self.assertEqual(checked.profile, "fixture_shape")
        self.assertIn("decl:wire_shape.public_record#public", indexed.declarations)
        with self.assertRaises(TypeError):
            indexed.document["ir_version"] = 2
        with self.assertRaises(TypeError):
            indexed.declarations["decl:wire_shape.public_record#public"]["view"] = "full"
        with self.assertRaises(TypeError):
            checked.document["ir_version"] = 2
        with self.assertRaises((TypeError, AttributeError)):
            checked.document |= {"ir_version": 2}
        checked.document.__init__({"ir_version": 3})
        self.assertEqual(checked.document["ir_version"], 1)

    def test_attested_checker_is_scoped(self) -> None:
        checker = AttestedChecker(self.reviewed_root, self.dependency())
        with checker:
            indexed = checker.load_indexed(
                ROOT / "fixtures/wire-record-shape.json", "fixture_shape"
            )
        self.assertEqual(indexed.profile, "fixture_shape")
        with self.assertRaisesRegex(AttestationError, "not inside"):
            checker.load_checked(ROOT / "fixtures/wire-record-shape.json", "fixture_shape")

    def test_attestation_rejects_digest_drift(self) -> None:
        with self.assertRaisesRegex(AttestationError, "digest mismatch"):
            with AttestedChecker(self.reviewed_root, self.dependency("0" * 64)):
                self.fail("drifted checker entered its context")

    def test_attestation_rejects_bytes_not_in_commit(self) -> None:
        checker_path = self.reviewed_root / "scripts/check_fixtures.py"
        checker_path.write_bytes(checker_path.read_bytes() + b"\n# dirty\n")
        dependency = self.dependency(digest(checker_path))
        with self.assertRaisesRegex(AttestationError, "differ from the locked commit"):
            with AttestedChecker(self.reviewed_root, dependency):
                self.fail("dirty checker entered its context")

    def test_attestation_rejects_wrong_commit(self) -> None:
        with self.assertRaisesRegex(AttestationError, "HEAD differs"):
            with AttestedChecker(
                self.reviewed_root, self.dependency(commit="0" * 40)
            ):
                self.fail("wrong commit entered its context")

    def test_attested_checker_ignores_poisoned_bytecode(self) -> None:
        with AttestedChecker(
            self.reviewed_root, self.dependency(include_poisoned_pyc=True)
        ) as checker:
            checked = checker.load_checked(
                ROOT / "fixtures/wire-record-shape.json", "fixture_shape"
            )
        self.assertEqual(checked.profile, "fixture_shape")

    def test_attested_checker_cleans_up_on_base_exception(self) -> None:
        original_temporary = attestation_module.tempfile.TemporaryDirectory
        original_attested_bytes = attestation_module._attested_bytes
        instances = []

        class TrackingTemporary:
            def __init__(self, *arguments: object, **keywords: object):
                self.delegate = original_temporary(*arguments, **keywords)
                self.name = self.delegate.name
                self.cleaned = False
                instances.append(self)

            def cleanup(self) -> None:
                self.delegate.cleanup()
                self.cleaned = True

        calls = 0

        def interrupt_third_call(*arguments: object, **keywords: object) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise KeyboardInterrupt("test post-allocation interruption")
            return original_attested_bytes(*arguments, **keywords)

        with mock.patch.object(
            attestation_module.tempfile,
            "TemporaryDirectory",
            TrackingTemporary,
        ), mock.patch.object(
            attestation_module,
            "_attested_bytes",
            side_effect=interrupt_third_call,
        ):
            with self.assertRaises(KeyboardInterrupt):
                with AttestedChecker(self.reviewed_root, self.dependency()):
                    self.fail("interrupted attestation entered its context")
        self.assertEqual(len(instances), 1)
        self.assertTrue(instances[0].cleaned)

    def test_document_only_strict_cannot_claim_extraction_trust(self) -> None:
        with self.assertRaisesRegex(Rejected, "process-owned"):
            load_checked(ROOT / "fixtures/production-extraction.json", "strict")


if __name__ == "__main__":
    unittest.main()

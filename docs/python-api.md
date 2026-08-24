# Offline Python API v1

Install from an exact reviewed checkout:

```sh
/usr/bin/python3 -m pip install . --no-deps --no-build-isolation
```

The reviewed offline build prerequisites are `setuptools==58.0.4` and
`wheel==0.37.0`; they are exact in `pyproject.toml`. The package uses only the
Python standard library at runtime.

## Same-read document loading

```python
load_checked(path: pathlib.Path, profile: str) -> CheckedDocument
index_checked(checked: CheckedDocument) -> CheckedIndex
```

Profiles are `structural`, document-only `strict`, and test-only
`fixture_shape`. `CheckedDocument` contains `document`, `semantic_projection`,
`semantic_fingerprint`, `source_sha256`, and `profile`. The checked document is
recursively immutable. `CheckedIndex` exposes immutable stable-ID maps for declarations,
components, discriminants, entities, enum literals, generic actuals, and
variants.

Document-only `strict` never accepts `context_kind: extraction`; persisted JSON
cannot prove its own legality.

## Reviewed-checkout attestation

```python
dependency = ReviewedDependency.from_mapping({
    "repository": "https://github.com/flyology-ada/flyology-type-ir",
    "commit": "<40 lowercase hex>",
    "ir_version": 1,
    "required_features": [
        "ada-type-ir/core",
        "ada-type-ir/decimal-strings",
        "ada-type-ir/exact-variants",
        "ada-type-ir/graph-refs",
        "ada-type-ir/typed-shapes",
    ],
    "resources": [
        {"path": "fixtures/fixtures.gpr", "sha256": "<64 hex>"},
        {"path": "fixtures/ada/example.ads", "sha256": "<64 hex>"},
    ],
    "checker": {"path": "scripts/check_fixtures.py", "sha256": "<64 hex>"},
    "schema": {"path": "schema/type-ir-v1.schema.json", "sha256": "<64 hex>"},
})

with AttestedChecker(type_ir_root, dependency) as checker:
    checked = checker.load_checked(path, profile)
    # or: indexed = checker.load_indexed(path, profile)
```

The context manager verifies the checkout origin and `HEAD`, proves every
locked path is a regular blob with identical bytes in that exact commit, then
hashes checker, schema, and explicitly listed resource bytes before copying them
to an isolated temporary root, imports only that exact checker, and removes the
root explicitly at exit. Calling either load method outside the context is an
error. A consumer owns and validates its surrounding lock format; this tuple
contains no overlay or lowering policy.

## Process-owned extraction

```python
extract_checked(request: ExtractionRequest) -> CheckedDocument
```

Extraction is supported only from the reviewed Type IR source checkout, not
from the installed loader package. `ExtractionRequest` requires explicit project/source/unit, absolute
`gprbuild`/`gnatls`/LAL-probe/runtime paths, target, sorted scenario bindings,
and the exact ordered PATH tuple containing only the approved GPRbuild and
GNAT `bin` directories. V1 accepts only the exact content of
`fixtures/extraction/production_shapes.gpr` and its source fixture. The result
has profile `strict` only after forced same-invocation GNAT legality with an
explicit empty configuration, unchanged project/toolchain/runtime-source/ALI
and library manifests (including modes, directories, and symlink identity),
the approved LAL 26.0.0 probe and native GMP path chain, canonical emission, and
owned validation. Any failure returns no document.

The internal extraction-authority identity prevents documents and public API
callers from setting a trust Boolean. Python module privacy is not a sandbox:
malicious code already executing in the same interpreter or a process that can
replace reviewed files is outside this API's threat model. Consumers should run
extraction in a dedicated offline process.

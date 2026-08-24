# Flyology Ada Type IR

`flyology_type_ir` is a shared, offline semantic Ada Type IR for Flyology code
generators. It provides stable in-memory graph types, explicit semantic facts,
validation profiles, a versioned JSON contract, and a separate Libadalang
extractor boundary.

The serde and wire runtimes do **not** depend on this crate or Libadalang. JSON
is an offline interchange format and is not the Flyology wire protocol. The
core crate has no dependency on `flyology_serde`.

## Status

Version 1 establishes the stable model, validation, schema, canonical golden
fixtures, an Ada model interface, and an installable dependency-free Python
checked-loader. The first production extractor slice is enabled for the
dedicated public enum/array/record fixture; every unproven declaration shape
fails the complete transaction without emitting JSON.

## Layout

- `src/`: dependency-light stable IR and validation API
- `schema/type-ir-v1.schema.json`: strict serialized schema
- `fixtures/`: canonical positive and intentionally rejected examples
- `tools/extractor/`: separate, exactly pinned Libadalang tool crate
- `python/flyology_type_ir/`: installed loader, immutable indexes, exact-byte
  attestation, and process-owned extraction API
- `tests/`: nested AUnit crate pinned to the parent library
- `docs/`: architecture, IR, extraction, and canonical JSON contracts

## Build and test

```sh
alr build
cd tests
alr run
```

The fixture verifier additionally checks canonical bytes, schema shape, and
negative mutants:

```sh
python3 scripts/check_fixtures.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s python/tests -v
```

The same duplicate-key-aware canonical loader validates an arbitrary document:

```sh
python3 scripts/check_fixtures.py --structural path/to/document.json
python3 scripts/check_fixtures.py --strict path/to/extraction.json
python3 scripts/check_fixtures.py --fixture-shape fixtures/wire-record-shape.json --print-fingerprint
```

Build the separately pinned Libadalang extractor as an additional boundary
check. On Apple Silicon with Homebrew, expose GMP's library directory to the
linker (Linux package-manager installations normally need no override):

```sh
cd tools/extractor
LIBRARY_PATH=/opt/homebrew/lib alr build
DYLD_LIBRARY_PATH=/opt/homebrew/lib ./bin/flyology_type_ir_extract
```

The smoke command must exit 1 after stating that no IR was emitted.

The host-toolchain integration test is `scripts/test_extractor.py`. Pass it
absolute `gprbuild`, `gnatls`, probe, runtime, target, and sanitized PATH
entries. It runs two production-strict transactions, compares the complete
audit golden after replacing only the checkout/GPRbuild/GNAT host-root prefixes
with fixed placeholders, compares the semantic fingerprint, and proves unsupported source and
direct aliased-array probe cases produce no document.

Install the offline Python boundary from a reviewed checkout with exact local
`setuptools==58.0.4` and `wheel==0.37.0` using
`/usr/bin/python3 -m pip install . --no-deps --no-build-isolation`. The supported document API is
`flyology_type_ir.load_checked(path, profile)`; `index_checked` creates
immutable graph tables from that same retained model; the retained checked
document is itself recursively immutable. The result
also carries canonical semantic-projection bytes, semantic SHA-256, source
SHA-256, and the applied profile.

`fixture_shape` is explicitly test-only. A caller-written extraction document
cannot authenticate its own legality, so document-only `strict` rejects
extraction provenance. Production extraction uses
`flyology_type_ir.extractor.extract_checked(request)`, which owns GNAT
legality, reviewed tool/runtime closure snapshots, LAL traversal, canonical
emission, and owned strict validation in one invocation. Extraction is a
source-checkout command, not an installed loader entry point, and should run in
a dedicated offline process; module privacy is not a sandbox against hostile
code already executing in that interpreter.

Pinned consumers may share `ReviewedDependency` and scoped
`AttestedChecker.load_checked`/`load_indexed`. These validate only the Type IR
dependency tuple. Consumer lock envelopes, overlays, lowering, Ada naming,
compatibility policy, and generated artifacts stay in the consumer repository.

## Consumer rule

Run structural validation when reading/auditing an IR document. Run strict
consumer validation before generation. Structural validity permits explicit
Unknown/Unsupported facts; the versioned strict profile defines mandatory
paths and rejects missing or imprecise facts. Producers cannot downgrade a
mandatory path to optional. `Strict_Consumer` rejects synthetic provenance,
and bare loading rejects self-asserted extraction provenance. V1's generic
subset is limited to `type T is range <>` and
box-only formal packages (`with package P is new G (<>)`); every other formal
type/package contract is Unsupported and extraction must fail closed.

See [architecture](docs/architecture.md), [IR model](docs/ir-model.md),
[canonical JSON](docs/canonical-json.md), and the
[offline Python API](docs/python-api.md).

## Agent setup

This repository uses APM 0.28.0 to provision locked shared instructions and
skills for Codex and Claude. Before starting either client in a new clone or
worktree, run:

```sh
curl -sSL https://aka.ms/apm-unix | sh -s -- @v0.28.0
apm --version

apm install --frozen
apm compile --target codex
```

Start a fresh client session afterward so it discovers the generated skills.
Repository-specific instructions are packaged under `agent-packages/`; shared
instructions and skills follow `flyology-ada/agents` `main`.
`apm.lock.yaml` records the exact dependency commits and content hashes, so
frozen installs do not float. Review an upstream update explicitly:

```sh
apm outdated
apm update flyology-ada/agents
apm compile --target codex
apm audit --ci
```

Commit the reviewed lockfile and generated `AGENTS.md` changes together.

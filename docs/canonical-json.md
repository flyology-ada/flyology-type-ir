# Canonical JSON v1

Canonical JSON is deterministic offline interchange, not Flyology wire.

## Reader policy

Readers first reject duplicate keys, then read only `ir_version`. Version 1 is
accepted exactly; unsupported versions are rejected before any semantic field
is interpreted. Every v1 object has `additionalProperties: false`. Unknown
required features are rejected. Declared optional diagnostics may appear only
inside the explicit `extensions` object and do not affect semantic identity.

Any semantic shape change increments `ir_version`.

## Canonical bytes

- UTF-8 without BOM; exactly one final LF.
- Object keys sorted by their UTF-8 byte sequences.
- No insignificant whitespace.
- Shortest JSON escapes: escape quote, reverse solidus, and control characters;
  use lowercase `u` hex only where a `\u` escape is required. Non-ASCII is
  emitted directly as UTF-8.
- No duplicate object keys.
- Integers are JSON numbers only for bounded structural counters such as
  `ir_version` and `declaration_order`.
- Optional extension values may contain objects, arrays, strings, booleans,
  and null, but no JSON numbers. Diagnostic numbers use normalized decimal
  strings, avoiding an implicit cross-language floating-point algorithm.
- Ada/static integer semantics use normalized decimal strings:
  `0` or optional `-` followed by `[1-9][0-9]*`.
- Declaration/component/discriminant/variant tables and set-like arrays are
  sorted by stable semantic key. Source-semantic sequences carry explicit
  `declaration_order`; variant choice sets use normalized choice keys.

A conforming parser strictly parses, emits canonical bytes, and byte-compares
the re-emission with the original. JSON Schema alone does not prove
canonicality. `scripts/check_fixtures.py` applies these rules to golden files
and rejection mutants.

Canonical interchange bytes are an audit artifact, not a semantic fingerprint:
they intentionally retain source locations, display spelling, diagnostic syntax
and details, extension diagnostics, and extractor context. A semantic fingerprint
is SHA-256 over `Encode_Semantic_Projection` output. That projection uses the
same canonical JSON byte rules and recursively removes `context`, `extensions`,
`optional_features`, every `location`, `display_name`, `syntax`,
and fact `detail` member. Display `name`, generic `formal_name`, and actual
`origin` are also excluded while canonical names, formal IDs, order, and exact
bindings remain. Annotation `expression_syntax` is retained only when there is
no typed argument; otherwise it is diagnostic presentation.
The projection retains semantic declaration order, resolved expression
structure, fact status/value/code, view access, graph links, and core feature
identifiers. Consumers must never use the full-document byte hash as a semantic
fingerprint. Consequently whitespace, casing, file movement, diagnostic wording,
and equivalent source formatting do not change the semantic projection.

`fixtures/production-extraction.json` is canonical output from the reference
host's process-owned transaction. Its audit context intentionally contains
absolute compiler, runtime, project, and source paths, so the full document is
not a portable attestation. Portable golden comparison uses its semantic
projection/fingerprint plus a full audit comparison that replaces only the
checkout, GPRbuild, and GNAT host-root prefixes with documented fixed
placeholders and recomputes the two path-sensitive audit digests. Every other
audit byte remains exact. Each host reruns `extract_checked` for its own exact
production tuple.

The effective-project `closure_digest` is lowercase SHA-256 over canonical JSON
(including the final LF) of exactly these keys: `accessibility_context`,
`canonical_gpr_path`, `compiler_identity`, `compiler_switches`,
`configuration_pragmas`, `context_kind`, `project_files`, `runtime_identity`,
`runtime_sources`, `scenario`, `selected_units`, and `target`. Every source
entry carries its own lowercase SHA-256 content digest. This audit digest is
canonical but does not participate in semantic declaration identity.

`legality_check.command_fingerprint` is lowercase SHA-256 over canonical JSON,
including the final LF, of exactly the `command` object: sorted keys `argv`,
`environment`, `tool_identity`, and `working_directory`. `argv` preserves
argument order; `environment` is sorted uniquely by name. The fixture command
is the integrated test action from working directory `tests`:
`["gprbuild","-P","../fixtures/fixtures.gpr","-c","-gnatc"]` with
an empty environment and `fixture-toolchain` identity. The checker recomputes
both provenance digests rather than trusting stored hex strings.

## Extensions

`extensions` maps reverse-DNS namespaces to diagnostic JSON values. Extension
names exactly match entries in `optional_features`; consumers may skip them. Mandatory
semantics must never be moved to extensions or inferred from an unknown field.
Serialized readers may skip listed optional extensions after strict canonical
parsing. The initial Ada in-memory validator deliberately rejects every nonempty
extension vector because it cannot carry an unforgeable parse attestation; a
future strict codec may introduce a private verified representation. This keeps
the current API fail-closed instead of trusting a caller-writable Boolean.

## Codec seam

`Flyology_Type_IR.Canonical_JSON.Codec` is the Ada interface for future strict
codecs, including the source-independent semantic projection. Version 1
intentionally ships no permissive handwritten parser. The
schema, canonical byte fixtures, rejection mutants, and exact codec contract
form the stable seam until a duplicate-key-aware implementation is added.
The maintained dependency-free Python loader is installed as
`flyology_type_ir`. `load_checked(path, profile)` returns a `CheckedDocument`
holding the exact parsed-and-validated model, canonical semantic-projection
bytes, their lowercase SHA-256 fingerprint, and the source-byte digest.
Consumers lower from that retained model or its recursive immutable
`index_checked` graph; they do not reopen the path after validation. Profiles
are `structural`, document-only `strict`, and test-only `fixture_shape`.

Only `fixture_shape` admits synthetic provenance. Document-only `strict`
rejects extraction provenance because JSON cannot attest its own legality.
`flyology_type_ir.extractor.extract_checked(request)` is the production entry
point: it returns profile `strict` only after owning GNAT legality, unchanged
input snapshots, exact LAL traversal, canonical bytes, and validation in the
same invocation.

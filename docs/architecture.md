# Architecture

## Dependency boundary

The root Alire library owns only stable IR records, graph references,
validation, and the canonical JSON API seam. It has no Libadalang, serde, or
wire dependency. `tools/extractor` is a separate nested executable crate and is
the only place that may depend on the exactly pinned Libadalang release.

No Flyology runtime depends on either crate. Generators consume IR offline and
emit runtime code or companion manifests.

## Extraction transaction

One extractor invocation is a fail-closed transaction:

1. Canonicalize the GPR path and sorted scenario-variable map.
2. Select the exact target, runtime, compiler switches, and tool identities.
3. Run GNAT legality for that exact tuple in the current invocation.
4. Abort unless the check succeeds and the requested units belong to its
   project closure.
5. Create Libadalang contexts for the same closure and walk declaration ASTs.
6. Rebind generic formals through positional, named, default, and nested actual
   maps. A remaining formal on a mandatory path is Unknown or an error.
7. Walk exact discriminant and nested variant syntax. `p_shapes` may be used as
   a diagnostic cross-check only.
8. Validate the graph, then serialize it canonically as a single transaction.

The context contains a deterministic SHA-256 effective-project manifest:
selected units and content identities, configuration pragmas, runtime sources,
effective compiler switches, scenario, target, runtime, and compiler. Its
closure digest detects changed source or configuration behind an unchanged
tuple string. The projection also includes the canonical root GPR identity,
accessibility tuple, and context kind. This audit material never contributes to
declaration IDs.

The legality command is a typed audit record containing argv, working directory,
sorted environment, and tool identity. Its fingerprint is recomputed from
canonical JSON bytes, but this caller-writable digest is not an attestation.
`context_kind: extraction` requires absolute compiler and root-project paths.
Document-only `load_checked(path, "strict")` therefore rejects extraction
contexts regardless of their fields. Production admission through the
supported API is granted only by
`extract_checked(request)`, which owns GNAT legality, the pinned LAL probe,
canonical emission, and strict validation in one process. Consumers cannot
manufacture this capability by editing JSON. The internal authority is an
object identity, not a caller-writable Boolean. Python privacy is not a sandbox
against hostile code already executing in the same interpreter, so extraction
runs in a dedicated offline process. `context_kind: fixture` uses repository-logical
paths and remains test-only.

A stale build result never authorizes extraction. Paths and provenance live in
the context/diagnostic section and never contribute to semantic IDs.

The first enabled extraction slice is the exact public `Production_Shapes`
fixture: two local enums, one constrained one-dimensional array, and one plain
nonvariant record. Any extra public declaration, private part, aspect,
discriminant, default, component qualifier, use-site constraint, unsupported
type form, diagnostic, or resolution failure aborts without JSON. The process
verifies a reviewed toolchain-closure lock, forces an explicit empty GNAT
configuration, and snapshots membership plus bytes for the project, selected
source, compiler/probe/module inputs, exact two-directory PATH, full logical
GPRbuild/GNAT trees (entry kind, mode, symlink target, and content), native GMP
path chain, and runtime sources/ALIs/libraries before and after every phase,
including strict validation.
The serialized final manifest retains every content digest and the exact
scenario/target/runtime/compiler tuple; intermediate snapshots remain process
evidence rather than new v1 fields.

## Accessibility and views

Public, private, full, and incomplete views have different semantic IDs and
explicit links. Class-wide declarations are explicit declaration forms.
The requested accessibility context controls which representation may be
extracted. Discovering a full view is not permission to expose it. Strict
consumers fail when required structure is hidden.

## Identity

Declaration keys use normalized lowercase Ada expanded names plus explicit
generic-instantiation binding and view qualification:

```text
decl:<expanded-name>[<formal>=<actual-id>,...]#<public|private|full|incomplete|class_wide>
```

Ada identifier comparison is case-insensitive; display spelling is retained
separately. Binding keys are sorted by normalized formal name. Source paths,
line/column, traversal order, source spelling, and Libadalang nodes are banned
from IDs. Anonymous types are hard extraction errors rather than fabricated
location IDs. Anonymous access parameters and user-defined operator resolution
are also Unsupported in v1; neither has a lossy stringly substitute in the
stable model.

Canonical v1 identifiers are lowercase Ada basic identifiers: no reserved-word
segments, trailing underscores, or consecutive underscores. The schema and
both semantic validators enforce the same closed grammar and reserved-word set.
Extended Ada
identifiers require Unicode case-equivalence normalization that v1 does not
define, so extraction rejects a declaration, reference, unit, or binding whose
semantic identity would contain one as Unsupported. It must never invent a
percent-encoded or source-location identity.

## Consumer overlays

Overlays may add generator policy but cannot replace an Unknown/Unsupported
mandatory structural fact, change a resolved Known fact, grant visibility, or
expose a representation unavailable in the requested view. Such an attempt is
a validation error. Serde owns names/default-policy/optional/text/array-bound/
construction/resource policy; it does not own Ada structural defaults or type
shape. Wire companion manifests remain authoritative for wire policy.
`Flyology_Type_IR.Validation.Overlay_Replacement_Allowed` is the normative
non-escalation check and always rejects replacement. An overlay reads the IR
and stores policy separately; it never writes structural or visibility facts.

## Shared offline loading boundary

The installed Python package owns same-read `load_checked`, recursive immutable
`index_checked`, and exact-byte `AttestedChecker`. Attestation consumes only a
closed reviewed dependency tuple: repository, commit, IR version, exact
required features, checker path/hash, and schema path/hash. Consumer-specific
lock envelopes and every overlay, lowering, Ada naming, compatibility, or
generation decision remain outside Type IR. These utilities never broaden the
production extraction capability and are never runtime dependencies.

## Physical representation

Size, alignment, packing, convention, bit/component clauses, and enumeration
representation values are ignored by the semantic core. Declaration ordinal,
not representation value, is the enum semantic order used by consumers.

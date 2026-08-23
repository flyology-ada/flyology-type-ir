# Review log

All reviews were performed independently from implementation. P0/P1 findings
block completion; P2 findings are fixed unless an accepted rationale is listed.
No rationale exceptions are currently used.

## Architecture review

The independent architecture pass found two P0s: strict admissibility could not
infer safety from structural validity, and semantic IDs could not be derived
from source/LAL identity. It also found P1 gaps in the root/tool boundary, fact
semantics, exact variant AST, legality transaction, private/full views, generic
rebinding, and version negotiation. P2s covered canonical bytes, exact numeric
domains, Ada identifier normalization, physical-representation exclusion,
graph invariants, and negative fixtures.

Resolution: the root is dependency-light, the Libadalang 26.0.0 boundary is a
separate fail-closed crate, Structural and Strict_Consumer validation are
separate, IDs use normalized semantic keys, exact expression/variant trees and
typed constraints/actuals are structural, JSON rules are exact, and canonical
positive plus rejection fixtures are integrated into the test crate.

## Full-change review

The first full-change pass found no P0, eight P1s, and five P2s. P1s were:
fail-open missing facts; Ada/schema mismatch; weak identity/view integrity;
contradictory variant graphs; inadequate schema/canonical checks; missing
use-site subtype shape; untyped generic rebinding; and incomplete provenance.
P2s were non-JSON numeric acceptance, stale fixture provenance, inadequate test
integration, extractor executable mismatch, and weak fact-code validation.

Resolution: core fact/role/value vocabularies are closed and typed; strict
profiles define required facts; schema and Ada expose matching shapes;
identity/view/owner/path/order links are validated; recursive expression and
constraint nodes retain resolved semantics; generic actuals have typed kinds;
the effective-project manifest includes verified content digests; the checker
evaluates the schema keywords in use, canonical bytes, graph integrity, and
ninety-three negative mutants; source fixtures pass GNAT legality; AUnit invokes
fixture checks; the executable mapping is corrected; and fact codes are
canonicalized.

## Consumer schema reviews

Serde and wire independently reviewed the actual draft and identified the same
freeze-blocking shape gaps plus explicit enum/entity/default/annotation nodes,
incomplete/class-wide views, extended-identifier policy, project-content
identity, and an overlay non-escalation rule. These are incorporated. V1
rejects extended Ada identifiers as Unsupported until it has a normative
Unicode case-equivalence identity rather than inventing an encoding. Overlays
cannot change a Known structural fact, override mandatory
Unknown/Unsupported structure, or grant visibility.

## Final-change review

The second independent change pass found no P0, ten remaining P1s, and two
P2s. They covered lossless defaults; fact-specific value typing; strict
constraint admissibility; generic identity/entity kinds; reciprocal views;
exact variant/enum/array graph integrity; canonical feature/scenario/alternative
ordering; extension isolation; missing expression forms; annotation values;
and test/extension verification.

Resolution: the Ada model and schema now both retain default expression plus
static value, use fact-specific types, treat visibility as one authoritative
fact pair, require Known constraint answers in strict mode, bind instance IDs
to typed Generic_Actual records, validate bidirectional graphs and dense
positions, require the complete v1 feature set, skip optional payloads during
core interpretation, cover common dynamic expression forms with an explicit
unsupported node, validate annotation arguments, run GNAT fixture legality as
a test action, and reject nonempty Ada extension payloads until an independent
canonical codec can attest them.

## Final stabilization review

The final independent pass found no P0, P1, P2, or P3 issues. It verified all
eight canonical fixtures and ninety-three rejection cases, the root Ada build,
GNAT legality for all ten source fixture units, the nested AUnit suite, the
fixture-shape acceptance and production-strict rejection gates, the pinned
fail-closed extractor build and smoke test, APM compilation and audit, JSON
syntax, and a clean `git diff --check`. Previously reported findings concerning the
checked-loader API, character-literal lineage, predefined operator resolution,
anonymous access parameters, and exact Ada identifier grammar are resolved.

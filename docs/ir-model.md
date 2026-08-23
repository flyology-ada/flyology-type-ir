# IR model v1

The document is a graph. A type reference contains one stable declaration ID
(whose suffix identifies its view) plus an explicit use-site constraint;
definitions are never recursively duplicated, so recursive Ada types remain
finite. There is no second view field that can contradict the ID.

## Facts

Every uncertain property is explicit:

- `known`: exact semantics are present in `value`.
- `unknown`: extraction could not establish the answer in the exact analysis
  context; `code` is a stable reason code.
- `unsupported`: the construct is understood but outside this IR version or
  consumer profile; `code` is a stable feature code.

Diagnostic detail is non-semantic. A dynamic but understood expression is
Known with a tagged expression value, not Unknown. Known values are a closed,
versioned union (boolean, decimal integer, exact rational, expression, or
text), not arbitrary JSON. Core fact names and reference roles are closed by
the v1 schema; extensions are the only escape hatch. Schema validity is
not consumer admissibility: structural validation admits these facts; the
strict profile rejects Unknown/Unsupported on mandatory paths.

Required declaration facts include definiteness, limitedness, tagged,
class-wide, abstract, access-containing, task, protected, controlled and
contains-controlled-parts. View access is represented once, authoritatively,
as the fact-valued `representation_available` and
`consumer_can_name_components` fields. Component aliased/constant status and
shape predicates are also fact-valued. Inaccessible controlledness is Unknown,
never inferred safe.
Strict validation requires every applicable core fact to be present and Known;
an omitted fact never means false or not applicable.

The exact required feature set is `ada-type-ir/core`,
`ada-type-ir/decimal-strings`, `ada-type-ir/exact-variants`,
`ada-type-ir/graph-refs`, and `ada-type-ir/typed-shapes`. The closed v1 core
fact vocabulary is `definite`, `limited`, `tagged`, `class_wide`, `abstract`,
`contains_access`, `task`, `protected`, `controlled`,
`contains_controlled`, `aliased`, `constant`, `predicate`,
`constraint_staticness`, `modulus`, `digits`,
`delta`, `small`, `constrained`, and `null_exclusion`. The closed reference-role
vocabulary is `base_subtype` and `parent_type`; all other graph edges are
closed typed structural fields rather than string-role references.

## Scalars and exact numbers

Scalar nodes distinguish signed, modular, enumeration, floating, ordinary
fixed, decimal fixed, character, and boolean types. All arbitrary-precision
integers are strings matching `0|-?[1-9][0-9]*`; `-0`, plus signs, leading
zeros, fractions, and exponents are forbidden. Exact non-integral values use a
tagged rational `{numerator, denominator}` reduced to lowest terms with
normalized decimal strings and a positive denominator (`0` is exactly `0/1`).
No semantic value passes through binary floating
point.

Constraints record declared-versus-inherited provenance, static/dynamic
classification, original expression syntax, evaluated bounds when available,
and a fact code when unavailable or unsupported.
Every concrete scalar carries an explicit effective range constraint. A range
whose values cannot be evaluated retains Unknown/Unsupported bound facts with
a stable reason; `kind: none` never silently means “bounds omitted.”

Type shapes are closed structural unions for scalar categories, enumeration,
array (rank, dimensions, index subtypes/constraints, component subtype),
record, access (designated subtype and null exclusion), derived/base subtype, and
opaque private/incomplete/task/protected/class-wide forms. Type and subtype
declaration form is separate from effective kind. Components and discriminants
represent default presence explicitly; absence is not Unknown. Present defaults
carry a Known staticness fact, the exact expression AST, and a static value only
when staticness is true. A dynamic default uses `static_value: null`, not an
Unknown pseudo-value.

Serialized `shape.kind` is the sole effective-kind discriminant. The Ada
`Type_Declaration.Kind` field is derived by a codec; there is intentionally no
second serialized `declaration.kind`. Class-wide status likewise exists only in
the authoritative core fact, not in access shape.

## Declaration order and canonical order

Record components, discriminants, enum literals, generic formals/actuals, and
annotations retain explicit `declaration_order`. This semantic presentation
order is distinct from canonical serialization order. Set-like arrays and graph
tables are sorted by stable ID/key. Variant alternatives and their choice sets
are serialized in normalized-choice order while `declaration_order` retains Ada
semantic presentation order. Consumers
never derive wire tags from array position.

## Variants

Variant parts are explicit graph nodes with a selector discriminant,
alternatives, exact discrete choices (expression/name/range/subtype/`others`),
component IDs, and an optional nested variant ID. `others` remains explicit,
occurs at most once, and is alone in its alternative. Each component retains
its complete alternative path. Expression/range conditions contain a canonical
recursive expression AST; name and subtype choices contain resolved graph
references. An expression choice is general rather than literal-only, so a
legal static condition such as `-1 + 1` remains exact. The AST includes
literals, resolved names, unary/binary operations,
attributes, conversions, qualified expressions, calls, selected/indexed
components, and an explicit unsupported node. Source syntax is diagnostic
presentation only. A subtype choice has no arbitrary singular value: its exact
set is the resolved subtype/use-site range, which must be a compatible static
range of the selector's root type.

Character-literal expression nodes carry a resolved predefined character-type
edge, so their code-point position is unambiguous. V1 rejects overloaded
character literals belonging to user-defined enumeration types as Unsupported;
it never infers their position from Unicode text.

Unary and binary operator nodes retain explicit operand/result type edges and
an executable `predefined` resolution marker. User-defined operator calls are
Unsupported in v1; they cannot be serialized as a predefined token. Anonymous
access parameters are likewise Unsupported because v1 does not model their
complete access-definition profile; callable modes are limited to `in`, `out`,
and `in out`.

## Normative integrity

Validation requires globally unique IDs; resolved type/expression/owner/view/
generic links; reciprocal related views; bidirectional component/alternative
membership; consistent nested-variant parent links; acyclic containment; and
dense, unique `declaration_order` within each owner. Named child IDs derive
from owner identity plus canonical name. Variant IDs derive from owner/parent
path and selector; alternative IDs use a normalized-decimal
canonical-choice rank, independent of source alternative order. Canonical tables and sets are
sorted by stable key and no graph reference may dangle.

Generic actuals are typed as type, value, object, package, or subprogram and
record formal ID/name, origin (positional/named/default), instance, and order.
Each formal records its corresponding kind, and validation requires exact
kind/name/order agreement plus exactly one actual per formal.
Values remain exact Known boolean, decimal-integer, exact-rational, or text
facts rather than being coerced to type references. Unknown or Unsupported
value actuals are rejected even by structural validation because they cannot
participate in a collision-free generic-instantiation identity. Object
actuals additionally retain a resolved object entity ID and must conform to
the formal type. Subprogram actuals must match the formal callable profile.
V1 formal packages are explicitly limited to Ada's box-only `is new G (<>)`
form: they carry `formal_package_contract: box_only` plus a template edge, and
package actuals must instantiate that template. Partial or explicit formal-
package associations are Unsupported and the extractor must emit no IR for
them. V1 formal types likewise support only the closed
`signed_integer_range` contract corresponding to `type T is range <>`; every
other formal-type category is Unsupported and fail-closed. Every
declaration inside an instance includes `<formal>=<generic-actual-id>` in its
identity, tying its generic chain to the exact typed actual record.

V1 intentionally rejects constrained type actuals and expression-valued
value/object actuals because their stable identity projection is not yet
specified. The schema narrows those shapes to an unconstrained type reference
or an exact Known scalar/text fact. Extractors fail closed rather than dropping
a constraint, expression, or imprecise actual.

## Annotations

Annotations are normalized but uninterpreted by the shared layer: namespace,
action/key, typed arguments or retained expression text, target declaration or
view, inherited flag, and source order. Serde owns its namespace; wire companion
manifests remain authoritative for wire policy.

## Callable entities and accessibility

Subprogram entities and generic formal subprograms carry a closed callable
profile: dense parameter order, canonical and display names, parameter mode,
resolved unconstrained type refs, and an optional resolved result type. The
profile is encoded into the entity ID, so legal overloads never collide.

The non-semantic extractor context records the consumer unit, derivation unit,
and public-spec/private-part/body region used for accessibility answers. This
tuple participates in the effective-project closure digest but never in a
semantic declaration ID. An overlay cannot grant visibility beyond that exact
context. Contexts are explicitly `extraction` or `fixture`; production strict
validation currently rejects both until a verified legality attestation is
implemented. The checker's `fixture_shape` profile is a test-only bypass of
that provenance gate while retaining all strict semantic checks.

## Canonical fixtures

- `fixtures/typed-shapes.json` is shape-strict under the checker's explicit
  fixture allowance and covers enum order,
  arrays, access, floating/fixed scalars, use-site constraints, present static
  and dynamic defaults, and resolved expression forms.
- `fixtures/exact-variant-ast.json` covers exact range/expression/name/subtype/
  others choices,
  nested variant containment, reciprocal component paths, and canonical choice
  ordering.
- `fixtures/generic-actual-rebinding.json` covers all typed actual kinds,
  formal/actual conformance, origin forms, overload profiles, and identity
  rebinding.
- `fixtures/wire-record-shape.json` is the minimal test-only consumer target:
  one public definite record with nameable Boolean, signed-16, and modular-16
  components, no discriminants, and exact static ranges.
- `fixtures/nested-generic-rebinding.json` proves that instance, actual, entity,
  and nested declaration IDs include the complete enclosing instantiation
  chain without recursive expansion.
- `fixtures/public-private-full-views.json`,
  `fixtures/static-dynamic-constraints.json`, and
  `fixtures/unknown-unsupported-facts.json` cover view authority, evaluated and
  dynamic bounds, and epistemic facts.
- `fixtures/rejected/` contains a real anonymous component use-site and a
  mandatory-imprecision rejection document; `scripts/check_fixtures.py` adds
  mutation regressions.

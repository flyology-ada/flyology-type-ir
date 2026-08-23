# Extractor boundary

This nested Alire executable is the only crate allowed to depend on
Libadalang. Its manifest locks Libadalang to exactly `26.0.0`; the generated
Alire lock records the source artifact. The current command is deliberately
fail-closed until the same-invocation GNAT legality gate and exact AST traversal
are implemented—it emits no partial or unaudited IR.

Implementation must follow `docs/architecture.md`: exact GPR/scenario/target/
runtime identity, project-closure membership, generic actual rebinding, access-
controlled private/full views, exact discriminant/variant AST, and structural
plus strict validation before canonical output.

Build with `alr build`. On Apple Silicon Homebrew installations, the system
`libgmp` external may require `LIBRARY_PATH=/opt/homebrew/lib alr build`; run
the resulting stub with
`DYLD_LIBRARY_PATH=/opt/homebrew/lib ./bin/flyology_type_ir_extract`. The stub
must exit 1 and emit no JSON. This host-library path is a build prerequisite,
not extractor context or semantic identity.

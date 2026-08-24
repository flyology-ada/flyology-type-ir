# Extractor boundary

This nested Alire crate is the only crate allowed to depend on Libadalang. Its
manifest and lock pin Libadalang to exactly `26.0.0`.

`flyology_type_ir_lal_probe` performs the project-backed semantic AST walk used
by the process-owned Python extractor. It emits closed line evidence, never
canonical JSON. The legacy `flyology_type_ir_extract` command remains
deliberately fail-closed so an old caller cannot bypass the owned transaction.

The initial enabled slice accepts exactly one public `Production_Shapes`
package containing two local enums, one constrained one-dimensional array, and
one plain nonvariant record. The probe resolves index, array-component, and
record-component type edges. It rejects private parts, extra declarations,
discriminants, aspects, use-site constraints, defaults, aliased/constant
components, and every other type form. It walks the exact AST and never uses
`p_shapes`.

Build with `alr build`. On Apple Silicon Homebrew installations, the system
`libgmp` external may require `LIBRARY_PATH=/opt/homebrew/lib alr build`.

The supported production entry point is called from this reviewed source
checkout as
`flyology_type_ir.extractor.extract_checked(ExtractionRequest(...))`. It
requires explicit absolute GPR, source, `gprbuild`, `gnatls`, LAL probe,
runtime, environment-path, target, and scenario inputs. One request constructs
both GNAT and GPR2/LAL arguments. The PATH tuple contains exactly the approved
GPRbuild and GNAT `bin` directories in that order; no ambient child-tool
directory is admitted. It verifies the reviewed project, explicit
empty GNAT configuration, extractor sources/lock, approved probe and native
GMP path/symlink chain, full GPRbuild/GNAT logical-tree digests, and exact target. It
snapshots membership and bytes for the selected inputs, tool trees, runtime Ada
sources, ALIs, and libraries at every phase and again after strict validation.
Any drift aborts without JSON.

The probe binary and Homebrew GMP are user-space reviewed inputs. macOS system
dyld libraries are part of the operating-system trust base, not repository
artifacts.

The legacy smoke command remains:

```sh
DYLD_LIBRARY_PATH=/opt/homebrew/lib ./bin/flyology_type_ir_extract
```

It must exit 1 and emit no JSON.

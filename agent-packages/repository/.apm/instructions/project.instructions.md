---
description: Preserve Flyology Ada Type IR's dependency boundary, semantic exactness, canonical interchange, and verification workflow.
---

# Flyology Ada Type IR repository guidance

- The root crate is the stable semantic IR library. It must never depend on
  Libadalang, `flyology_serde`, or either Flyology runtime.
- Libadalang belongs only in `tools/extractor`, pinned exactly at that tool
  boundary. Extraction must be preceded by a successful same-invocation GNAT
  legality check for the exact project, canonical scenario map, target, and
  runtime.
- Stable semantic IDs never contain source paths, locations, traversal indexes,
  Libadalang handles, or physical representation information.
- Preserve explicit Known/Unknown/Unsupported facts. Never substitute defaults.
- Walk the exact discriminant/variant AST; never use `p_shapes` as the semantic
  source of truth.
- Canonical JSON fixtures are contract artifacts. Any semantic shape change
  requires an `ir_version` change and corresponding schema/fixture review.
- Tests live in the nested `tests` Alire crate. Run `alr build` in the root and
  `alr run` in `tests` before committing.
- Use focused Problem/Solution commit messages consistent with other Flyology
  repositories.

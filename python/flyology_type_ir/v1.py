"""Version 1 same-read loading API.

Production extraction is deliberately absent from ``load_checked``. Use
``flyology_type_ir.extractor.extract_checked`` so legality and LAL analysis are
owned by the same process that grants the strict result.
"""

from ._bootstrap import checker_module

_checker = checker_module()
CheckedDocument = _checker.CheckedDocument
Rejected = _checker.Rejected
load_checked = _checker.load_checked

__all__ = ["CheckedDocument", "Rejected", "load_checked"]

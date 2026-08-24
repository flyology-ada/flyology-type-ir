"""Load the private checker from an install or this exact source tree."""

from __future__ import annotations

import importlib
import hashlib
import sys
from pathlib import Path
from types import ModuleType


def checker_module() -> ModuleType:
    try:
        return importlib.import_module("flyology_type_ir._checker")
    except ModuleNotFoundError as error:
        if error.name != "flyology_type_ir._checker":
            raise
    repository = Path(__file__).resolve().parents[2]
    source = repository / "scripts/check_fixtures.py"
    schema = repository / "schema/type-ir-v1.schema.json"
    if not source.is_file() or not schema.is_file():
        raise ImportError("private Type IR checker is absent from this installation")
    name = "flyology_type_ir._source_checker"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    module = ModuleType(name)
    module.__file__ = str(source)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        source_bytes = source.read_bytes()
        code = compile(source_bytes, str(source), "exec", dont_inherit=True)
        exec(code, module.__dict__)
        module.__flyology_source_sha256__ = hashlib.sha256(source_bytes).hexdigest()
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


__all__ = ["checker_module"]

#!/usr/bin/env python3
"""Dependency-free canonical-byte and v1 contract checks for golden fixtures."""

from __future__ import annotations

import copy
import argparse
import hashlib
import json
import math
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

_PACKAGE_ROOT = Path(__file__).resolve().parent / "_root"
ROOT = _PACKAGE_ROOT if _PACKAGE_ROOT.is_dir() else Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
KNOWN_FEATURES = {
    "ada-type-ir/core",
    "ada-type-ir/decimal-strings",
    "ada-type-ir/exact-variants",
    "ada-type-ir/graph-refs",
    "ada-type-ir/typed-shapes",
}
TOP_KEYS = {
    "annotations",
    "components",
    "context",
    "declarations",
    "discriminants",
    "entities",
    "enum_literals",
    "extensions",
    "generic_actuals",
    "ir_version",
    "optional_features",
    "required_features",
    "variants",
}


def freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: freeze(child) for key, child in value.items()}
        )
    if isinstance(value, list):
        return tuple(freeze(child) for child in value)
    return value


def thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [thaw(child) for child in value]
    return value


@dataclass(frozen=True)
class CheckedDocument:
    """One-read validation result; consumers must use this retained model."""

    document: Mapping[str, object]
    semantic_projection: bytes
    semantic_fingerprint: str
    source_sha256: str
    profile: str


# This identity is an internal coupling between the owned extractor transaction
# and strict validation. It is not a security boundary against hostile code in
# the same Python interpreter; the supported public API never exports it.
_EXTRACTION_AUTHORITY = object()
STRICT_DECLARATION_FACTS = {
    "abstract",
    "class_wide",
    "contains_access",
    "contains_controlled",
    "controlled",
    "definite",
    "limited",
    "protected",
    "tagged",
    "task",
}
SEMANTIC_ID = re.compile(r"^decl:(?:[a-z0-9_.=,\[\]#:-]|%[0-9a-f]{2})+$")
DECIMAL = re.compile(r"^(0|-?[1-9][0-9]*)$")
ADA_RESERVED_WORDS = {
    "abort", "abs", "abstract", "accept", "access", "aliased", "all", "and",
    "array", "at", "begin", "body", "case", "constant", "declare", "delay",
    "delta", "digits", "do", "else", "elsif", "end", "entry", "exception",
    "exit", "for", "function", "generic", "goto", "if", "in", "interface",
    "is", "limited", "loop", "mod", "new", "not", "null", "of", "or",
    "others", "out", "overriding", "package", "parallel", "pragma", "private",
    "procedure", "protected", "raise", "range", "record", "rem", "renames",
    "requeue", "return", "reverse", "select", "separate", "some", "subtype",
    "synchronized", "tagged", "task", "terminate", "then", "type", "until",
    "use", "when", "while", "with", "xor",
}
_SCHEMA_BYTES = (ROOT / "schema/type-ir-v1.schema.json").read_bytes()
SCHEMA_SHA256 = hashlib.sha256(_SCHEMA_BYTES).hexdigest()
SCHEMA = json.loads(_SCHEMA_BYTES.decode("utf-8"))
REJECTION_COUNT = 0


class Rejected(ValueError):
    pass


def valid_semantic_id(value: str) -> bool:
    suffix = next(
        (item for item in ("#class_wide", "#incomplete", "#private", "#public", "#full") if value.endswith(item)),
        None,
    )
    if suffix is None or not SEMANTIC_ID.fullmatch(value):
        return False
    body = value[5 : -len(suffix)]
    if not body:
        return False
    for encoded in re.findall(r"(?:%[0-9a-f]{2})+", body):
        try:
            bytes.fromhex(encoded.replace("%", "")).decode("utf-8")
        except UnicodeDecodeError:
            return False
    depth = 0
    for index, character in enumerate(body):
        if character == "[":
            if index + 1 == len(body) or body[index + 1] == "]":
                return False
            depth += 1
        elif character == "]":
            if depth == 0:
                return False
            depth -= 1
        elif character == "#" and depth == 0:
            return False
    return depth == 0


def valid_canonical_name(value: str, *, segment: bool = False) -> bool:
    parts = value.split(".")
    if segment and len(parts) != 1:
        return False
    for part in parts:
        if (
            not re.fullmatch(r"[a-z](?:[a-z0-9]|_(?=[a-z0-9]))*", part)
            or part in ADA_RESERVED_WORDS
        ):
            return False
    return True


def project_semantics(value: object) -> object:
    """Remove diagnostic presentation without removing resolved semantics."""
    excluded = {
        "detail",
        "display_name",
        "formal_name",
        "location",
        "name",
        "origin",
        "syntax",
    }

    if isinstance(value, dict):
        local_excluded = excluded
        if "arguments" in value and value.get("arguments"):
            local_excluded = excluded | {"expression_syntax"}
        return {
            key: project_semantics(child)
            for key, child in value.items()
            if key not in local_excluded
        }
    if isinstance(value, list):
        return [project_semantics(child) for child in value]
    return value


def semantic_projection(document: dict[str, object]) -> bytes:

    projected = {
        key: project_semantics(value)
        for key, value in document.items()
        if key not in {"context", "extensions", "optional_features"}
    }
    return json.dumps(
        projected, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"


def length_prefix(value: str) -> str:
    return f"{len(value.encode('utf-8'))}:{value}"


def fact_semantic_key(fact: dict[str, object]) -> str:
    if fact["status"] != "known":
        return f"{fact['status'].upper()}:{length_prefix(fact['code'])}"
    value = fact["value"]
    if value["kind"] == "boolean":
        return f"KNOWN:BOOLEAN:{str(value['value']).upper()}"
    if value["kind"] == "decimal_integer":
        return f"KNOWN:INTEGER:{length_prefix(value['value'])}"
    if value["kind"] == "exact_rational":
        rational = value["value"]
        return (
            "KNOWN:RATIONAL:"
            + length_prefix(rational["numerator"])
            + length_prefix(rational["denominator"])
        )
    if value["kind"] == "text":
        return f"KNOWN:TEXT:{length_prefix(value['value'])}"
    return "KNOWN:EXPRESSION"


OPERATOR_IMAGE = {
    "+": "PLUS_OPERATOR", "-": "MINUS_OPERATOR", "*": "MULTIPLY_OPERATOR",
    "/": "DIVIDE_OPERATOR", "mod": "MOD_OPERATOR", "rem": "REM_OPERATOR",
    "**": "EXPONENT_OPERATOR", "abs": "ABS_OPERATOR", "not": "NOT_OPERATOR",
    "and": "AND_OPERATOR", "or": "OR_OPERATOR", "xor": "XOR_OPERATOR",
    "=": "EQUAL_OPERATOR", "!=": "NOT_EQUAL_OPERATOR", "<": "LESS_OPERATOR",
    "<=": "LESS_EQUAL_OPERATOR", ">": "GREATER_OPERATOR", ">=": "GREATER_EQUAL_OPERATOR",
}


def expression_semantic_key(value: dict[str, object]) -> str:
    kind = value["kind"]
    tag = {
        "boolean_literal": "BOOLEAN_LITERAL", "character_literal": "CHARACTER_LITERAL",
        "integer_literal": "INTEGER_LITERAL", "decimal_literal": "DECIMAL_LITERAL",
        "string_literal": "STRING_LITERAL", "declaration_ref": "DECLARATION_REFERENCE",
        "unary": "UNARY_OPERATION", "binary": "BINARY_OPERATION",
        "attribute": "ATTRIBUTE_REFERENCE", "type_conversion": "TYPE_CONVERSION",
        "qualified": "QUALIFIED_EXPRESSION", "function_call": "FUNCTION_CALL",
        "selected_component": "SELECTED_COMPONENT", "indexed_component": "INDEXED_COMPONENT",
        "unsupported": "UNSUPPORTED_EXPRESSION",
    }[kind] + ":"
    if kind == "boolean_literal":
        return tag + str(value["value"]).upper()
    if kind == "character_literal":
        return tag + length_prefix(value["resolved_type_id"]) + length_prefix(value["value"])
    if kind in {"integer_literal", "string_literal"}:
        return tag + length_prefix(value["value"])
    if kind == "decimal_literal":
        return tag + length_prefix(value["value"]["numerator"]) + length_prefix(value["value"]["denominator"])
    if kind == "declaration_ref":
        return tag + length_prefix(value["declaration_id"])
    if kind == "unary":
        return (
            tag + OPERATOR_IMAGE[value["operator"]] + ":"
            + length_prefix(value["operand_type_id"])
            + length_prefix(value["result_type_id"])
            + length_prefix(expression_semantic_key(value["operand"]))
        )
    if kind == "binary":
        return (
            tag + OPERATOR_IMAGE[value["operator"]] + ":"
            + length_prefix(value["left_type_id"])
            + length_prefix(value["right_type_id"])
            + length_prefix(value["result_type_id"])
            + length_prefix(expression_semantic_key(value["left"]))
            + length_prefix(expression_semantic_key(value["right"]))
        )
    if kind == "attribute":
        count = len(value["arguments"])
        if (
            (value["attribute"] in {"first", "last", "length"} and count > 1)
            or (value["attribute"] in {"pos", "pred", "succ", "val"} and count != 1)
        ):
            raise Rejected("attribute argument count is invalid")
        return tag + value["attribute"].upper() + "_ATTRIBUTE:" + length_prefix(expression_semantic_key(value["prefix"])) + "".join(
            length_prefix(expression_semantic_key(item)) for item in value["arguments"]
        )
    if kind in {"type_conversion", "qualified"}:
        return tag + length_prefix(type_ref_semantic_key(value["target_subtype"])) + length_prefix(expression_semantic_key(value["operand"]))
    if kind == "function_call":
        return tag + length_prefix(value["resolved_subprogram_id"]) + "".join(length_prefix(expression_semantic_key(item)) for item in value["arguments"])
    if kind == "selected_component":
        return tag + length_prefix(expression_semantic_key(value["prefix"])) + length_prefix(value["selector_id"])
    if kind == "indexed_component":
        return tag + length_prefix(expression_semantic_key(value["prefix"])) + "".join(length_prefix(expression_semantic_key(item)) for item in value["indices"])
    return tag + length_prefix(value["feature_code"])


def constraint_semantic_key(value: dict[str, object]) -> str:
    if value["kind"] == "none":
        return "NONE"
    provenance = {"declared_subtype": "DECLARED_SUBTYPE", "inherited_base": "INHERITED_FROM_BASE", "use_site": "USE_SITE"}[value["provenance"]]
    if value["kind"] == "scalar_range":
        return "RANGE:" + provenance + ":" + "".join(length_prefix(item) for item in (
            expression_semantic_key(value["low"]), expression_semantic_key(value["high"]),
            fact_semantic_key(value["staticness"]), fact_semantic_key(value["static_low"]),
            fact_semantic_key(value["static_high"]), fact_semantic_key(value["predicate"]),
        ))
    if value["kind"] == "array_indices":
        return "ARRAY:" + "".join(
            f"{item['position']}:"
            + length_prefix(type_ref_semantic_key(item["index_subtype"]))
            + length_prefix(constraint_semantic_key(item["constraint"]))
            for item in value["dimensions"]
        )
    if value["kind"] == "discriminants":
        return "DISCRIMINANTS:" + "".join(
            length_prefix(item["discriminant_id"])
            + length_prefix(expression_semantic_key(item["expression"]))
            + length_prefix(fact_semantic_key(item["staticness"]))
            + (length_prefix(fact_semantic_key(item["static_value"])) if item["static_value"] is not None else "NULL")
            for item in value["associations"]
        )
    tag = "DIGITS_CONSTRAINT" if value["kind"] == "digits" else "DELTA_CONSTRAINT"
    secondary = value.get("small", {"status": "unknown", "code": "", "detail": ""})
    return tag + ":" + length_prefix(expression_semantic_key(value[value["kind"]])) + length_prefix(fact_semantic_key(value["static_value"])) + length_prefix(fact_semantic_key(secondary))


def type_ref_semantic_key(value: dict[str, object]) -> str:
    return length_prefix(value["declaration_id"]) + length_prefix(constraint_semantic_key(value["constraint"]))


def choice_semantic_key(choice: dict[str, object]) -> str:
    kind = choice["kind"]
    if kind == "expression":
        return "0:EXPRESSION:" + length_prefix(expression_semantic_key(choice["expression"])) + length_prefix(fact_semantic_key(choice["static_value"]))
    if kind == "name":
        return "1:NAME:" + length_prefix(choice["resolved_declaration_id"]) + length_prefix(fact_semantic_key(choice["static_value"]))
    if kind == "range":
        return "2:RANGE:" + length_prefix(expression_semantic_key(choice["low"])) + length_prefix(expression_semantic_key(choice["high"])) + length_prefix(fact_semantic_key(choice["static_low"])) + length_prefix(fact_semantic_key(choice["static_high"]))
    if kind == "subtype":
        return "3:SUBTYPE:" + length_prefix(type_ref_semantic_key(choice["resolved_subtype"]))
    return "9:OTHERS"


def alternative_semantic_key(alternative: dict[str, object]) -> str:
    return choice_semantic_key(alternative["choices"][0])


def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Rejected(f"duplicate key: {key}")
        result[key] = value
    return result


def parse(raw: bytes) -> dict[str, object]:
    if raw.startswith(b"\xef\xbb\xbf") or not raw.endswith(b"\n"):
        raise Rejected("UTF-8 BOM or missing final LF")
    if raw.endswith(b"\n\n"):
        raise Rejected("more than one final LF")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                Rejected(f"non-JSON numeric constant: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(str(error)) from error
    if not isinstance(value, dict):
        raise Rejected("top-level value must be an object")
    try:
        canonical = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8") + b"\n"
    except UnicodeEncodeError as error:
        raise Rejected(str(error)) from error
    if canonical != raw:
        raise Rejected("bytes are not canonical")
    return value


def validate_schema(value: object, schema: dict[str, object], path: str = "") -> None:
    """Evaluate the Draft 2020-12 keywords used by this repository's schema."""
    if "$ref" in schema:
        target: object = SCHEMA
        for token in schema["$ref"].removeprefix("#/").split("/"):
            target = target[token]
        validate_schema(value, target, path)
        return
    if "oneOf" in schema:
        matches = 0
        for choice in schema["oneOf"]:
            try:
                validate_schema(value, choice, path)
                matches += 1
            except Rejected:
                pass
        if matches != 1:
            raise Rejected(f"{path}: expected exactly one schema alternative")
        return
    for requirement in schema.get("allOf", []):
        validate_schema(value, requirement, path)
    if "if" in schema:
        try:
            validate_schema(value, schema["if"], path)
            branch = schema.get("then")
        except Rejected:
            branch = schema.get("else")
        if branch is not None:
            validate_schema(value, branch, path)
    if "const" in schema:
        constant = schema["const"]
        if type(value) is not type(constant) or value != constant:
            raise Rejected(f"{path}: value does not match const")
    if "enum" in schema and not any(
        type(value) is type(item) and value == item for item in schema["enum"]
    ):
        raise Rejected(f"{path}: value is outside enum")
    allowed_types = schema.get("type")
    if allowed_types:
        if not isinstance(allowed_types, list):
            allowed_types = [allowed_types]
        predicates = {
            "array": lambda item: isinstance(item, list),
            "boolean": lambda item: isinstance(item, bool),
            "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
            "null": lambda item: item is None,
            "object": lambda item: isinstance(item, dict),
            "string": lambda item: isinstance(item, str),
        }
        if not any(predicates[kind](value) for kind in allowed_types):
            raise Rejected(f"{path}: wrong JSON type")
    if isinstance(value, str) and "pattern" in schema:
        if not re.search(schema["pattern"], value):
            raise Rejected(f"{path}: string does not match pattern")
    if isinstance(value, str) and len(value) < schema.get("minLength", 0):
        raise Rejected(f"{path}: string is too short")
    if isinstance(value, str) and "maxLength" in schema and len(value) > schema["maxLength"]:
        raise Rejected(f"{path}: string is too long")
    if isinstance(value, int) and "minimum" in schema and value < schema["minimum"]:
        raise Rejected(f"{path}: integer is below minimum")
    if isinstance(value, int) and "maximum" in schema and value > schema["maximum"]:
        raise Rejected(f"{path}: integer is above maximum")
    if isinstance(value, list):
        if schema.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            raise Rejected(f"{path}: array items are not unique")
        if len(value) < schema.get("minItems", 0):
            raise Rejected(f"{path}: array is too short")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise Rejected(f"{path}: array is too long")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_schema(item, schema["items"], f"{path}/{index}")
    if isinstance(value, dict):
        required = set(schema.get("required", []))
        if not required.issubset(value):
            raise Rejected(f"{path}: missing required object fields")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                validate_schema(item, properties[key], f"{path}/{key}")
            elif additional is False:
                raise Rejected(f"{path}: additional property {key}")
            elif isinstance(additional, dict):
                validate_schema(item, additional, f"{path}/{key}")
        if "propertyNames" in schema:
            for key in value:
                validate_schema(key, schema["propertyNames"], f"{path}/{key}")


def check_fact(fact: object) -> None:
    if not isinstance(fact, dict) or fact.get("status") not in {
        "known",
        "unknown",
        "unsupported",
    }:
        raise Rejected("malformed fact")
    status = fact["status"]
    expected = {"detail", "status", "value"} if status == "known" else {
        "code",
        "detail",
        "status",
    }
    if set(fact) != expected:
        raise Rejected(f"wrong fields for {status} fact")
    if status != "known" and not re.fullmatch(r"[a-z][a-z0-9_.-]*", fact["code"]):
        raise Rejected("fact code is not stable/canonical")


def declaration_name_from_id(stable_id: str) -> str:
    depth = 0
    result: list[str] = []
    for character in stable_id.removeprefix("decl:"):
        if character == "[":
            depth += 1
        elif character == "]":
            if depth == 0:
                return ""
            depth -= 1
        elif character == "#" and depth == 0:
            break
        elif depth == 0:
            result.append(character)
    return "" if depth else "".join(result)


def declaration_family_key(stable_id: str) -> str:
    """Drop only the terminal view, preserving every generic actual binding."""
    return stable_id.rsplit("#", 1)[0]


def rooted_type_family_key(stable_id: str) -> str:
    """Normalize ordinary views while keeping class-wide a distinct Ada type."""
    return stable_id if stable_id.endswith("#class_wide") else declaration_family_key(stable_id)


def effective_closure_digest(document: dict[str, object]) -> str:
    context = document["context"]
    effective = context["effective_project"]
    closure_input = {
        "accessibility_context": context["accessibility_context"],
        "canonical_gpr_path": context["canonical_gpr_path"],
        "compiler_identity": context["compiler_identity"],
        "compiler_switches": effective["compiler_switches"],
        "configuration_pragmas": effective["configuration_pragmas"],
        "context_kind": context["context_kind"],
        "project_files": effective["project_files"],
        "runtime_identity": context["runtime_identity"],
        "runtime_sources": effective["runtime_sources"],
        "scenario": context["scenario"],
        "selected_units": effective["selected_units"],
        "target": context["target"],
    }
    closure_bytes = json.dumps(
        closure_input, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"
    return hashlib.sha256(closure_bytes).hexdigest()


def walk_facts(value: object, strict: bool = False) -> None:
    if isinstance(value, dict):
        if "status" in value:
            check_fact(value)
            if strict and value["status"] != "known":
                raise Rejected("strict structural fact is imprecise")
        else:
            for child in value.values():
                walk_facts(child, strict)
    elif isinstance(value, list):
        for child in value:
            walk_facts(child, strict)


def validate(
    document: dict[str, object],
    strict: bool = False,
    *,
    allow_fixture: bool = False,
    extraction_authority: object | None = None,
) -> None:
    trusted_extraction = extraction_authority is _EXTRACTION_AUTHORITY
    if set(document) != TOP_KEYS:
        raise Rejected("unknown or missing top-level field")
    if document["ir_version"] != 1:
        raise Rejected("unsupported IR version")
    required = document["required_features"]
    if required != sorted(required) or set(required) != KNOWN_FEATURES:
        raise Rejected("required feature set must be the complete sorted v1 core")
    if document["optional_features"] != sorted(document["optional_features"]):
        raise Rejected("optional features are not sorted")
    if document["context"]["scenario"] != sorted(
        document["context"]["scenario"], key=lambda item: item["name"]
    ):
        raise Rejected("scenario map is not canonical")
    scenario_names = [item["name"] for item in document["context"]["scenario"]]
    if len(scenario_names) != len(set(scenario_names)):
        raise Rejected("scenario names are not unique")
    context = document["context"]
    if strict and context["context_kind"] == "fixture" and not allow_fixture:
        raise Rejected("strict production consumers reject synthetic fixture provenance")
    if strict and context["context_kind"] == "extraction" and not trusted_extraction:
        raise Rejected(
            "extraction documents require the process-owned extract_checked gate"
        )
    for key in (
        "compiler_identity",
        "compiler_path",
        "extractor_version",
        "gnat_version",
        "libadalang_version",
        "project_name",
        "runtime_identity",
        "target",
    ):
        if not context[key]:
            raise Rejected(f"context {key} must not be empty")
    if context["context_kind"] == "extraction":
        if not context["canonical_gpr_path"].startswith("/") or not context["compiler_path"].startswith("/"):
            raise Rejected("extraction GPR/compiler paths must be absolute")
    elif (
        context["context_kind"] != "fixture"
        or context["canonical_gpr_path"] != "fixtures/fixtures.gpr"
        or context["compiler_path"] != "PATH:gprbuild"
    ):
        raise Rejected("fixture context must use the canonical logical legality command")
    legality_command = context["legality_check"]["command"]
    if legality_command["environment"] != sorted(
        legality_command["environment"], key=lambda item: item["name"]
    ) or len({item["name"] for item in legality_command["environment"]}) != len(
        legality_command["environment"]
    ):
        raise Rejected("legality command environment is not canonical")
    legality_bytes = json.dumps(
        legality_command, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"
    if hashlib.sha256(legality_bytes).hexdigest() != context["legality_check"]["command_fingerprint"]:
        raise Rejected("legality command fingerprint is stale")
    if context["context_kind"] == "fixture" and legality_command != {
        "argv": ["gprbuild", "-P", "../fixtures/fixtures.gpr", "-c", "-gnatc"],
        "environment": [],
        "tool_identity": "fixture-toolchain",
        "working_directory": "tests",
    }:
        raise Rejected("fixture legality command does not match the integrated test action")
    accessibility = context["accessibility_context"]
    if accessibility["region"] not in {"body", "private_part", "public_spec"}:
        raise Rejected("accessibility region is not canonical")
    if set(document["extensions"]) != set(document["optional_features"]):
        raise Rejected("extensions and optional_features must name the same namespaces")
    effective = document["context"]["effective_project"]
    for key in ("configuration_pragmas", "project_files", "runtime_sources"):
        if effective[key] != sorted(effective[key], key=lambda item: item["logical_name"]):
            raise Rejected(f"effective project {key} is not canonical")
        logical_names = [item["logical_name"] for item in effective[key]]
        if any(not item for item in logical_names):
            raise Rejected(f"effective project {key} contains an empty logical name")
        if len(logical_names) != len(set(logical_names)):
            raise Rejected(f"effective project {key} has duplicate logical names")
    for key in ("project_closure", "requested_units"):
        if document["context"][key] != sorted(document["context"][key]):
            raise Rejected(f"context {key} is not canonical")
        if any(not item for item in document["context"][key]):
            raise Rejected(f"context {key} contains an empty unit name")
    closure_units = set(context["project_closure"])
    if not set(context["requested_units"]).issubset(closure_units):
        raise Rejected("requested units must belong to the project closure")
    if effective["selected_units"] != sorted(
        effective["selected_units"],
        key=lambda item: (item["unit_name"], item["source_kind"], item["logical_name"]),
    ):
        raise Rejected("selected source manifest is not canonical")
    selected_keys = [
        (item["unit_name"], item["source_kind"], item["logical_name"])
        for item in effective["selected_units"]
    ]
    if len(selected_keys) != len(set(selected_keys)):
        raise Rejected("selected source manifest contains duplicates")
    selected_units = {item["unit_name"] for item in effective["selected_units"]}
    if selected_units != closure_units:
        raise Rejected("selected unit manifest must exactly cover the project closure")
    project_names = {item["logical_name"] for item in effective["project_files"]}
    if context["canonical_gpr_path"] not in project_names:
        raise Rejected("effective project manifest must contain the canonical root GPR")
    if context["context_kind"] == "fixture" or trusted_extraction:
        for project_file in effective["project_files"]:
            project_path = ROOT / project_file["logical_name"]
            if not project_path.is_file() or hashlib.sha256(project_path.read_bytes()).hexdigest() != project_file["content_digest"]:
                raise Rejected("project-file content digest is stale")
    if context["context_kind"] == "extraction" and trusted_extraction:
        for manifest_name in ("configuration_pragmas", "runtime_sources"):
            for source in effective[manifest_name]:
                source_path = Path(source["logical_name"])
                if not source_path.is_absolute():
                    raise Rejected(f"extraction {manifest_name} paths must be absolute")
                if (
                    not source_path.is_file()
                    or hashlib.sha256(source_path.read_bytes()).hexdigest()
                    != source["content_digest"]
                ):
                    raise Rejected(f"{manifest_name} content digest is stale")
    if context["context_kind"] == "fixture" or trusted_extraction:
        for source in effective["selected_units"]:
            source_path = ROOT / source["logical_name"]
            if not source_path.is_file():
                raise Rejected("selected fixture unit is missing")
            actual_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
            if actual_digest != source["content_digest"]:
                raise Rejected("selected unit content digest is stale")
    if effective_closure_digest(document) != effective["closure_digest"]:
        raise Rejected("effective project closure digest is stale")

    ids: set[str] = set()
    declarations: set[str] = set()
    components: set[str] = set()
    discriminants: set[str] = set()
    alternatives: set[str] = set()
    for table_name in (
        "components",
        "declarations",
        "discriminants",
        "entities",
        "enum_literals",
        "generic_actuals",
        "variants",
    ):
        table = document[table_name]
        if table != sorted(table, key=lambda item: item["stable_id"]):
            raise Rejected(f"{table_name} table is not sorted by stable_id")
        for item in table:
            stable_id = item["stable_id"]
            if not valid_semantic_id(stable_id) or stable_id in ids:
                raise Rejected("invalid, anonymous, or duplicate stable ID")
            ids.add(stable_id)
            if table_name == "declarations":
                declarations.add(stable_id)
            elif table_name == "components":
                components.add(stable_id)
            elif table_name == "discriminants":
                discriminants.add(stable_id)
            elif table_name == "variants":
                for alternative in item["alternatives"]:
                    alternative_id = alternative["stable_id"]
                    if not valid_semantic_id(alternative_id) or alternative_id in ids:
                        raise Rejected("invalid or duplicate alternative ID")
                    ids.add(alternative_id)
                    alternatives.add(alternative_id)
    entity_by_id = {item["stable_id"]: item for item in document["entities"]}
    for item in document["declarations"] + document["entities"]:
        if not valid_canonical_name(item["canonical_name"]):
            raise Rejected("canonical declaration/entity name is malformed")
    for table_name in ("components", "discriminants", "enum_literals"):
        for item in document[table_name]:
            if not valid_canonical_name(item["canonical_name"], segment=True):
                raise Rejected("canonical child name is malformed")
    for item in document["generic_actuals"]:
        if not valid_canonical_name(item["formal_canonical_name"], segment=True):
            raise Rejected("canonical formal name is malformed")

    def direct_literal_value(expression: dict[str, object] | None) -> object | None:
        if expression is None:
            return None
        kind = expression["kind"]
        if kind == "boolean_literal":
            return {"kind": "boolean", "value": expression["value"]}
        if kind == "character_literal":
            value = expression["value"]
            if len(value) == 1:
                return {"kind": "decimal_integer", "value": str(ord(value))}
            return None
        if kind == "integer_literal":
            return {"kind": "decimal_integer", "value": expression["value"]}
        if kind == "decimal_literal":
            return {"kind": "exact_rational", "value": expression["value"]}
        if kind == "string_literal":
            return {"kind": "text", "value": expression["value"]}
        if kind != "unary":
            return None
        operand = direct_literal_value(expression["operand"])
        if operand is None:
            return None
        operator = expression["operator"]
        if operator == "+" and operand["kind"] in {"decimal_integer", "exact_rational"}:
            return operand
        if operator in {"-", "abs"} and operand["kind"] in {
            "decimal_integer", "exact_rational",
        }:
            copied = copy.deepcopy(operand)
            if copied["kind"] == "decimal_integer":
                number = copied["value"]
                copied["value"] = (
                    (number[1:] if number.startswith("-") else "-" + number)
                    if operator == "-" and number != "0"
                    else number.removeprefix("-")
                )
            else:
                number = copied["value"]["numerator"]
                copied["value"]["numerator"] = (
                    (number[1:] if number.startswith("-") else "-" + number)
                    if operator == "-" and number != "0"
                    else number.removeprefix("-")
                )
            return copied
        if operator == "not" and operand["kind"] == "boolean":
            return {"kind": "boolean", "value": not operand["value"]}
        return None

    def check_direct_literal_agreement(
        expression: dict[str, object] | None,
        fact: dict[str, object],
        label: str,
    ) -> None:
        direct = direct_literal_value(expression)
        if fact["status"] == "known" and direct is not None and fact["value"] != direct:
            raise Rejected(f"{label} contradicts its direct literal expression")

    def check_constraint(
        constraint: dict[str, object], required_provenance: str | set[str] | None,
        target: dict[str, object] | None = None,
    ) -> None:
        if constraint["kind"] == "none":
            return
        allowed = (
            required_provenance
            if isinstance(required_provenance, set)
            else {required_provenance}
        )
        if constraint["provenance"] not in allowed:
            raise Rejected("constraint provenance disagrees with its structural context")
        if target is not None:
            target_kind = target["shape"]["kind"]
            applicable = {
                "scalar_range": {
                    "signed_scalar", "modular_scalar", "boolean_scalar", "enumeration", "floating_scalar",
                    "ordinary_fixed_scalar", "decimal_fixed_scalar", "character_scalar",
                },
                "array_indices": {"array"},
                "discriminants": {"record"},
                "digits": {"floating_scalar", "decimal_fixed_scalar"},
                "delta": {"ordinary_fixed_scalar", "decimal_fixed_scalar"},
            }
            if target_kind not in applicable[constraint["kind"]]:
                raise Rejected("constraint kind is incompatible with referenced declaration")
            if constraint["kind"] == "scalar_range":
                expected_value_kind = {
                    "signed_scalar": "decimal_integer",
                    "modular_scalar": "decimal_integer",
                    "boolean_scalar": "boolean",
                    "enumeration": "decimal_integer",
                    "character_scalar": "decimal_integer",
                    "floating_scalar": "exact_rational",
                    "ordinary_fixed_scalar": "exact_rational",
                    "decimal_fixed_scalar": "exact_rational",
                }[target_kind]
                for bound_name in ("static_low", "static_high"):
                    bound = constraint[bound_name]
                    if bound["status"] == "known" and bound["value"]["kind"] != expected_value_kind:
                        raise Rejected("evaluated scalar bound has the wrong value kind")
                if (
                    constraint["staticness"]["status"] == "known"
                    and constraint["staticness"]["value"]
                        == {"kind": "boolean", "value": True}
                    and any(
                        constraint[name]["status"] != "known"
                        for name in ("static_low", "static_high")
                    )
                ):
                    raise Rejected("Known static range requires exact evaluated bounds")
                check_direct_literal_agreement(
                    constraint["low"], constraint["static_low"], "scalar low bound"
                )
                check_direct_literal_agreement(
                    constraint["high"], constraint["static_high"], "scalar high bound"
                )
        if constraint["kind"] == "array_indices":
            dimensions = constraint["dimensions"]
            if [item["position"] for item in dimensions] != list(
                range(1, len(dimensions) + 1)
            ):
                raise Rejected("constraint array dimensions are not dense from one")
            for dimension in dimensions:
                check_type_ref(dimension["index_subtype"])
                dimension_target = next(
                    item for item in document["declarations"]
                    if item["stable_id"] == dimension["index_subtype"]["declaration_id"]
                )
                if dimension_target["shape"]["kind"] not in {
                    "boolean_scalar", "character_scalar", "enumeration",
                    "modular_scalar", "signed_scalar",
                }:
                    raise Rejected("array index subtype is not discrete")
                check_constraint(dimension["constraint"], "use_site", dimension_target)
            if target is not None:
                target_dimensions = target["shape"]["dimensions"]
                if len(dimensions) != target["shape"]["rank"] or any(
                    item["index_subtype"]["declaration_id"]
                    != target_dimensions[index]["index_subtype"]["declaration_id"]
                    for index, item in enumerate(dimensions)
                ):
                    raise Rejected("array use-site dimensions disagree with target array shape")
        elif constraint["kind"] == "discriminants":
            associations = constraint["associations"]
            association_ids = [item["discriminant_id"] for item in associations]
            if association_ids != sorted(association_ids) or len(association_ids) != len(
                set(association_ids)
            ):
                raise Rejected("discriminant associations are not unique and canonical")
            for association in associations:
                if association["discriminant_id"] not in discriminants:
                    raise Rejected("discriminant association is unresolved")
                if target is not None:
                    discriminant = next(
                        item for item in document["discriminants"]
                        if item["stable_id"] == association["discriminant_id"]
                    )
                    if discriminant["owner_id"] != target["stable_id"]:
                        raise Rejected("discriminant association belongs to another record")
                check_fact(association["staticness"])
                if strict and association["staticness"]["status"] != "known":
                    raise Rejected("strict discriminant staticness is imprecise")
                if association["staticness"]["status"] == "known":
                    is_static = association["staticness"]["value"] == {
                        "kind": "boolean",
                        "value": True,
                    }
                    if is_static != (association["static_value"] is not None):
                        raise Rejected("discriminant static-value presence disagrees with staticness")
                if association["static_value"] is not None:
                    check_fact(association["static_value"])
                    discriminant = next(
                        item for item in document["discriminants"]
                        if item["stable_id"] == association["discriminant_id"]
                    )
                    expected = expected_static_kind(discriminant["type"])
                    if association["static_value"]["status"] == "known" and (
                        expected is None
                        or association["static_value"]["value"]["kind"] != expected
                    ):
                        raise Rejected("discriminant association static value has the wrong type")
                    if strict and association["static_value"]["status"] != "known":
                        raise Rejected("strict discriminant static value is imprecise")
                    check_direct_literal_agreement(
                        association["expression"],
                        association["static_value"],
                        "discriminant association value",
                    )
        elif constraint["kind"] in {"digits", "delta"}:
            expression_name = "digits" if constraint["kind"] == "digits" else "delta"
            check_direct_literal_agreement(
                constraint[expression_name],
                constraint["static_value"],
                f"{constraint['kind']} value",
            )

    def check_type_ref(reference: dict[str, object]) -> None:
        if reference["declaration_id"] not in declarations:
            raise Rejected("unresolved type reference")
        target = next(
            item for item in document["declarations"]
            if item["stable_id"] == reference["declaration_id"]
        )
        check_constraint(reference["constraint"], "use_site", target)

    def expected_named_child(owner_id: str, name: str) -> str:
        owner_body, view = owner_id.rsplit("#", 1)
        return f"{owner_body}.{name.lower()}#{view}"

    def expected_static_kind(reference: dict[str, object]) -> str | None:
        declaration = next(
            item for item in document["declarations"]
            if item["stable_id"] == reference["declaration_id"]
        )
        if declaration["shape"]["kind"] == "array" and declaration["shape"]["rank"] == 1:
            component = next(
                item for item in document["declarations"]
                if item["stable_id"]
                == declaration["shape"]["component_type"]["declaration_id"]
            )
            if component["shape"]["kind"] == "character_scalar":
                return "text"
        return {
            "boolean_scalar": "boolean",
            "character_scalar": "decimal_integer",
            "enumeration": "decimal_integer",
            "signed_scalar": "decimal_integer",
            "modular_scalar": "decimal_integer",
            "floating_scalar": "exact_rational",
            "ordinary_fixed_scalar": "exact_rational",
            "decimal_fixed_scalar": "exact_rational",
        }.get(declaration["shape"]["kind"])

    def root_type_id(reference: dict[str, object]) -> str:
        current = reference["declaration_id"]
        seen: set[str] = set()
        while current not in seen:
            seen.add(current)
            declaration = next(
                (
                    item for item in document["declarations"]
                    if item["stable_id"] == current
                ),
                None,
            )
            if declaration is None:
                raise Rejected("base-subtype graph contains an unresolved reference")
            base = next(
                (
                    item for item in declaration["references"]
                    if item["role"] == "base_subtype"
                    and declaration["declaration_form"] == "subtype"
                ),
                None,
            )
            if base is None:
                return current
            current = base["target"]["declaration_id"]
        raise Rejected("base-subtype graph contains a cycle")

    def type_family_key(reference: dict[str, object]) -> str:
        return rooted_type_family_key(root_type_id(reference))

    for start in document["declarations"]:
        current = start
        seen: set[str] = set()
        while current["declaration_form"] in {"derived", "subtype"}:
            if current["stable_id"] in seen:
                raise Rejected("base-subtype and derivation graph contains a cycle")
            seen.add(current["stable_id"])
            base = next(
                (item for item in current["references"] if item["role"] == "base_subtype"),
                None,
            )
            if base is None:
                break
            current = next(
                (
                    item for item in document["declarations"]
                    if item["stable_id"] == base["target"]["declaration_id"]
                ),
                None,
            )
            if current is None:
                raise Rejected("base-subtype graph contains an unresolved reference")

    def check_default(default: dict[str, object], reference: dict[str, object]) -> None:
        if not default["present"]:
            return
        check_fact(default["staticness"])
        if strict and default["staticness"]["status"] != "known":
            raise Rejected("strict default staticness is imprecise")
        if default["staticness"]["status"] == "known":
            is_static = default["staticness"]["value"] == {
                "kind": "boolean",
                "value": True,
            }
            if is_static != (default["static_value"] is not None):
                raise Rejected("default static-value presence disagrees with staticness")
        if default["static_value"] is not None:
            check_fact(default["static_value"])
            if strict and default["static_value"]["status"] != "known":
                raise Rejected("strict static default value is imprecise")
            if default["static_value"]["status"] == "known":
                expected = expected_static_kind(reference)
                if expected is None or default["static_value"]["value"]["kind"] != expected:
                    raise Rejected("static default is incompatible with its resolved type")
            check_direct_literal_agreement(
                default["expression"], default["static_value"], "static default"
            )

    for declaration in document["declarations"]:
        if not declaration["stable_id"].endswith(f"#{declaration['view']}"):
            raise Rejected("declaration view and semantic ID suffix disagree")
        if declaration_name_from_id(declaration["stable_id"]) != declaration["canonical_name"]:
            raise Rejected("semantic ID and canonical declaration name disagree")
        if strict:
            if set(declaration["facts"]) != STRICT_DECLARATION_FACTS:
                raise Rejected("strict declaration is missing required core facts")
            for fact in declaration["facts"].values():
                if fact["status"] != "known":
                    raise Rejected("strict declaration fact is imprecise")
        related_ids = declaration["related_view_ids"]
        if related_ids != sorted(related_ids) or len(related_ids) != len(set(related_ids)):
            raise Rejected("related view IDs are not canonical")
        expected_related = sorted(
            item["stable_id"]
            for item in document["declarations"]
            if declaration_family_key(item["stable_id"])
            == declaration_family_key(declaration["stable_id"])
            and item["stable_id"] != declaration["stable_id"]
            and item["declaration_form"] != "class_wide"
            and declaration["declaration_form"] != "class_wide"
        )
        if related_ids != expected_related:
            raise Rejected("related_view_ids do not list every view")
        for related in related_ids:
            if related == declaration["stable_id"] or related not in declarations:
                raise Rejected("unresolved or self-related view")
            related_item = next(
                item for item in document["declarations"] if item["stable_id"] == related
            )
            if declaration_family_key(related_item["stable_id"]) != declaration_family_key(
                declaration["stable_id"]
            ):
                raise Rejected("related views have different canonical declarations")
            if declaration["stable_id"] not in related_item["related_view_ids"]:
                raise Rejected("related view links are not reciprocal")
        for reference in declaration["references"]:
            check_type_ref(reference["target"])
        reference_keys = [(item["role"], item["label"]) for item in declaration["references"]]
        if len(reference_keys) != len(set(reference_keys)):
            raise Rejected("declaration reference roles and labels must be unique")
        if declaration["references"] != sorted(
            declaration["references"],
            key=lambda item: (
                item["role"],
                item["label"] or "",
                item["target"]["declaration_id"],
                json.dumps(item["target"]["constraint"], sort_keys=True),
            ),
        ):
            raise Rejected("declaration references are not canonical")
        shape = declaration["shape"]
        form = declaration["declaration_form"]
        if form == "type" and shape["kind"] == "modular_scalar":
            modulus = shape["modulus"]
            scalar_range = shape["range"]
            if (
                modulus["status"] != "known"
                or scalar_range["static_low"]["status"] != "known"
                or scalar_range["static_high"]["status"] != "known"
                or scalar_range["static_low"]["value"]
                != {"kind": "decimal_integer", "value": "0"}
                or scalar_range["static_high"]["value"]
                != {
                    "kind": "decimal_integer",
                    "value": str(int(modulus["value"]["value"]) - 1),
                }
            ):
                raise Rejected("base modular range must be exactly 0 through modulus-1")
        if form == "type" and shape["kind"] == "boolean_scalar":
            scalar_range = shape["range"]
            if (
                scalar_range["static_low"]["status"] != "known"
                or scalar_range["static_low"]["value"]
                != {"kind": "boolean", "value": False}
                or scalar_range["static_high"]["status"] != "known"
                or scalar_range["static_high"]["value"]
                != {"kind": "boolean", "value": True}
            ):
                raise Rejected("base boolean range must be exactly False through True")
        can_name = declaration["view_access"]["consumer_can_name_components"]
        available = declaration["view_access"]["representation_available"]
        if (
            can_name["status"] == "known"
            and can_name["value"] == {"kind": "boolean", "value": True}
            and not (
                available["status"] == "known"
                and available["value"] == {"kind": "boolean", "value": True}
            )
        ):
            raise Rejected("component naming cannot exceed representation availability")
        if (
            context["accessibility_context"]["region"] == "public_spec"
            and declaration["view"] == "full"
            and can_name["status"] == "known"
            and can_name["value"] == {"kind": "boolean", "value": True}
            and any(
                item["view"] == "private" or item["declaration_form"] == "private"
                for item in document["declarations"]
                if item["stable_id"] in declaration["related_view_ids"]
            )
        ):
            raise Rejected("public-spec context cannot name a private completion's components")
        base_refs = [
            item for item in declaration["references"] if item["role"] == "base_subtype"
        ]
        if form in {"derived", "subtype"}:
            if len(base_refs) != 1:
                raise Rejected("derived and subtype declarations require one base-subtype edge")
            base = next(
                item for item in document["declarations"]
                if item["stable_id"] == base_refs[0]["target"]["declaration_id"]
            )
            if base_refs[0]["target"]["constraint"] != {"kind": "none"}:
                raise Rejected("base-subtype edge must be unconstrained")
            if base["shape"]["kind"] != shape["kind"]:
                raise Rejected("subtype/derived effective kind disagrees with base")
        elif base_refs:
            raise Rejected("only derived and subtype declarations may carry a base-subtype edge")
        parent_refs = [
            item for item in declaration["references"] if item["role"] == "parent_type"
        ]
        if form == "class_wide":
            if len(parent_refs) != 1:
                raise Rejected("class-wide declarations require exactly one parent-type edge")
            parent = next(
                item for item in document["declarations"]
                if item["stable_id"] == parent_refs[0]["target"]["declaration_id"]
            )
            if (
                parent_refs[0]["target"]["constraint"] != {"kind": "none"}
                or parent["view"] == "class_wide"
                or declaration_family_key(parent["stable_id"])
                != declaration_family_key(declaration["stable_id"])
                or parent["facts"]["tagged"]["status"] != "known"
                or parent["facts"]["tagged"]["value"] != {"kind": "boolean", "value": True}
            ):
                raise Rejected("class-wide parent must be an unconstrained tagged specific view")
        elif parent_refs:
            raise Rejected("only class-wide declarations may carry a parent-type edge")
        if form == "private" and not (
            shape == {"kind": "opaque", "reason": "private"}
            and declaration["view"] in {"public", "private"}
        ):
            raise Rejected("private declaration form requires a private opaque view")
        if form == "incomplete" and not (
            shape == {"kind": "opaque", "reason": "incomplete"}
            and declaration["view"] == "incomplete"
        ):
            raise Rejected("incomplete declaration form requires an incomplete opaque view")
        if form == "class_wide" and (
            shape != {"kind": "opaque", "reason": "class_wide"}
            or declaration["view"] != "class_wide"
        ):
            raise Rejected("class-wide declaration form requires a class-wide opaque shape")
        if form in {"derived", "subtype"} and shape["kind"] in {"interface", "opaque"}:
            raise Rejected("derived and subtype declarations must retain effective type shape")
        expected_core = {
            "class_wide": form == "class_wide",
            "task": shape == {"kind": "opaque", "reason": "task"},
            "protected": shape == {"kind": "opaque", "reason": "protected"},
        }
        if shape["kind"] in {
            "access", "boolean_scalar", "character_scalar", "decimal_fixed_scalar",
            "enumeration", "floating_scalar", "modular_scalar",
            "ordinary_fixed_scalar", "signed_scalar",
        }:
            expected_core["definite"] = True
        if form == "class_wide":
            expected_core["definite"] = False
            expected_core["tagged"] = True
        if shape in ({"kind": "opaque", "reason": "task"}, {"kind": "opaque", "reason": "protected"}):
            expected_core["limited"] = True
        if shape["kind"] == "interface":
            expected_core.update({"tagged": True, "abstract": True})
        if shape["kind"] == "access":
            expected_core["contains_access"] = True
        for fact_name, expected in expected_core.items():
            fact = declaration["facts"].get(fact_name)
            if fact is not None and fact["status"] == "known" and fact["value"] != {
                "kind": "boolean",
                "value": expected,
            }:
                raise Rejected(f"{fact_name} fact contradicts declaration form or shape")
        if (
            declaration["facts"]["abstract"]["status"] == "known"
            and declaration["facts"]["abstract"]["value"]
                == {"kind": "boolean", "value": True}
            and declaration["facts"]["tagged"]["status"] == "known"
            and declaration["facts"]["tagged"]["value"]
                != {"kind": "boolean", "value": True}
        ):
            raise Rejected("abstract type must be tagged")
        if shape["kind"] in {
            "boolean_scalar", "character_scalar", "decimal_fixed_scalar",
            "enumeration", "floating_scalar", "modular_scalar",
            "ordinary_fixed_scalar", "signed_scalar",
        } and shape["range"]["kind"] != "scalar_range":
            raise Rejected("concrete scalar requires an explicit effective range fact")
        contained_refs = []
        if shape["kind"] == "array":
            contained_refs.append(shape["component_type"])
            constrained = shape["constrained"]
            if constrained["status"] == "known":
                dimension_constraints = [
                    item["constraint"]["kind"] != "none"
                    for item in shape["dimensions"]
                ]
                if constrained["value"] == {"kind": "boolean", "value": True}:
                    if not all(dimension_constraints):
                        raise Rejected("constrained array has an unconstrained dimension")
                elif any(dimension_constraints):
                    raise Rejected("unconstrained array has a constrained dimension")
            if (
                constrained["status"] == "known"
                and declaration["facts"]["definite"]["status"] == "known"
                and constrained["value"]
                    != declaration["facts"]["definite"]["value"]
            ):
                raise Rejected("array constrainedness and definiteness disagree")
        elif shape["kind"] == "record":
            if shape["constraint"]["kind"] not in {"none", "discriminants"}:
                raise Rejected("record declaration constraint must be discriminants or none")
            check_constraint(shape["constraint"], {"declared_subtype", "inherited_base"}, declaration)
            contained_refs.extend(
                item["type"] for item in document["components"]
                if item["owner_id"] == declaration["stable_id"]
            )
            contained_refs.extend(
                item["type"] for item in document["discriminants"]
                if item["owner_id"] == declaration["stable_id"]
            )
        for reference in contained_refs:
            child = next(
                item for item in document["declarations"]
                if item["stable_id"] == reference["declaration_id"]
            )
            implications = {
                "contains_access": child["shape"]["kind"] == "access"
                    or child["facts"]["contains_access"].get("value")
                       == {"kind": "boolean", "value": True},
                "contains_controlled": child["facts"]["controlled"].get("value")
                    == {"kind": "boolean", "value": True}
                    or child["facts"]["contains_controlled"].get("value")
                       == {"kind": "boolean", "value": True},
                "limited": child["facts"]["limited"].get("value")
                    == {"kind": "boolean", "value": True},
            }
            for fact_name, implied in implications.items():
                owner_fact = declaration["facts"][fact_name]
                if implied and owner_fact["status"] == "known" and owner_fact["value"] != {
                    "kind": "boolean", "value": True,
                }:
                    raise Rejected(f"contained type contradicts owner {fact_name} fact")
            child_definite = child["facts"]["definite"]
            owner_definite = declaration["facts"]["definite"]
            if (
                reference["constraint"] == {"kind": "none"}
                and
                child_definite["status"] == "known"
                and child_definite["value"] == {"kind": "boolean", "value": False}
                and owner_definite["status"] == "known"
                and owner_definite["value"] != {"kind": "boolean", "value": False}
            ):
                raise Rejected("indefinite contained type contradicts owner definiteness")
        for fact_name in ("modulus", "digits"):
            fact = shape.get(fact_name)
            if fact is not None and fact["status"] == "known" and int(fact["value"]["value"]) <= 0:
                raise Rejected(f"{fact_name} must be positive")
        for fact_name in ("delta", "small"):
            fact = shape.get(fact_name)
            if fact is not None and fact["status"] == "known" and int(fact["value"]["value"]["numerator"]) <= 0:
                raise Rejected(f"{fact_name} must be positive")
        if shape["kind"] in {"floating_scalar", "decimal_fixed_scalar"}:
            if shape["digits_constraint"]["kind"] != "digits":
                raise Rejected("digits provenance must use a digits constraint")
            check_constraint(shape["digits_constraint"], {"declared_subtype", "inherited_base"}, declaration)
        if shape["kind"] in {"ordinary_fixed_scalar", "decimal_fixed_scalar"}:
            if shape["delta_constraint"]["kind"] != "delta":
                raise Rejected("delta provenance must use a delta constraint")
            check_constraint(shape["delta_constraint"], {"declared_subtype", "inherited_base"}, declaration)
        check_constraint(
            shape.get("range", {"kind": "none"}),
            {"declared_subtype", "inherited_base"},
            declaration,
        )
        if "predicate" in shape and fact_semantic_key(shape["predicate"]) != fact_semantic_key(
            shape["range"]["predicate"]
        ):
            raise Rejected("shape predicate contradicts effective range predicate")
        if shape["kind"] in {"floating_scalar", "decimal_fixed_scalar"} and fact_semantic_key(
            shape["digits"]
        ) != fact_semantic_key(shape["digits_constraint"]["static_value"]):
            raise Rejected("digits fact contradicts digits constraint")
        if shape["kind"] in {"ordinary_fixed_scalar", "decimal_fixed_scalar"}:
            if fact_semantic_key(shape["delta"]) != fact_semantic_key(
                shape["delta_constraint"]["static_value"]
            ):
                raise Rejected("delta fact contradicts delta constraint")
            if fact_semantic_key(shape["small"]) != fact_semantic_key(
                shape["delta_constraint"]["small"]
            ):
                raise Rejected("small fact contradicts delta constraint")
        if shape["kind"] == "array":
            if shape["rank"] != len(shape["dimensions"]):
                raise Rejected("array rank and dimensions disagree")
            if [item["position"] for item in shape["dimensions"]] != list(
                range(1, shape["rank"] + 1)
            ):
                raise Rejected("array dimension positions are not dense from one")
            check_type_ref(shape["component_type"])
            for dimension in shape["dimensions"]:
                check_type_ref(dimension["index_subtype"])
                dimension_target = next(
                    item for item in document["declarations"]
                    if item["stable_id"] == dimension["index_subtype"]["declaration_id"]
                )
                if dimension_target["shape"]["kind"] not in {
                    "boolean_scalar", "character_scalar", "enumeration",
                    "modular_scalar", "signed_scalar",
                }:
                    raise Rejected("array index subtype is not discrete")
                check_constraint(
                    dimension["constraint"],
                    {"declared_subtype", "inherited_base"},
                    dimension_target,
                )
        elif shape["kind"] == "access":
            check_type_ref(shape["designated_subtype"])
    for component in document["components"]:
        if component["owner_id"] not in declarations:
            raise Rejected("unresolved component owner")
        owner = next(
            item for item in document["declarations"]
            if item["stable_id"] == component["owner_id"]
        )
        if owner["shape"]["kind"] != "record":
            raise Rejected("component owner is not a record")
        check_type_ref(component["type"])
        check_default(component["default"], component["type"])
        if component["stable_id"] != expected_named_child(
            component["owner_id"], component["canonical_name"]
        ):
            raise Rejected("component ID does not encode owner and canonical name")
        if not set(component["variant_path"]).issubset(alternatives):
            raise Rejected("unresolved variant path")
    for discriminant in document["discriminants"]:
        if discriminant["owner_id"] not in declarations:
            raise Rejected("unresolved discriminant owner")
        owner = next(
            item for item in document["declarations"]
            if item["stable_id"] == discriminant["owner_id"]
        )
        if owner["shape"]["kind"] != "record":
            raise Rejected("discriminant owner is not a record")
        check_type_ref(discriminant["type"])
        check_default(discriminant["default"], discriminant["type"])
        if discriminant["stable_id"] != expected_named_child(
            discriminant["owner_id"], discriminant["canonical_name"]
        ):
            raise Rejected("discriminant ID does not encode owner and canonical name")
    for entity in document["entities"]:
        if entity["type"] is not None:
            check_type_ref(entity["type"])
        typed_entity = entity["entity_kind"] == "object" or (
            entity["entity_kind"] == "generic_formal"
            and entity["formal_kind"] == "object"
        )
        if typed_entity != (entity["type"] is not None):
            raise Rejected("object/value entity type presence is inconsistent")
        callable_entity = entity["entity_kind"] == "subprogram" or (
            entity["entity_kind"] == "generic_formal"
            and entity["formal_kind"] == "subprogram"
        )
        if callable_entity != (entity["callable_profile"] is not None):
            raise Rejected("callable profile presence disagrees with entity kind")
        if entity["callable_profile"] is not None:
            profile = entity["callable_profile"]
            if [item["position"] for item in profile["parameters"]] != list(
                range(len(profile["parameters"]))
            ):
                raise Rejected("callable parameters must be in dense semantic order")
            for parameter in profile["parameters"]:
                check_type_ref(parameter["type"])
                if parameter["type"]["constraint"] != {"kind": "none"}:
                    raise Rejected("v1 callable profile types must be unconstrained graph refs")
            if profile["result"] is not None:
                check_type_ref(profile["result"])
                if profile["result"]["constraint"] != {"kind": "none"}:
                    raise Rejected("v1 callable result must be an unconstrained graph ref")
        object_formal = entity["entity_kind"] == "generic_formal" and entity["formal_kind"] == "object"
        if object_formal != (entity["object_mode"] is not None):
            raise Rejected("generic formal object mode presence is inconsistent")
        package_formal = entity["entity_kind"] == "generic_formal" and entity["formal_kind"] == "package"
        if package_formal != (entity["formal_template_id"] is not None):
            raise Rejected("generic formal package template edge is inconsistent")
        if package_formal != (entity["formal_package_contract"] == "box_only"):
            raise Rejected("v1 generic package formals must use the box-only contract")
        if entity["formal_template_id"] is not None:
            template = entity_by_id.get(entity["formal_template_id"])
            if template is None or template["entity_kind"] != "generic_template":
                raise Rejected("generic formal package template does not resolve")
        type_formal = entity["entity_kind"] == "generic_formal" and entity["formal_kind"] == "type"
        if type_formal != (entity["formal_type_contract"] is not None):
            raise Rejected("generic formal type contract presence is inconsistent")
    for literal in document["enum_literals"]:
        owner = next(
            (item for item in document["declarations"] if item["stable_id"] == literal["owner_id"]),
            None,
        )
        if owner is None or owner["shape"]["kind"] != "enumeration":
            raise Rejected("enum literal owner is not an enumeration")
        if literal["position"] != str(literal["declaration_order"]):
            raise Rejected("enum literal position disagrees with semantic order")
        if literal["stable_id"] != expected_named_child(
            literal["owner_id"], literal["canonical_name"]
        ):
            raise Rejected("enum literal ID does not encode owner and canonical name")
    for declaration in document["declarations"]:
        if declaration["shape"]["kind"] == "enumeration":
            owned = sorted(
                (
                    item
                    for item in document["enum_literals"]
                    if item["owner_id"] == declaration["stable_id"]
                ),
                key=lambda item: item["declaration_order"],
            )
            if declaration["shape"]["literal_ids"] != [item["stable_id"] for item in owned]:
                raise Rejected("enumeration literal membership is not exact")
            if declaration["declaration_form"] == "type":
                if not owned:
                    raise Rejected("a base enumeration requires at least one literal")
                effective_range = declaration["shape"]["range"]
                if any(
                    effective_range[name]["status"] != "known"
                    or effective_range[name]["value"]
                    != {"kind": "decimal_integer", "value": expected}
                    for name, expected in (("static_low", "0"), ("static_high", str(len(owned) - 1)))
                ):
                    raise Rejected("base enumeration range must be exactly 0 through N-1")
    all_ids = ids
    expression_ids = {
        item["stable_id"]
        for table_name in (
            "components", "declarations", "discriminants", "entities",
            "enum_literals",
        )
        for item in document[table_name]
    }
    annotation_target_ids = {
        item["stable_id"]
        for table_name in (
            "components", "declarations", "discriminants", "entities", "enum_literals",
        )
        for item in document[table_name]
    }
    for annotation in document["annotations"]:
        if annotation["target_id"] not in annotation_target_ids:
            raise Rejected("annotation target is not an Ada declaration or entity")
        if not annotation["arguments"] and annotation["expression_syntax"] is None:
            raise Rejected("annotation requires typed arguments or retained expression text")
    if document["annotations"] != sorted(
        document["annotations"],
        key=lambda item: (
            item["target_id"], item["namespace"], item["action"],
            item["declaration_order"],
        ),
    ):
        raise Rejected("annotations are not in canonical target/namespace/action order")
    bindings_by_instance: dict[str, list[tuple[str, str]]] = {}
    for entity in document["entities"]:
        if entity["entity_kind"] == "generic_formal":
            if entity["formal_kind"] is None:
                raise Rejected("generic formal requires an exact formal kind")
            if entity["formal_kind"] == "value":
                raise Rejected("Ada value actuals bind object formals; value is not a formal kind")
            owner = entity_by_id.get(entity["owner_id"])
            if owner is None or owner["entity_kind"] != "generic_template":
                raise Rejected("generic formal owner must be its template")
            if not entity["canonical_name"].startswith(owner["canonical_name"] + "."):
                raise Rejected("generic formal canonical name is outside its template")
            if entity["formal_kind"] == "object" and entity["type"] is None:
                raise Rejected("object generic formals require a resolved type")
        elif entity["formal_kind"] is not None:
            raise Rejected("only generic formals may carry formal_kind")
        if entity["entity_kind"] != "generic_formal":
            enclosing = sorted(
                (
                    candidate
                    for candidate in document["entities"]
                    if candidate["entity_kind"] == "package"
                    and candidate["stable_id"] != entity["stable_id"]
                    and entity["canonical_name"].startswith(
                        candidate["canonical_name"] + "."
                    )
                ),
                key=lambda candidate: len(candidate["canonical_name"]),
            )
            expected_owner = enclosing[-1]["stable_id"] if enclosing else None
            if entity["owner_id"] != expected_owner:
                raise Rejected("entity owner must be the longest enclosing package instance")
    for actual in document["generic_actuals"]:
        instance = entity_by_id.get(actual["instance_id"])
        if instance is not None:
            bindings_by_instance.setdefault(instance["canonical_name"], []).append(
                (actual["formal_canonical_name"], actual["stable_id"])
            )

    def expanded_name(name: str, include_self: bool) -> str:
        insertions: dict[int, str] = {}
        for instance_name, bindings in bindings_by_instance.items():
            if name.startswith(instance_name + ".") or (
                include_self and name == instance_name
            ):
                if bindings != sorted(bindings):
                    raise Rejected("generic identity bindings are not sorted by formal name")
                insertions[len(instance_name)] = "[" + ",".join(
                    f"{formal_name}={actual_id}"
                    for formal_name, actual_id in bindings
                ) + "]"
        return "".join(
            character + insertions.get(index, "")
            for index, character in enumerate(name, start=1)
        )

    for actual in document["generic_actuals"]:
        formal = entity_by_id.get(actual["formal_id"])
        instance = entity_by_id.get(actual["instance_id"])
        template = entity_by_id.get(actual["template_id"])
        if formal is None or formal["entity_kind"] != "generic_formal":
            raise Rejected("generic formal is not a generic-formal entity")
        if instance is None or instance["entity_kind"] != "package":
            raise Rejected("generic instance is not a package entity")
        if template is None or template["entity_kind"] != "generic_template":
            raise Rejected("generic template does not resolve")
        if instance["instantiated_template_id"] != actual["template_id"]:
            raise Rejected("generic instance points to a different template")
        if formal["owner_id"] != actual["template_id"]:
            raise Rejected("generic formal belongs to a different template")
        if formal["declaration_order"] != actual["declaration_order"]:
            raise Rejected("generic actual does not preserve formal order")
        kind_matches = (
            formal["formal_kind"] == "object"
            and (
                (actual["kind"] == "value" and formal["object_mode"] == "in")
                or (actual["kind"] == "object" and formal["object_mode"] == "in_out")
            )
        ) or (
            formal["formal_kind"] != "object"
            and formal["formal_kind"] == actual["kind"]
        )
        if not kind_matches:
            raise Rejected("generic actual kind is inadmissible for its formal")
        if formal["canonical_name"].rsplit(".", 1)[-1] != actual["formal_canonical_name"]:
            raise Rejected("generic actual name disagrees with its formal")
        if actual["kind"] == "type":
            check_type_ref(actual["value"])
            if actual["value"]["constraint"] != {"kind": "none"}:
                raise Rejected("constrained generic type actual is unsupported in v1 identity")
            identity_value = actual["value"]["declaration_id"] + ",constraint=none"
        elif actual["kind"] in {"package", "subprogram"}:
            value_entity = entity_by_id.get(actual["value_id"])
            if value_entity is None or value_entity["entity_kind"] != actual["kind"]:
                raise Rejected("generic declaration actual has the wrong entity kind")
            identity_value = actual["value_id"]
        elif actual["kind"] == "object":
            value_entity = entity_by_id.get(actual["value_id"])
            if value_entity is None or value_entity["entity_kind"] != "object":
                raise Rejected("generic object actual does not resolve to an object")
            if type_family_key(value_entity["type"]) != type_family_key(formal["type"]):
                raise Rejected("generic object actual type does not conform to its formal")
            identity_value = f"object:{actual['value_id']}"
        else:
            fact = actual["value"]
            if fact["status"] != "known":
                raise Rejected("imprecise generic value actual has no v1 stable identity")
            expected = expected_static_kind(formal["type"])
            if expected is None or fact["value"]["kind"] != expected:
                raise Rejected("generic scalar actual is incompatible with formal type")
            typed = fact["value"]
            if typed["kind"] == "boolean":
                identity_value = "true" if typed["value"] else "false"
            elif typed["kind"] == "decimal_integer":
                identity_value = typed["value"]
            elif typed["kind"] == "exact_rational":
                identity_value = (
                    f"rat:{typed['value']['numerator']}:"
                    f"{typed['value']['denominator']}"
                )
            elif typed["kind"] == "text":
                identity_value = "text:x" + "".join(
                    f"%{byte:02x}" for byte in typed["value"].encode("utf-8")
                )
            else:
                raise Rejected("expression-valued generic actual has no v1 stable identity")
        if actual["kind"] == "subprogram":
            value_entity = entity_by_id[actual["value_id"]]
            actual_profile = value_entity["callable_profile"]
            formal_profile = formal["callable_profile"]
            if (
                len(actual_profile["parameters"]) != len(formal_profile["parameters"])
                or any(
                    actual_parameter["mode"] != formal_parameter["mode"]
                    or type_family_key(actual_parameter["type"])
                    != type_family_key(formal_parameter["type"])
                    for actual_parameter, formal_parameter in zip(
                        actual_profile["parameters"], formal_profile["parameters"]
                    )
                )
                or (actual_profile["result"] is None)
                    != (formal_profile["result"] is None)
                or (
                    actual_profile["result"] is not None
                    and type_family_key(actual_profile["result"])
                    != type_family_key(formal_profile["result"])
                )
            ):
                raise Rejected("generic subprogram actual profile does not conform")
        if actual["kind"] == "package":
            value_entity = entity_by_id[actual["value_id"]]
            if value_entity["instantiated_template_id"] != formal["formal_template_id"]:
                raise Rejected("generic package actual instantiates the wrong template")
        if actual["kind"] == "type":
            target = next(
                item for item in document["declarations"]
                if item["stable_id"] == root_type_id(actual["value"])
            )
            if formal["formal_type_contract"] == "signed_integer_range" and target["shape"]["kind"] != "signed_scalar":
                raise Rejected("generic type actual does not satisfy the formal type contract")
        expected_actual_id = (
            f"decl:{expanded_name(instance['canonical_name'], include_self=False)}"
            f".actual.{actual['formal_canonical_name']}"
            f"[value={identity_value}]#public"
        )
        if actual["stable_id"] != expected_actual_id:
            raise Rejected("generic actual stable ID does not encode its exact binding")

    for instance in document["entities"]:
        template_id = instance["instantiated_template_id"]
        if template_id is None:
            continue
        if instance["entity_kind"] != "package":
            raise Rejected("only packages may instantiate generic templates")
        formals = [
            item
            for item in document["entities"]
            if item["entity_kind"] == "generic_formal" and item["owner_id"] == template_id
        ]
        for formal in formals:
            matches = [
                item
                for item in document["generic_actuals"]
                if item["instance_id"] == instance["stable_id"]
                and item["formal_id"] == formal["stable_id"]
            ]
            if len(matches) != 1:
                raise Rejected("each generic formal requires exactly one actual")

    for declaration in document["declarations"]:
        body = expanded_name(declaration["canonical_name"], include_self=True)
        expected_id = f"decl:{body}#{declaration['view']}"
        if declaration["stable_id"] != expected_id:
            raise Rejected("declaration ID does not exactly encode its generic bindings and view")
    for entity in document["entities"]:
        profile = entity["callable_profile"]
        profile_suffix = ""
        if profile is not None:
            parameters = ",".join(
                f"{item['position']}:{item['mode']}:{item['canonical_name']}:"
                f"{item['type']['declaration_id']}"
                for item in profile["parameters"]
            )
            result = "none" if profile["result"] is None else profile["result"]["declaration_id"]
            profile_suffix = f"[profile={parameters},result={result}]"
        elif entity["object_mode"] is not None:
            profile_suffix = (
                f"[object={entity['object_mode']},"
                f"type={entity['type']['declaration_id']}]"
            )
        expected_id = f"decl:{expanded_name(entity['canonical_name'], include_self=True)}{profile_suffix}#public"
        if entity["stable_id"] != expected_id:
            raise Rejected("entity ID does not exactly encode its generic binding chain")
    for variant in document["variants"]:
        if not variant["alternatives"]:
            raise Rejected("variant part requires at least one alternative")
        if variant["parent_alternative_id"] is None and sum(
            1 for item in document["variants"]
            if item["owner_id"] == variant["owner_id"]
            and item["parent_alternative_id"] is None
        ) != 1:
            raise Rejected("record owner may have only one root variant part")
        if variant["owner_id"] not in declarations:
            raise Rejected("unresolved variant owner")
        if variant["selector_discriminant_id"] not in discriminants:
            raise Rejected("unresolved variant selector")
        selector = next(
            item
            for item in document["discriminants"]
            if item["stable_id"] == variant["selector_discriminant_id"]
        )
        if selector["owner_id"] != variant["owner_id"]:
            raise Rejected("variant selector has a different owner")
        others_seen = False
        seen_choice_keys: set[str] = set()
        alternative_keys = [
            alternative_semantic_key(item)
            for item in variant["alternatives"]
        ]
        if len(alternative_keys) != len(set(alternative_keys)):
            raise Rejected("variant alternatives have duplicate semantic choice sets")
        if variant["alternatives"] != sorted(
            variant["alternatives"],
            key=alternative_semantic_key,
        ):
            raise Rejected("variant alternatives are not in canonical choice order")
        if sorted(item["declaration_order"] for item in variant["alternatives"]) != list(
            range(len(variant["alternatives"]))
        ):
            raise Rejected("variant alternative order is not dense and unique")
        for alternative in variant["alternatives"]:
            if (
                alternative["component_ids"] != sorted(alternative["component_ids"])
                or len(alternative["component_ids"])
                != len(set(alternative["component_ids"]))
            ):
                raise Rejected("variant component IDs are not canonical")
            if alternative["choices"] != sorted(
                alternative["choices"],
                key=choice_semantic_key,
            ):
                raise Rejected("variant choices are not canonical")
            for choice in alternative["choices"]:
                choice_key = choice_semantic_key(choice)
                if choice_key in seen_choice_keys:
                    raise Rejected("variant contains a duplicate semantic choice")
                seen_choice_keys.add(choice_key)
                if choice["kind"] == "name":
                    target_id = choice["resolved_declaration_id"]
                    target_entity = entity_by_id.get(target_id)
                    if target_entity is not None and (
                        target_entity["entity_kind"] == "object"
                        or (
                            target_entity["entity_kind"] == "generic_formal"
                            and target_entity["formal_kind"] == "object"
                        )
                    ):
                        target_family = type_family_key(target_entity["type"])
                    else:
                        target_literal = next(
                            (item for item in document["enum_literals"] if item["stable_id"] == target_id),
                            None,
                        )
                        target_family = (
                            type_family_key({"declaration_id": target_literal["owner_id"]})
                            if target_literal is not None else None
                        )
                        if (
                            target_literal is not None
                            and choice["static_value"]["status"] == "known"
                            and choice["static_value"]["value"]
                            != {"kind": "decimal_integer", "value": target_literal["position"]}
                        ):
                            raise Rejected(
                                "enum name choice value does not equal its literal position"
                            )
                    if target_family is None:
                        raise Rejected("name choice must resolve to a value-denoting entity or enum literal")
                    if target_family != type_family_key(selector["type"]):
                        raise Rejected("name choice resolved value has the wrong selector type")
                if choice["kind"] == "subtype":
                    check_type_ref(choice["resolved_subtype"])
                    selector_type = next(
                        item for item in document["declarations"]
                        if item["stable_id"] == selector["type"]["declaration_id"]
                    )
                    subtype = next(
                        item for item in document["declarations"]
                        if item["stable_id"]
                        == choice["resolved_subtype"]["declaration_id"]
                    )
                    effective = (
                        choice["resolved_subtype"]["constraint"]
                        if choice["resolved_subtype"]["constraint"]["kind"] != "none"
                        else subtype["shape"]["range"]
                    )
                    if (
                        subtype["shape"]["kind"] != selector_type["shape"]["kind"]
                        or type_family_key(choice["resolved_subtype"])
                        != type_family_key(selector["type"])
                    ):
                        raise Rejected("subtype choice is incompatible with its selector")
                    if effective["kind"] != "scalar_range" or any(
                        effective[name]["status"] != "known"
                        for name in ("staticness", "static_low", "static_high")
                    ) or effective["staticness"]["value"] != {
                        "kind": "boolean", "value": True,
                    }:
                        raise Rejected("subtype choice requires one exact resolved static range")
                expected = expected_static_kind(selector["type"])
                fact_names = (
                    ("static_low", "static_high")
                    if choice["kind"] == "range"
                    else (("static_value",) if choice["kind"] in {"expression", "name"} else ())
                )
                for fact_name in fact_names:
                    fact = choice[fact_name]
                    if fact["status"] == "known" and (
                        expected is None or fact["value"]["kind"] != expected
                    ):
                        raise Rejected("variant choice static value has the wrong selector type")
                if choice["kind"] == "expression":
                    check_direct_literal_agreement(
                        choice["expression"], choice["static_value"],
                        "variant expression choice",
                    )
                elif choice["kind"] == "range":
                    check_direct_literal_agreement(
                        choice["low"], choice["static_low"], "variant range low"
                    )
                    check_direct_literal_agreement(
                        choice["high"], choice["static_high"], "variant range high"
                    )
            if not set(alternative["component_ids"]).issubset(components):
                raise Rejected("unresolved variant component")
            others = [choice for choice in alternative["choices"] if choice["kind"] == "others"]
            if others and (others_seen or len(alternative["choices"]) != 1):
                raise Rejected("invalid others choice")
            others_seen = others_seen or bool(others)
            for component_id in alternative["component_ids"]:
                component = next(
                    item for item in document["components"] if item["stable_id"] == component_id
                )
                if component["owner_id"] != variant["owner_id"]:
                    raise Rejected("variant component has a different owner")
                if alternative["stable_id"] not in component["variant_path"]:
                    raise Rejected("variant/component membership is not reciprocal")
            nested_id = alternative["nested_variant_id"]
            if nested_id is not None:
                nested = next(
                    (item for item in document["variants"] if item["stable_id"] == nested_id),
                    None,
                )
                if nested is None:
                    raise Rejected("nested variant does not resolve")
                if nested["parent_alternative_id"] != alternative["stable_id"]:
                    raise Rejected("nested variant parent link is inconsistent")
                if nested["owner_id"] != variant["owner_id"]:
                    raise Rejected("nested variant owner is inconsistent")

        parent_id = variant["parent_alternative_id"]
        if parent_id is not None:
            parent = next(
                (
                    alternative
                    for candidate in document["variants"]
                    for alternative in candidate["alternatives"]
                    if alternative["stable_id"] == parent_id
                ),
                None,
            )
            if parent is None or parent["nested_variant_id"] != variant["stable_id"]:
                raise Rejected("variant parent link is not reciprocal")

    variant_by_id = {item["stable_id"]: item for item in document["variants"]}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit_variant(variant_id: str) -> None:
        if variant_id in visiting:
            raise Rejected("variant nesting contains a cycle")
        if variant_id in visited:
            return
        visiting.add(variant_id)
        for alternative in variant_by_id[variant_id]["alternatives"]:
            nested_id = alternative["nested_variant_id"]
            if nested_id is not None:
                visit_variant(nested_id)
        visiting.remove(variant_id)
        visited.add(variant_id)

    for variant_id in variant_by_id:
        visit_variant(variant_id)

    for variant in document["variants"]:
        selector = next(
            item
            for item in document["discriminants"]
            if item["stable_id"] == variant["selector_discriminant_id"]
        )
        if variant["parent_alternative_id"] is None:
            prefix_id = variant["owner_id"]
        else:
            prefix_id = variant["parent_alternative_id"]
        prefix_body, view = prefix_id.rsplit("#", 1)
        expected_variant_id = (
            f"{prefix_body}.variant.{selector['canonical_name']}#{view}"
        )
        if variant["stable_id"] != expected_variant_id:
            raise Rejected("variant ID does not encode owner path and selector")
        variant_body = variant["stable_id"].rsplit("#", 1)[0]
        for index, alternative in enumerate(variant["alternatives"]):
            expected_alternative_id = (
                f"{variant_body}.alternative.{index}#{view}"
            )
            if alternative["stable_id"] != expected_alternative_id:
                raise Rejected("alternative ID does not encode canonical choice rank")

    alternative_map = {
        alternative["stable_id"]: alternative
        for variant in document["variants"]
        for alternative in variant["alternatives"]
    }
    variant_for_alternative = {
        alternative["stable_id"]: variant
        for variant in document["variants"]
        for alternative in variant["alternatives"]
    }
    for component in document["components"]:
        if len(component["variant_path"]) != len(set(component["variant_path"])):
            raise Rejected("variant path contains duplicates")
        for index, alternative_id in enumerate(component["variant_path"]):
            if component["stable_id"] not in alternative_map[alternative_id]["component_ids"]:
                raise Rejected("component/variant membership is not reciprocal")
            variant = variant_for_alternative[alternative_id]
            if variant["owner_id"] != component["owner_id"]:
                raise Rejected("component variant path crosses owners")
            expected_parent = None if index == 0 else component["variant_path"][index - 1]
            if variant["parent_alternative_id"] != expected_parent:
                raise Rejected("variant path is not an exact ordered ancestor chain")

    def check_graph_nodes(value: object) -> None:
        if isinstance(value, dict):
            if value.get("kind") in {
                "attribute", "binary", "boolean_literal", "character_literal",
                "decimal_literal", "declaration_ref", "function_call",
                "indexed_component", "integer_literal", "qualified",
                "selected_component", "string_literal", "type_conversion",
                "unary", "unsupported",
            }:
                expression_semantic_key(value)
            if set(value) == {"constraint", "declaration_id"}:
                check_type_ref(value)
            if value.get("kind") == "declaration_ref":
                if value["declaration_id"] not in expression_ids:
                    raise Rejected("unresolved expression declaration")
            if value.get("kind") == "character_literal":
                target = next(
                    (
                        item for item in document["declarations"]
                        if item["stable_id"] == value["resolved_type_id"]
                    ),
                    None,
                )
                if (
                    target is None
                    or target["shape"]["kind"] != "character_scalar"
                    or root_type_id({"declaration_id": value["resolved_type_id"]})
                    not in {
                        "decl:standard.character#public",
                        "decl:standard.wide_character#public",
                        "decl:standard.wide_wide_character#public",
                    }
                ):
                    raise Rejected(
                        "v1 character literal must resolve through a predefined Standard character type"
                    )
            if value.get("kind") == "function_call":
                target = entity_by_id.get(value["resolved_subprogram_id"])
                if (
                    target is None
                    or target["entity_kind"] != "subprogram"
                    or target["callable_profile"]["result"] is None
                ):
                    raise Rejected("expression call target must be a resolved function")
            if value.get("kind") == "unary" and any(
                value[name] not in declarations
                for name in ("operand_type_id", "result_type_id")
            ):
                raise Rejected("predefined unary operator type edge is unresolved")
            if value.get("kind") in {"unary", "binary"} and value.get(
                "operator_resolution"
            ) != "predefined":
                raise Rejected("v1 rejects user-defined operator resolution")
            if value.get("kind") == "binary" and any(
                value[name] not in declarations
                for name in ("left_type_id", "right_type_id", "result_type_id")
            ):
                raise Rejected("predefined binary operator type edge is unresolved")
            if value.get("kind") == "selected_component" and value["selector_id"] not in expression_ids:
                raise Rejected("unresolved selected component")
            if strict and value.get("kind") == "unsupported":
                raise Rejected("strict consumer rejects unsupported expression AST nodes")
            for child in value.values():
                check_graph_nodes(child)
        elif isinstance(value, list):
            for child in value:
                check_graph_nodes(child)

    semantic_document = {
        key: value for key, value in document.items() if key != "extensions"
    }
    check_graph_nodes(semantic_document)

    def check_dense(table_name: str, owner_name: str) -> None:
        groups: dict[str, list[int]] = {}
        for item in document[table_name]:
            groups.setdefault(item[owner_name], []).append(item["declaration_order"])
        for orders in groups.values():
            if sorted(orders) != list(range(len(orders))):
                raise Rejected(f"{table_name} declaration order is not dense and unique")

    check_dense("components", "owner_id")
    check_dense("discriminants", "owner_id")
    check_dense("enum_literals", "owner_id")
    check_dense("generic_actuals", "instance_id")
    check_dense("annotations", "target_id")
    formal_orders: dict[str, list[int]] = {}
    for entity in document["entities"]:
        if entity["entity_kind"] == "generic_formal":
            formal_orders.setdefault(entity["owner_id"], []).append(entity["declaration_order"])
    if any(sorted(orders) != list(range(len(orders))) for orders in formal_orders.values()):
        raise Rejected("generic formal order is not dense and unique per template")

    walk_facts(semantic_document, strict)

    def check_decimals(value: object, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                check_decimals(child, child_key)
        elif isinstance(value, list):
            for child in value:
                check_decimals(child, key)
        elif key in {"denominator", "modulus", "numerator"}:
            if not isinstance(value, str) or not DECIMAL.fullmatch(value):
                raise Rejected(f"noncanonical decimal string at {key}")

    check_decimals(semantic_document)

    def check_rationals(value: object) -> None:
        if isinstance(value, dict):
            if set(value) == {"denominator", "numerator"}:
                numerator = int(value["numerator"])
                denominator = int(value["denominator"])
                if denominator <= 0 or math.gcd(abs(numerator), denominator) != 1:
                    raise Rejected("exact rational is not normalized")
            for child in value.values():
                check_rationals(child)
        elif isinstance(value, list):
            for child in value:
                check_rationals(child)

    check_rationals(semantic_document)


def _checked_bytes(
    raw: bytes, profile: str, *, extraction_authority: object | None = None
) -> CheckedDocument:
    """Validate retained bytes; document callers cannot assert extraction trust."""
    if profile not in {"structural", "strict", "fixture_shape"}:
        raise ValueError(f"unknown validation profile: {profile}")
    document = parse(raw)
    validate_schema(document, SCHEMA)
    validate(
        document,
        strict=profile in {"strict", "fixture_shape"},
        allow_fixture=profile == "fixture_shape",
        extraction_authority=extraction_authority,
    )
    projection = semantic_projection(document)
    return CheckedDocument(
        document=freeze(document),
        semantic_projection=projection,
        semantic_fingerprint=hashlib.sha256(projection).hexdigest(),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        profile=profile,
    )


def load_checked(path: Path, profile: str) -> CheckedDocument:
    """Read once, validate, and return that exact model plus its semantic digest.

    ``fixture_shape`` is test-only: it applies every Strict_Consumer semantic
    check while admitting synthetic fixture provenance. ``strict`` is the
    production gate and currently admits no extraction document.
    """
    raw = path.read_bytes()
    return _checked_bytes(raw, profile)

def expect_rejected(name: str, operation) -> None:
    global REJECTION_COUNT
    try:
        operation()
    except (Rejected, json.JSONDecodeError):
        REJECTION_COUNT += 1
        return
    raise AssertionError(f"negative mutant accepted: {name}")


def main() -> None:
    if int("1" * 5_000) <= 0:
        raise AssertionError("arbitrary-precision decimal validation is capped")
    positive = sorted(path for path in FIXTURES.glob("*.json"))
    documents = {
        path.name: thaw(load_checked(path, "structural").document)
        for path in positive
    }
    typed_document = thaw(
        load_checked(FIXTURES / "typed-shapes.json", "fixture_shape").document
    )
    covered_shapes = {item["shape"]["kind"] for item in typed_document["declarations"]}
    required_shape_coverage = {
        "access", "array", "boolean_scalar", "character_scalar",
        "decimal_fixed_scalar", "enumeration", "floating_scalar", "interface",
        "modular_scalar", "ordinary_fixed_scalar", "record", "signed_scalar",
    }
    if not required_shape_coverage.issubset(covered_shapes):
        raise AssertionError("typed-shapes fixture no longer covers every concrete v1 shape")
    use_site_kinds = {
        item["type"]["constraint"]["kind"] for item in typed_document["components"]
    }
    if not {"array_indices", "discriminants"}.issubset(use_site_kinds):
        raise AssertionError("typed-shapes fixture lost structural use-site constraints")
    view_forms = {
        item["declaration_form"]
        for item in documents["public-private-full-views.json"]["declarations"]
    }
    if not {"class_wide", "incomplete", "private", "type"}.issubset(view_forms):
        raise AssertionError("view fixture lost an explicit declaration/view form")
    choice_kinds = {
        choice["kind"]
        for variant in documents["exact-variant-ast.json"]["variants"]
        for alternative in variant["alternatives"]
        for choice in alternative["choices"]
    }
    if choice_kinds != {"expression", "name", "others", "range", "subtype"}:
        raise AssertionError("variant fixture no longer covers every exact choice form")
    expression_kinds = {
        argument["value"]["kind"]
        for annotation in typed_document["annotations"]
        for argument in annotation["arguments"]
        if argument["kind"] == "expression"
    }
    required_expression_coverage = {
        "attribute", "boolean_literal", "function_call", "indexed_component", "qualified",
        "selected_component", "string_literal", "type_conversion", "unary",
    }
    if not required_expression_coverage.issubset(expression_kinds):
        raise AssertionError("typed fixture lost a retained expression form")
    letter = next(item for item in typed_document["declarations"] if item["canonical_name"] == "shapes.letter")
    if {letter["shape"]["range"]["low"]["kind"], letter["shape"]["range"]["high"]["kind"]} != {"character_literal"}:
        raise AssertionError("character subtype bounds lost literal-kind identity")
    if length_prefix("é") != "2:é":
        raise AssertionError("semantic key lengths must count UTF-8 bytes")
    if valid_canonical_name("x%4d%69%58%65%44", segment=True):
        raise AssertionError("v1 accepted an extended identifier identity")
    generic_family_a = "decl:g.i[t=decl:a#public].item#public"
    generic_family_b = "decl:g.i[t=decl:b#public].item#full"
    if declaration_family_key(generic_family_a) == declaration_family_key(generic_family_b):
        raise AssertionError("declaration family identity lost an enclosing generic binding")
    if rooted_type_family_key("decl:g.t#public") == rooted_type_family_key(
        "decl:g.t#class_wide"
    ):
        raise AssertionError("specific and class-wide types collapsed into one family")
    if rooted_type_family_key("decl:g.t#public") != rooted_type_family_key(
        "decl:g.t#full"
    ):
        raise AssertionError("ordinary views failed to normalize to one type family")
    unsupported_kinds = {
        argument["value"]["kind"]
        for annotation in documents["unknown-unsupported-facts.json"]["annotations"]
        for argument in annotation["arguments"]
    }
    if "unsupported" not in unsupported_kinds:
        raise AssertionError("Unknown/Unsupported fixture lost expression fail-closed coverage")
    generic_fixture = documents["generic-actual-rebinding.json"]
    if {item["kind"] for item in generic_fixture["generic_actuals"]} != {
        "object", "package", "subprogram", "type", "value"
    }:
        raise AssertionError("generic fixture lost a typed actual kind")
    if {item["origin"] for item in generic_fixture["generic_actuals"]} != {
        "default", "named", "positional"
    }:
        raise AssertionError("generic fixture lost an actual-origin form")

    anonymous = FIXTURES / "rejected/anonymous-type.json"
    expect_rejected(
        "anonymous type", lambda: load_checked(anonymous, "structural")
    )
    imprecise = FIXTURES / "rejected/unknown-mandatory-fact.json"
    load_checked(imprecise, "structural")
    expect_rejected(
        "mandatory Unknown",
        lambda: load_checked(imprecise, "fixture_shape"),
    )

    base = documents["generic-actual-rebinding.json"]
    mutant = copy.deepcopy(base)
    mutant["ir_version"] = 2
    expect_rejected("unknown version", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["future_semantics"] = True
    expect_rejected("unknown key", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["declarations"][1]["references"][0]["target"]["declaration_id"] = "decl:missing#public"
    expect_rejected("unresolved reference", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["static-dynamic-constraints.json"])
    mutant["declarations"][1]["shape"]["range"]["high"]["value"] = "01"
    expect_rejected("noncanonical integer", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(base)
    mutant["declarations"][0]["view"] = "private"
    expect_rejected("view suffix mismatch", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    mutant["variants"][0]["alternatives"][1]["declaration_order"] = 0
    expect_rejected("duplicate declaration order", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["optional_features"] = ["example.test/diagnostic"]
    expect_rejected("unlisted extension", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["declarations"][0]["shape"]["predicate"]["value"] = {"future": True}
    expect_rejected("untyped Known value", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(base)
    mutant["required_features"] = []
    expect_rejected("empty required features", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["context"]["scenario"] = [
        {"name": "MODE", "value": "fixture"},
        {"name": "MODE", "value": "fixture"},
    ]
    expect_rejected("duplicate scenario name", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    mutant["variants"][0]["alternatives"].reverse()
    expect_rejected("reversed alternatives", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["declarations"][1]["stable_id"] = (
        "decl:generics.instance[t=decl:generics.actual#public].item#public"
    )
    expect_rejected("generic binding mismatch", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["public-private-full-views.json"])
    related = next(item for item in mutant["declarations"] if item["related_view_ids"])
    related["related_view_ids"] = []
    expect_rejected("nonreciprocal related view", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["declarations"][0]["view_access"]["representation_available"] = {
        "detail": "",
        "status": "known",
        "value": {"kind": "text", "value": "yes"},
    }
    expect_rejected("wrong visibility fact type", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    mutant["components"][0]["variant_path"] = [
        "decl:demo.packet.alt.others#public"
    ]
    expect_rejected("incoherent variant path", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["static-dynamic-constraints.json"])
    mutant["entities"][0]["stable_id"] = "decl:constraints.limit#full#public"
    expect_rejected("extra semantic ID suffix", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    next(
        item for item in mutant["entities"]
        if item["canonical_name"] == "generics.template.t"
    )["formal_kind"] = "value"
    expect_rejected("generic formal kind mismatch", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["generic_actuals"][0]["formal_canonical_name"] = "u"
    expect_rejected("generic formal canonical-name mismatch", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    root_variant, nested_variant = mutant["variants"]
    nested_zero = nested_variant["alternatives"][0]
    nested_zero["nested_variant_id"] = root_variant["stable_id"]
    root_variant["parent_alternative_id"] = nested_zero["stable_id"]
    for component in mutant["components"]:
        component["variant_path"] = []
    for variant in mutant["variants"]:
        for alternative in variant["alternatives"]:
            alternative["component_ids"] = []
    expect_rejected("variant nesting cycle", lambda: validate(mutant))
    mutant = copy.deepcopy(base)
    mutant["context"]["compiler_identity"] = ""
    expect_rejected("empty compiler identity", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["declarations"][0]["kind"] = "array"
    expect_rejected("duplicate type classification", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    fixed = next(
        item for item in mutant["declarations"]
        if item["canonical_name"] == "shapes.fixed_2"
    )
    fixed["shape"]["delta"]["value"]["value"] = {
        "denominator": "16",
        "numerator": "2",
    }
    expect_rejected("nonnormalized exact rational", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["nested-generic-rebinding.json"])
    nested_declaration = next(
        item for item in mutant["declarations"]
        if item["canonical_name"].endswith("inner_instance.item")
    )
    nested_declaration["stable_id"] = nested_declaration["stable_id"].replace(
        "[u=decl:nested_generics.outer_instance.actual.u[value=decl:nested_generics.actual#public,constraint=none]#public]",
        "",
        1,
    )
    expect_rejected("missing enclosing generic chain", lambda: validate(mutant))

    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["context"]["legality_check"]["succeeded"] = 1
    expect_rejected("boolean const is not JSON number one", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["declarations"][0]["declaration_order"] = 2147483648
    expect_rejected("Ada Natural overflow", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["static-dynamic-constraints.json"])
    subtype = next(item for item in mutant["declarations"] if item["declaration_form"] == "subtype")
    subtype["references"] = []
    expect_rejected("missing subtype base edge", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    signed = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "signed_scalar")
    signed["declaration_form"] = "class_wide"
    expect_rejected("class-wide form/effective-shape mismatch", lambda: validate(mutant, strict=True))
    mutant = copy.deepcopy(documents["unknown-unsupported-facts.json"])
    mutant["declarations"][0]["shape"] = {"kind": "opaque", "reason": "task"}
    mutant["declarations"][0]["declaration_form"] = "type"
    mutant["declarations"][0]["facts"]["task"] = {"detail": "", "status": "known", "value": {"kind": "boolean", "value": False}}
    expect_rejected("opaque task contradicts task fact", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["context"]["requested_units"] = ["Outside"]
    expect_rejected("requested unit outside closure", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["context"]["project_closure"] = ["Other", "Shapes"]
    expect_rejected("selected manifest does not cover closure", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["nested-generic-rebinding.json"])
    inner = next(item for item in mutant["entities"] if item["canonical_name"].endswith("inner_instance"))
    inner["owner_id"] = None
    expect_rejected("forged nested generic owner", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    value_actual = next(item for item in mutant["generic_actuals"] if item["kind"] == "value")
    formal = next(item for item in mutant["entities"] if item["stable_id"] == value_actual["formal_id"])
    formal["type"] = None
    expect_rejected("untyped value formal", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    value_actual = next(item for item in mutant["generic_actuals"] if item["kind"] == "value")
    value_actual["value"] = {
        "code": "not_analyzed", "detail": "", "status": "unknown"
    }
    expect_rejected(
        "imprecise generic value identity", lambda: validate_schema(mutant, SCHEMA)
    )
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    object_actual = next(item for item in mutant["generic_actuals"] if item["kind"] == "object")
    object_entity = next(item for item in mutant["entities"] if item["stable_id"] == object_actual["value_id"])
    object_entity["type"]["declaration_id"] = "decl:standard.boolean#public"
    expect_rejected("generic object type nonconformance", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    subprogram_actual = next(item for item in mutant["generic_actuals"] if item["kind"] == "subprogram")
    boolean_overload = next(
        item for item in mutant["entities"]
        if item["entity_kind"] == "subprogram"
        and item["callable_profile"]["parameters"][0]["type"]["declaration_id"]
        == "decl:standard.boolean#public"
    )
    subprogram_actual["value_id"] = boolean_overload["stable_id"]
    expect_rejected("generic subprogram profile nonconformance", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    package_formal = next(
        item for item in mutant["entities"]
        if item["entity_kind"] == "generic_formal" and item["formal_kind"] == "package"
    )
    package_formal["formal_template_id"] = "decl:generics.mixed#public"
    expect_rejected("generic package template nonconformance", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    subtype_choice = next(
        choice for variant in mutant["variants"]
        for alternative in variant["alternatives"]
        for choice in alternative["choices"] if choice["kind"] == "subtype"
    )
    subtype_choice["static_value"] = {
        "detail": "", "status": "known",
        "value": {"kind": "decimal_integer", "value": "7"},
    }
    expect_rejected("subtype choice singular value", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    scalar = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "signed_scalar")
    scalar["shape"]["range"] = {"kind": "none"}
    expect_rejected("scalar without effective range", lambda: validate(mutant, strict=True))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    array = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "array")
    array["shape"]["constrained"] = {
        "detail": "", "status": "known", "value": {"kind": "boolean", "value": True}
    }
    index_type = next(
        item for item in mutant["declarations"]
        if item["stable_id"] == array["shape"]["dimensions"][0]["index_subtype"]["declaration_id"]
    )
    array["shape"]["dimensions"][0]["constraint"] = copy.deepcopy(
        index_type["shape"]["range"]
    )
    expect_rejected("array constrainedness contradiction", lambda: validate(mutant, strict=True))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["context"]["legality_check"]["command"]["argv"].append("-O2")
    expect_rejected("stale legality command fingerprint", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    del mutant["declarations"][0]["facts"]["limited"]
    expect_rejected("missing core ownership fact", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["annotations"][0]["action"] = "Bad Action"
    expect_rejected("annotation lexical grammar", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["public-private-full-views.json"])
    mutant["declarations"] = [
        item for item in mutant["declarations"]
        if item["stable_id"] != "decl:views.secret#private"
    ]
    public_secret = next(
        item for item in mutant["declarations"]
        if item["stable_id"] == "decl:views.secret#public"
    )
    full_secret = next(
        item for item in mutant["declarations"]
        if item["stable_id"] == "decl:views.secret#full"
    )
    public_secret["related_view_ids"] = [full_secret["stable_id"]]
    full_secret["related_view_ids"] = [public_secret["stable_id"]]
    full_secret["view_access"]["consumer_can_name_components"] = {
        "detail": "", "status": "known", "value": {"kind": "boolean", "value": True}
    }
    expect_rejected("public-spec private completion visibility escalation", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    typed_component = next(item for item in mutant["components"] if item["name"] == "Value")
    typed_component["default"] = {
        "expression": {"kind": "string_literal", "syntax": '"wrong"', "value": "wrong"},
        "present": True,
        "static_value": {"detail": "", "status": "known", "value": {"kind": "text", "value": "wrong"}},
        "staticness": {"detail": "", "status": "known", "value": {"kind": "boolean", "value": True}},
        "syntax": '"wrong"',
    }
    expect_rejected("typed component default mismatch", lambda: validate(mutant, strict=True))
    mutant = copy.deepcopy(documents["static-dynamic-constraints.json"])
    static = next(item for item in mutant["declarations"] if item["canonical_name"].endswith("static_range"))
    static["shape"]["range"]["static_low"]["value"] = {"kind": "text", "value": "wrong"}
    expect_rejected("typed scalar bound mismatch", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["static-dynamic-constraints.json"])
    static = next(item for item in mutant["declarations"] if item["canonical_name"].endswith("static_range"))
    static["shape"]["range"]["low"]["value"] = "2"
    expect_rejected("scalar bound literal/evaluation contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["discriminants"][0]["default"]["expression"]["value"] = "4"
    expect_rejected("default literal/evaluation contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    constrained_component = next(
        item for item in mutant["components"]
        if item["type"]["constraint"]["kind"] == "discriminants"
    )
    constrained_component["type"]["constraint"]["associations"][0]["expression"]["value"] = "3"
    expect_rejected("discriminant literal/evaluation contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    floating = next(
        item for item in mutant["declarations"]
        if item["shape"]["kind"] == "floating_scalar"
    )
    floating["shape"]["digits_constraint"]["digits"]["value"] = "7"
    expect_rejected("digits literal/evaluation contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    character_bound = next(
        item["shape"]["range"]["low"] for item in mutant["declarations"]
        if item["canonical_name"] == "shapes.letter"
    )
    character_bound["resolved_type_id"] = "decl:shapes.color#public"
    expect_rejected("overloaded user-enum character literal", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    fake_character = copy.deepcopy(
        next(
            item for item in mutant["declarations"]
            if item["stable_id"] == "decl:standard.character#public"
        )
    )
    fake_character["canonical_name"] = "shapes.fake_character"
    fake_character["display_name"] = "Fake_Character"
    fake_character["stable_id"] = "decl:shapes.fake_character#public"
    mutant["declarations"].append(fake_character)
    mutant["declarations"].sort(key=lambda item: item["stable_id"])
    character_bound = next(
        item["shape"]["range"]["low"] for item in mutant["declarations"]
        if item["canonical_name"] == "shapes.letter"
    )
    character_bound["resolved_type_id"] = fake_character["stable_id"]
    expect_rejected("non-Standard character root literal", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    value_actual = next(item for item in mutant["generic_actuals"] if item["kind"] == "value")
    value_actual["value"]["value"] = {"kind": "text", "value": "42"}
    expect_rejected("typed generic actual mismatch", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    typed_component = next(item for item in mutant["components"] if item["name"] == "Value")
    typed_component["default"]["expression"]["left"]["declaration_id"] = "decl:shapes.holder.annotation.fake#public"
    expect_rejected("expression points outside Ada entity domain", lambda: validate(mutant, strict=True))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["annotations"][0]["target_id"] = "decl:shapes.holder.annotation.fake#public"
    expect_rejected("annotation points outside Ada entity domain", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    duplicate_choice = copy.deepcopy(mutant["variants"][0]["alternatives"][0]["choices"][0])
    mutant["variants"][0]["alternatives"][0]["choices"].append(duplicate_choice)
    expect_rejected("duplicate semantic variant choice", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    name_choice = next(
        choice for variant in mutant["variants"] for alternative in variant["alternatives"]
        for choice in alternative["choices"] if choice["kind"] == "name"
    )
    name_choice["resolved_declaration_id"] = "decl:standard.integer#public"
    expect_rejected("name choice resolves to a type declaration", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    boolean_declaration = copy.deepcopy(
        next(
            item for item in documents["typed-shapes.json"]["declarations"]
            if item["stable_id"] == "decl:standard.boolean#public"
        )
    )
    mutant["declarations"].append(boolean_declaration)
    mutant["declarations"].sort(key=lambda item: item["stable_id"])
    zero = next(item for item in mutant["entities"] if item["canonical_name"] == "demo.zero")
    flag = copy.deepcopy(zero)
    flag["canonical_name"] = "demo.flag"
    flag["display_name"] = "Flag"
    flag["stable_id"] = "decl:demo.flag#public"
    flag["type"]["declaration_id"] = "decl:standard.boolean#public"
    mutant["entities"].append(flag)
    mutant["entities"].sort(key=lambda item: item["stable_id"])
    name_choice = next(
        choice for variant in mutant["variants"] for alternative in variant["alternatives"]
        for choice in alternative["choices"] if choice["kind"] == "name"
    )
    name_choice["resolved_declaration_id"] = flag["stable_id"]
    expect_rejected("name choice resolved value has wrong selector type", lambda: validate(mutant))

    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    range_choice = next(
        choice for variant in mutant["variants"] for alternative in variant["alternatives"]
        for choice in alternative["choices"] if choice["kind"] == "range"
    )
    range_choice["low"]["value"] = "12"
    expect_rejected("variant literal/evaluation contradiction", lambda: validate(mutant))

    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    typed = documents["typed-shapes.json"]
    color = copy.deepcopy(
        next(item for item in typed["declarations"] if item["stable_id"] == "decl:shapes.color#public")
    )
    color["stable_id"] = "decl:demo.color#public"
    color["canonical_name"] = "demo.color"
    mutant["declarations"].append(color)
    mutant["declarations"].sort(key=lambda item: item["stable_id"])
    color_literals = []
    for literal in typed["enum_literals"]:
        copied = copy.deepcopy(literal)
        copied["owner_id"] = color["stable_id"]
        copied["stable_id"] = copied["stable_id"].replace("decl:shapes.color.", "decl:demo.color.")
        copied["canonical_name"] = copied["canonical_name"]
        color_literals.append(copied)
    mutant["enum_literals"] = sorted(color_literals, key=lambda item: item["stable_id"])
    mutant["discriminants"][0]["type"]["declaration_id"] = color["stable_id"]
    root = mutant["variants"][0]
    name_alternative = copy.deepcopy(root["alternatives"][0])
    name_choice = next(choice for choice in name_alternative["choices"] if choice["kind"] == "name")
    name_choice["resolved_declaration_id"] = "decl:demo.color.red#public"
    name_choice["static_value"]["value"]["value"] = "2"
    name_alternative["choices"] = [name_choice]
    name_alternative["component_ids"] = []
    name_alternative["nested_variant_id"] = None
    others_alternative = copy.deepcopy(root["alternatives"][-1])
    others_alternative["stable_id"] = "decl:demo.packet.variant.kind.alternative.1#public"
    others_alternative["declaration_order"] = 1
    others_alternative["component_ids"] = []
    root["alternatives"] = [name_alternative, others_alternative]
    mutant["variants"] = [root]
    for component in mutant["components"]:
        component["variant_path"] = []
    expect_rejected("enum name choice position mismatch", lambda: validate(mutant))

    mutant = copy.deepcopy(documents["exact-variant-ast.json"])
    component_ids = mutant["variants"][0]["alternatives"][0]["component_ids"]
    component_ids.append(component_ids[0])
    expect_rejected("duplicate variant component ID", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["declarations"][0]["display_name"] = ""
    expect_rejected("empty retained display name", lambda: validate_schema(mutant, SCHEMA))
    for bad_name in ("shapes.x_", "shapes.x__y", "shapes.end"):
        mutant = copy.deepcopy(documents["typed-shapes.json"])
        mutant["declarations"][0]["canonical_name"] = bad_name
        expect_rejected(
            f"non-Ada basic identifier {bad_name}",
            lambda mutant=mutant: validate_schema(mutant, SCHEMA),
        )
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["entities"][0]["callable_profile"]["parameters"][0]["mode"] = "access"
    expect_rejected("anonymous access parameter", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    unary = next(
        value for annotation in mutant["annotations"]
        for argument in annotation["arguments"]
        for value in [argument.get("value")]
        if isinstance(value, dict) and value.get("kind") == "unary"
    )
    unary["operator_resolution"] = "user_defined"
    expect_rejected("user-defined operator resolution", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["annotations"][0]["namespace"] = "a..b"
    expect_rejected("malformed annotation namespace", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    mutant["context"]["accessibility_context"] = {
        "consumer_unit": "x%4d%69%58%65%44.generated",
        "derivation_unit": "x%41%64%61",
        "region": "public_spec",
    }
    expect_rejected("extended identifier context", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    first_attribute = mutant["annotations"][1]["arguments"][0]["value"]
    first_attribute["arguments"].append(
        {"kind": "integer_literal", "syntax": "2", "value": "2"}
    )
    expect_rejected("too many First attribute arguments", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    function = next(item for item in mutant["entities"] if item["entity_kind"] == "subprogram")
    procedure = copy.deepcopy(function)
    procedure["canonical_name"] = "shapes.consume"
    procedure["display_name"] = "Consume"
    procedure["callable_profile"]["result"] = None
    procedure["stable_id"] = (
        "decl:shapes.consume[profile=0:in:x:decl:standard.integer#public,result=none]#public"
    )
    mutant["entities"].append(procedure)
    mutant["entities"].sort(key=lambda item: item["stable_id"])
    call = next(
        argument["value"] for annotation in mutant["annotations"]
        for argument in annotation["arguments"]
        if argument["kind"] == "expression" and argument["value"]["kind"] == "function_call"
    )
    call["resolved_subprogram_id"] = procedure["stable_id"]
    expect_rejected("procedure used as expression call", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    vector = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "array")
    decimal_fixed = next(
        item for item in mutant["declarations"]
        if item["shape"]["kind"] == "decimal_fixed_scalar"
    )
    bad_index = copy.deepcopy(decimal_fixed["shape"]["digits_constraint"])
    bad_index["provenance"] = "declared_subtype"
    vector["shape"]["dimensions"][0]["constraint"] = bad_index
    expect_rejected("non-range declared array index constraint", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    holder = next(item for item in mutant["declarations"] if item["canonical_name"] == "shapes.holder")
    container = next(item for item in mutant["declarations"] if item["canonical_name"] == "shapes.container")
    count = next(item for item in mutant["discriminants"] if item["owner_id"] == holder["stable_id"])
    foreign = copy.deepcopy(count)
    foreign["canonical_name"] = "foreign"
    foreign["name"] = "Foreign"
    foreign["owner_id"] = container["stable_id"]
    container_body, container_view = container["stable_id"].rsplit("#", 1)
    foreign["stable_id"] = f"{container_body}.foreign#{container_view}"
    mutant["discriminants"].append(foreign)
    mutant["discriminants"].sort(key=lambda item: item["stable_id"])
    holder["shape"]["constraint"] = {
        "associations": [{
            "discriminant_id": foreign["stable_id"],
            "expression": {"kind": "integer_literal", "syntax": "1", "value": "1"},
            "static_value": {
                "detail": "", "status": "known",
                "value": {"kind": "decimal_integer", "value": "1"},
            },
            "staticness": {
                "detail": "", "status": "known",
                "value": {"kind": "boolean", "value": True},
            },
        }],
        "kind": "discriminants",
        "provenance": "declared_subtype",
    }
    expect_rejected("declaration constraint uses another record discriminant", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["static-dynamic-constraints.json"])
    subtypes = [item for item in mutant["declarations"] if item["declaration_form"] == "subtype"]
    for index, subtype in enumerate(subtypes[:2]):
        subtype["references"][0]["target"]["declaration_id"] = subtypes[1 - index]["stable_id"]
    expect_rejected("cyclic base-subtype graph", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    color = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "enumeration")
    mutant["enum_literals"] = [item for item in mutant["enum_literals"] if item["owner_id"] != color["stable_id"]]
    color["shape"]["literal_ids"] = []
    expect_rejected("empty base enumeration", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    color = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "enumeration")
    color["shape"]["range"]["static_high"]["value"]["value"] = "9"
    expect_rejected("base enumeration range contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    modular = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "modular_scalar")
    modular["shape"]["range"]["static_high"]["value"]["value"] = "14"
    expect_rejected("base modular range contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    boolean = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "boolean_scalar")
    boolean["shape"]["range"]["static_high"]["value"]["value"] = False
    expect_rejected("base boolean range contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    package_formal = next(
        item for item in mutant["entities"]
        if item["entity_kind"] == "generic_formal" and item["formal_kind"] == "package"
    )
    package_formal["formal_package_contract"] = None
    expect_rejected("non-box generic package formal", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    type_formal = next(
        item for item in mutant["entities"]
        if item["entity_kind"] == "generic_formal" and item["formal_kind"] == "type"
    )
    type_formal["formal_type_contract"] = None
    expect_rejected("missing generic type contract", lambda: validate_schema(mutant, SCHEMA))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    object_formal = next(
        item for item in mutant["entities"]
        if item["entity_kind"] == "generic_formal" and item["formal_kind"] == "object"
    )
    object_formal["formal_kind"] = "value"
    expect_rejected("value is not an Ada generic formal kind", lambda: validate_schema(mutant, SCHEMA))
    extraction = copy.deepcopy(documents["typed-shapes.json"])
    extraction["context"]["context_kind"] = "extraction"
    extraction["context"]["compiler_path"] = "/bin/true"
    extraction["context"]["canonical_gpr_path"] = str((ROOT / "fixtures/fixtures.gpr").resolve())
    extraction["context"]["effective_project"]["project_files"][0]["logical_name"] = extraction["context"]["canonical_gpr_path"]
    extraction["context"]["legality_check"]["command"] = {
        "argv": ["/bin/true"], "environment": [], "tool_identity": "caller-asserted",
        "working_directory": "/",
    }
    extraction["context"]["legality_check"]["command_fingerprint"] = hashlib.sha256(
        json.dumps(
            extraction["context"]["legality_check"]["command"],
            ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8") + b"\n"
    ).hexdigest()
    extraction["context"]["effective_project"]["closure_digest"] = effective_closure_digest(extraction)
    validate(extraction)
    expect_rejected("unattested extraction context", lambda: validate(extraction, strict=True))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    signed = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "signed_scalar")
    signed["shape"]["predicate"]["value"]["value"] = True
    expect_rejected("shape/range predicate contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    floating = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "floating_scalar")
    floating["shape"]["digits_constraint"]["static_value"]["value"]["value"] = "7"
    expect_rejected("digits fact/constraint contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["typed-shapes.json"])
    fixed = next(item for item in mutant["declarations"] if item["shape"]["kind"] == "ordinary_fixed_scalar")
    fixed["shape"]["delta_constraint"]["static_value"]["value"]["value"] = {
        "denominator": "16", "numerator": "3",
    }
    expect_rejected("delta fact/constraint contradiction", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    positive_declaration = next(
        item for item in mutant["declarations"]
        if item["canonical_name"] == "generics.positive"
    )
    positive_declaration["declaration_form"] = "derived"
    expect_rejected("derived type does not conform as its parent", lambda: validate(mutant))
    mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    object_actual = next(item for item in mutant["generic_actuals"] if item["kind"] == "object")
    object_formal = next(item for item in mutant["entities"] if item["stable_id"] == object_actual["formal_id"])
    object_formal["object_mode"] = "in"
    expect_rejected("mode-in object formal cannot use an object identity", lambda: validate(mutant))

    diagnostic_mutant = copy.deepcopy(documents["typed-shapes.json"])
    diagnostic_mutant["context"]["canonical_gpr_path"] = "/moved/shapes.gpr"
    diagnostic_mutant["declarations"][0]["display_name"] = "COLOR"
    diagnostic_mutant["declarations"][0]["location"]["line"] = 999
    typed_component = next(item for item in diagnostic_mutant["components"] if item["name"] == "Value")
    typed_component["default"]["syntax"] = "Count+1"
    typed_component["default"]["expression"]["syntax"] = "Count+1"
    if semantic_projection(diagnostic_mutant) != semantic_projection(
        documents["typed-shapes.json"]
    ):
        raise AssertionError("diagnostic/source changes altered semantic projection")
    annotation_mutant = copy.deepcopy(documents["typed-shapes.json"])
    annotation_mutant["annotations"][0]["expression_syntax"] = "Different_Policy"
    if semantic_projection(annotation_mutant) != semantic_projection(
        documents["typed-shapes.json"]
    ):
        raise AssertionError("typed annotation source text altered semantic projection")
    origin_mutant = copy.deepcopy(documents["generic-actual-rebinding.json"])
    origin_mutant["generic_actuals"][0]["origin"] = "positional"
    if semantic_projection(origin_mutant) != semantic_projection(
        documents["generic-actual-rebinding.json"]
    ):
        raise AssertionError("generic association syntax altered semantic projection")

    extension = copy.deepcopy(base)
    extension["optional_features"] = ["example.test/diagnostic"]
    extension["extensions"] = {
        "example.test/diagnostic": {
            "denominator": "diagnostic text",
            "status": "not-a-core-fact",
        }
    }
    validate_schema(extension, SCHEMA)
    validate(extension)
    extension_with_number = copy.deepcopy(extension)
    extension_with_number["extensions"]["example.test/diagnostic"]["count"] = 1.0
    expect_rejected(
        "extension JSON number has no cross-language canonical form",
        lambda: validate_schema(extension_with_number, SCHEMA),
    )

    raw = (FIXTURES / "generic-actual-rebinding.json").read_bytes()
    duplicate = raw.replace(b'{"annotations":', b'{"annotations":[],"annotations":', 1)
    expect_rejected("duplicate key", lambda: parse(duplicate))
    reordered = raw.replace(
        b'{"annotations":[],"components":', b'{"components":[],"annotations":', 1
    )
    expect_rejected("reordered/duplicate semantic key", lambda: parse(reordered))
    expect_rejected(
        "non-JSON numeric constant",
        lambda: parse(b'{"value":NaN}\n'),
    )
    expect_rejected(
        "escaped lone surrogate",
        lambda: parse(b'{"value":"\\ud800"}\n'),
    )

    print(f"checked {len(positive)} canonical fixtures and {REJECTION_COUNT} rejection cases")


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Strictly load canonical Type IR v1 JSON and validate it"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--structural", type=Path, metavar="FILE")
    mode.add_argument("--strict", type=Path, metavar="FILE")
    mode.add_argument("--fixture-shape", type=Path, metavar="FILE")
    parser.add_argument("--print-fingerprint", action="store_true")
    arguments = parser.parse_args()
    selected = next(
        (
            (profile, path) for profile, path in (
                ("structural", arguments.structural),
                ("strict", arguments.strict),
                ("fixture_shape", arguments.fixture_shape),
            ) if path is not None
        ),
        None,
    )
    if selected is not None:
        profile, path = selected
        checked = load_checked(path, profile)
        print(f"{profile.replace('_', '-')} valid: {path}")
        if arguments.print_fingerprint:
            print(checked.semantic_fingerprint)
    else:
        if arguments.print_fingerprint:
            parser.error("--print-fingerprint requires a validation mode")
        main()


if __name__ == "__main__":
    try:
        cli()
    except Rejected as error:
        print(f"rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from None

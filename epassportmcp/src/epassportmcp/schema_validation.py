"""Small validator for the deliberately limited action-schema vocabulary.

The catalog still exposes ordinary JSON Schemas to MCP clients.  Runtime
validation only needs the keywords emitted by :mod:`epassportmcp.catalog`, so
carrying a complete JSON Schema implementation is unnecessary.
"""

from __future__ import annotations

from typing import Any, Mapping


def validate(schema: Mapping[str, Any], value: Any, path: str = "$") -> list[str]:
    """Return caller-facing validation errors for *value*.

    Supported keywords are ``oneOf``, ``type``, ``enum``, object properties,
    array items, and numeric/array bounds.  Unknown annotation keywords (such
    as ``description`` and ``default``) do not affect validation.
    """

    alternatives = schema.get("oneOf")
    if isinstance(alternatives, list):
        matches = sum(not validate(alternative, value, path) for alternative in alternatives)
        if matches != 1:
            return [f"{path}: must match exactly one accepted form"]

    expected = schema.get("type")
    if isinstance(expected, str) and not _has_type(value, expected):
        return [f"{path}: expected {expected}, got {_json_type(value)}"]

    errors: list[str] = []
    choices = schema.get("enum")
    if isinstance(choices, list) and value not in choices:
        errors.append(f"{path}: must be one of {choices!r}")

    if expected == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                errors.append(f"{path}.{name}: is required")
        if schema.get("additionalProperties") is False:
            for name in sorted(set(value) - set(properties)):
                errors.append(f"{path}.{name}: is not an accepted property")
        for name, child_schema in properties.items():
            if name in value:
                errors.extend(validate(child_schema, value[name], f"{path}.{name}"))

    if expected == "array":
        prefix = schema.get("prefixItems", [])
        for index, child_schema in enumerate(prefix[: len(value)]):
            errors.extend(validate(child_schema, value[index], f"{path}[{index}]"))
        child_schema = schema.get("items")
        if isinstance(child_schema, Mapping):
            for index in range(len(prefix), len(value)):
                errors.extend(validate(child_schema, value[index], f"{path}[{index}]"))
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            errors.append(f"{path}: requires at least {minimum_items} items")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            errors.append(f"{path}: accepts at most {maximum_items} items")

    if expected in {"integer", "number"}:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{path}: must be at least {minimum}")
        if isinstance(maximum, (int, float)) and value > maximum:
            errors.append(f"{path}: must be at most {maximum}")
    return errors


def _has_type(value: Any, expected: str) -> bool:
    return {
        "object": lambda item: isinstance(item, Mapping),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }.get(expected, lambda _item: True)(value)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__

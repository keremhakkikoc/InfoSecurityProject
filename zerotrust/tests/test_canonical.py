"""Tests for common.canonical — sort_keys + compact separators."""

from __future__ import annotations

from zerotrust.common.canonical import canonical_json, canonical_sha256_hex


def test_canonical_sorts_keys():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b
    # Keys must be in sorted order
    assert a.index(b'"a"') < a.index(b'"b"')


def test_canonical_no_whitespace():
    assert canonical_json({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'


def test_canonical_handles_nested_objects():
    obj = {"outer": {"b": 2, "a": 1}, "list": [{"y": 2, "x": 1}]}
    out = canonical_json(obj)
    assert out == b'{"list":[{"x":1,"y":2}],"outer":{"a":1,"b":2}}'


def test_canonical_sha256_is_stable():
    obj = {"x": 1, "y": [1, 2, 3]}
    assert canonical_sha256_hex(obj) == canonical_sha256_hex({"y": [1, 2, 3], "x": 1})

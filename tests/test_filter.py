"""LDAP 转义练习的 15 个行为契约测试，初始全部为红。

前 10 个用例分别对应题面中的 10 个缺陷，后 5 个覆盖正常构造、通配转义、
括号注入、标识名逗号转义与批量一致性。tests 目录不可修改。
"""

import pytest

from dirsvc.filter import (
    build_filter,
    check_injection,
    escape_dn,
    escape_value,
    filter_batch,
    normalize,
    parse_template,
    validate_policy,
)


SAFE_POLICY = {
    "allow_raw_concat": False,
    "allow_wildcard": False,
    "escape_dn": True,
}


def test_defect_01_escape_value_escapes_wildcard_and_parens():
    """缺陷 1：值转义不能只处理反斜杠而放过通配符与括号。"""
    assert escape_value(r"a\b*c(d)") == r"a\5cb\2ac\28d\29"


def test_defect_02_escape_value_pads_hex_to_two_digits():
    """缺陷 2：十六进制转义必须补足两位，短码不能被截断。"""
    escaped = escape_value("\x00")
    assert escaped == r"\00"
    assert len(escaped) == 3


def test_defect_03_escape_value_does_not_truncate_at_nul():
    """缺陷 3：空字节必须转义，过滤器不能在空字节处提前结束。"""
    escaped = escape_value("a\x00b")
    assert escaped == r"a\00b"
    assert "\x00" not in escaped
    assert escaped.endswith("b")


def test_defect_04_escape_dn_handles_equals_plus_and_quote():
    """缺陷 4：标识名转义不能只处理逗号，等号、加号与引号也要处理。"""
    value = 'R&D=Ops+Admin "North"'
    assert escape_dn(value) == r'R&D\=Ops\+Admin \"North\"'


def test_defect_05_build_filter_escapes_every_parameter():
    """缺陷 5：模板拼装不能把参数原样插入，所有参数都必须转义。"""
    template = "(&(uid={user})(cn={name}))"
    params = {"user": "a*b(c)", "name": r"Smith\Jones"}
    assert build_filter(template, params) == r"(&(uid=a\2ab\28c\29)(cn=Smith\5cJones))"


def test_defect_06_parse_template_rejects_structural_placeholders():
    """缺陷 6：占位符只能在断言值位置，不能出现在结构位置或过滤器之间。"""
    assert parse_template("(uid={value})") == [
        ("text", "(uid="),
        ("param", "value"),
        ("text", ")"),
    ]

    with pytest.raises(ValueError):
        parse_template("({field}=alice)")
    with pytest.raises(ValueError):
        parse_template("(uid=before{value})")
    with pytest.raises(ValueError):
        parse_template("(uid={value}after)")
    with pytest.raises(ValueError):
        parse_template("(uid={value})(cn=other)")


def test_defect_07_check_injection_detects_right_paren():
    """缺陷 7：注入检测不能只查左括号，右括号闭合注入也必须报出。"""
    assert check_injection("alice)") == ["right_paren"]
    assert check_injection("alice(") == ["left_paren"]
    assert check_injection(r"alice\29") == []
    assert check_injection("a*b") == ["wildcard"]


def test_defect_08_normalize_strips_and_collapses_whitespace():
    """缺陷 8：规范化必须去掉首尾空白并折叠内部连续空白。"""
    assert normalize(" \t Alice \n  Smith \r ") == "Alice Smith"
    assert normalize("ALICE") == "ALICE"


def test_defect_09_validate_policy_rejects_raw_concat():
    """缺陷 9：策略校验必须发现允许原样拼接的配置。"""
    assert validate_policy(
        {
            "allow_raw_concat": True,
            "allow_wildcard": False,
            "escape_dn": True,
        }
    ) == ["raw_concat"]

    assert validate_policy(
        {
            "allow_raw_concat": True,
            "allow_wildcard": True,
            "escape_dn": False,
        }
    ) == ["raw_concat", "wildcard", "dn_escape"]

    assert validate_policy(SAFE_POLICY) == []


def test_defect_10_filter_batch_keeps_request_params_isolated():
    """缺陷 10：批量构造不能复用分段，后一个请求不能命中前一个请求的参数。"""
    requests = [
        {"id": "first", "template": "(uid={value})", "params": {"value": "alice"}},
        {"id": "second", "template": "(uid={value})", "params": {"value": "bob"}},
    ]
    assert filter_batch(requests, SAFE_POLICY) == {
        "first": "(uid=alice)",
        "second": "(uid=bob)",
    }


def test_base_01_normal_username_builds_filter():
    """基础用例：普通用户名能构造出精确的过滤器。"""
    assert build_filter("(uid={value})", {"value": "alice"}) == "(uid=alice)"


def test_base_02_wildcard_is_escaped():
    """基础用例：单个星号必须变成十六进制转义。"""
    assert escape_value("*") == r"\2a"


def test_base_03_paren_injection_is_escaped():
    """基础用例：左右括号注入都必须变成十六进制转义。"""
    assert escape_value(")(") == r"\29\28"


def test_base_04_dn_comma_is_escaped():
    """基础用例：标识名中的逗号必须用反斜杠转义。"""
    assert escape_dn("Doe, Jane") == r"Doe\, Jane"


def test_base_05_batches_match_individual_builds():
    """基础用例：两批批量构造互不影响，且与逐个单独构造一致。"""
    first_requests = [
        {"id": "one", "template": "(uid={value})", "params": {"value": "alice"}},
        {"id": "two", "template": "(cn={value})", "params": {"value": "bob"}},
    ]
    second_requests = [
        {"id": "one", "template": "(uid={value})", "params": {"value": "carol"}},
        {"id": "two", "template": "(cn={value})", "params": {"value": "dave"}},
    ]

    first = filter_batch(first_requests, SAFE_POLICY)
    second = filter_batch(second_requests, SAFE_POLICY)

    expected_first = {
        "one": build_filter("(uid={value})", {"value": "alice"}),
        "two": build_filter("(cn={value})", {"value": "bob"}),
    }
    expected_second = {
        "one": build_filter("(uid={value})", {"value": "carol"}),
        "two": build_filter("(cn={value})", {"value": "dave"}),
    }

    assert first == expected_first
    assert second == expected_second
    assert first != second
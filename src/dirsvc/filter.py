r"""LDAP 过滤器与标识名转义桩：安全契约与调用边界。

过滤器值
--------
escape_value 只处理 RFC 4515 规定的五类字符：空字节、左括号、右括号、星号、
反斜杠。转义结果固定为反斜杠加两位小写十六进制数字。其余字符逐字符保留，
不 trim、不折叠空白、不改大小写。

标识名
------
escape_dn 处理 RFC 4514 特殊字符、空字节、开头井号与首尾空格；内部空格保留。
输出只由原始字符决定，只做一层转义。

模板
----
占位符写作 {name}，name 是 ASCII 标识符。占位符只能占满一个断言值，不能出现
在属性名、过滤器之间或值的中间。参数值一律经过 escape_value，模板文本不转义，
替换结果也不会被再次解释为模板。

容差 0
------
所有函数只接受文档声明的类型，不做隐式转换、不修复畸形输入、不忽略大小写、
不做 Unicode 规范化。所有字符串比较与输出都逐字符精确。

依赖
----
只允许标准库 re、base64 与 pytest；离线运行，不使用随机数，不联网。
"""

import re

_PLACEHOLDER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# 缺陷 1/2/3：通配符、括号、空字节与反斜杠都必须转义，且十六进制固定两位。
_VALUE_ESCAPES = {
    "\x00": r"\00",
    "(": r"\28",
    ")": r"\29",
    "*": r"\2a",
    "\\": r"\5c",
}

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _is_mapping(obj) -> bool:
    """按行为判断映射，不泄漏对 dict 的依赖，也不把字符串当成映射。"""
    return (
        not isinstance(obj, (str, bytes, bytearray))
        and hasattr(obj, "keys")
        and hasattr(obj, "__getitem__")
    )


def escape_value(value: str) -> str:
    r"""按 RFC 4515 转义一个过滤器断言值。

    转义表
    ------
    - 空字节 U+0000 写成反斜杠 00。
    - 左括号写成反斜杠 28。
    - 右括号写成反斜杠 29。
    - 星号写成反斜杠 2a。
    - 反斜杠写成反斜杠 5c。

    每个转义必须恰好是反斜杠加两位小写十六进制数字：不能只写一位，不能使用
    大写十六进制，不能漏掉反斜杠，也不能对已经生成的转义序列再做一次转义。
    除上述五类字符外，其余字符（包括空格、换行、制表符和非 ASCII 字符）全部
    逐字符原样保留。本函数不负责外层括号，也不把值拼进过滤器。

    容差 0
    ------
    value 必须是 str，其他类型抛 TypeError。不 trim、不折叠空白、不改大小写、
    不做 Unicode 规范化。输出只由输入字符决定。
    """

    if not isinstance(value, str):
        raise TypeError("value must be str")
    # 缺陷 1：星号与括号必须转义；缺陷 2：十六进制固定两位；缺陷 3：空字节必须转义。
    return "".join(_VALUE_ESCAPES.get(ch, ch) for ch in value)


def escape_dn(value: str) -> str:
    r"""按 RFC 4514 转义标识名中的一个属性值。

    转义表
    ------
    - 反斜杠写成两个反斜杠。
    - 逗号写成反斜杠加逗号，等号写成反斜杠加等号，加号写成反斜杠加加号。
    - 双引号写成反斜杠加双引号，小于号写成反斜杠加小于号，大于号写成反斜杠
      加大于号，分号写成反斜杠加分号。
    - 空字节写成反斜杠 00。
    - 位于整个值开头的井号写成反斜杠加井号。
    - 位于整个值开头或末尾的空格写成反斜杠加空格；内部空格保持原样。
      全为空格的字符串只在首尾各转义一次，不重复叠加反斜杠。

    未列出的字母、数字、标点和非 ASCII 字符原样保留。本函数只处理一个属性值，
    不负责拼接相对可辨识名，也不负责添加或删除外层引号。

    容差 0
    ------
    value 必须是 str，其他类型抛 TypeError。不 trim、不折叠空白、不改大小写、
    不做 Unicode 规范化。输出只由原始字符决定，不对输出再次调用本函数。
    """

    if not isinstance(value, str):
        raise TypeError("value must be str")
    if value == "":
        return ""

    last = len(value) - 1
    out = []
    for index, char in enumerate(value):
        # 缺陷 4：逗号之外的等号、加号、引号、尖括号与分号也必须转义。
        if char == "\\":
            out.append("\\\\")
        elif char == ",":
            out.append("\\,")
        elif char == "=":
            out.append("\\=")
        elif char == "+":
            out.append("\\+")
        elif char == '"':
            out.append('\\"')
        elif char == "<":
            out.append("\\<")
        elif char == ">":
            out.append("\\>")
        elif char == ";":
            out.append("\\;")
        elif char == "\x00":
            out.append("\\00")
        elif char == "#" and index == 0:
            out.append("\\#")
        elif char == " " and (index == 0 or index == last):
            # 全为空格时首尾各只转义一次，不叠加反斜杠。
            out.append("\\ ")
        else:
            out.append(char)
    return "".join(out)


def build_filter(template: str, params: dict) -> str:
    r"""按模板构造过滤器，所有参数值都经过过滤器值转义。

    流程
    ----
    1. 调用 parse_template 得到文本段与参数段。
    2. 文本段原样拼接，不转义、不重新解析。
    3. 参数段取出同名参数，调用 escape_value 后拼接。

    参数约束
    --------
    - params 必须是映射，键与占位符名按精确字符串匹配。
    - 模板声明的每个名称都必须存在，缺失时抛 KeyError(name)。
    - params 不能包含模板未声明的名称，多余名称抛 ValueError。
    - 参数值必须是 str，其他类型抛 TypeError。参数值里的花括号、括号、星号、
      反斜杠与百分号都没有模板语法含义，只能作为普通值被转义。

    容差 0
    ------
    template 必须是 str，params 必须是映射，否则抛 TypeError。输出必须等于
    文本段与逐字符转义后的参数段按原顺序拼接的结果，不能 trim 或规范化参数。
    """

    if not isinstance(template, str):
        raise TypeError("template must be str")
    if not _is_mapping(params):
        raise TypeError("params must be a mapping")

    segments = parse_template(template)

    declared = {piece for kind, piece in segments if kind == "param"}
    extra = [key for key in params.keys() if key not in declared]
    if extra:
        raise ValueError("undeclared parameters: {0!r}".format(extra))
    for name in declared:
        if name not in params:
            raise KeyError(name)

    out = []
    for kind, piece in segments:
        if kind == "text":
            out.append(piece)
        else:
            value = params[piece]
            if not isinstance(value, str):
                raise TypeError("parameter {0!r} must be str".format(piece))
            # 缺陷 5：参数一律经过 escape_value，不能原样插入。
            out.append(escape_value(value))
    return "".join(out)


def parse_template(template: str) -> list:
    r"""把模板切分为文本段与参数段，并拒绝结构位置上的占位符。

    占位符规则
    ----------
    - 语法是 {name}；name 非空，首字符为 ASCII 字母或下划线，其余字符为 ASCII
      字母、数字或下划线。
    - 占位符必须占满一个断言值：它的前一个字符必须是属性操作符的等号，后一个
      字符必须是右括号。
    - 占位符不能出现在属性名中，不能出现在两个过滤器之间，不能有值前缀、值后缀、
      空名称、嵌套占位符或位置占位符。
    - 不支持双写花括号转义；花括号只用于占位符。

    结构规则
    --------
    - 整个模板必须是一个完整过滤器：以左括号开头，以右括号结尾。
    - 允许嵌套的与、或、非过滤器，但括号深度从 0 开始，任何位置不能为负，
      并且只能在最后一个字符处回到 0。提前回到 0 说明有多个顶层过滤器，拒绝。
    - 空模板、空过滤器、括号不平衡、花括号不配对都抛 ValueError。
    - 模板文本按过滤器结构处理；字面值中的括号必须写成 LDAP 十六进制转义，
      不能直接出现在模板中。

    返回格式
    --------
    list，元素只有两种精确形状：
    - ("text", 文本)
    - ("param", 参数名)

    相邻文本合并，不产生空文本段。没有占位符时返回 [("text", template)]。
    例如 (uid={value}) 返回
    [("text", "(uid="), ("param", "value"), ("text", ")")]。

    容差 0
    ------
    template 必须是 str，否则抛 TypeError。不 trim、不自动补括号、不忽略大小写、
    不修复畸形输入。
    """

    if not isinstance(template, str):
        raise TypeError("template must be str")
    if template == "":
        raise ValueError("empty template")
    if not template.startswith("(") or not template.endswith(")"):
        raise ValueError("template must be a single parenthesised filter")
    # 缺陷 6：括号深度从 0 开始，任何位置不能为负，只能在最后一个字符处回到 0。
    depth = 0
    for index, char in enumerate(template):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced parentheses")
            if depth == 0 and index != len(template) - 1:
                raise ValueError("multiple top-level filters")
    if depth != 0:
        raise ValueError("unbalanced parentheses")
    if "()" in template:
        raise ValueError("empty filter")

    segments = []
    buffer = []

    def flush():
        if buffer:
            segments.append(("text", "".join(buffer)))
            del buffer[:]

    index = 0
    length = len(template)
    while index < length:
        char = template[index]
        if char == "{":
            close = template.find("}", index + 1)
            if close == -1:
                raise ValueError("unmatched opening brace")
            name = template[index + 1:close]
            if not _PLACEHOLDER_NAME.match(name):
                raise ValueError("invalid placeholder name: {0!r}".format(name))
            # 占位符必须占满一个断言值：前一个字符是等号，后一个字符是右括号。
            if index == 0 or template[index - 1] != "=":
                raise ValueError("placeholder is not in a value position")
            if close + 1 >= length or template[close + 1] != ")":
                raise ValueError("placeholder is not in a value position")
            flush()
            segments.append(("param", name))
            index = close + 1
        elif char == "}":
            raise ValueError("unmatched closing brace")
        else:
            buffer.append(char)
            index += 1

    flush()
    if not segments:
        return [("text", template)]
    return segments


def check_injection(filter_text: str) -> list[str]:
    r"""扫描原始输入，报告未转义的通配符与括号。

    扫描规则
    --------
    - 从左到右逐字符扫描。
    - 反斜杠后紧跟两个十六进制数字时，视为一个已转义的八位组，跳过三个字符；
      十六进制大小写都接受。
    - 其他位置出现星号报 wildcard，出现左括号报 left_paren，出现右括号报
      right_paren。
    - 其他字符忽略。单独的反斜杠本身不是问题；如果它没有形成合法转义，后续
      字符仍按原样检查。

    返回格式
    --------
    只返回 wildcard、left_paren、right_paren 三个稳定代码，按首次出现顺序去重。
    安全输入返回 []。本函数检查的是准备嵌入过滤器的原始值，不假定输入已经是
    一个带外层括号的完整过滤器。

    容差 0
    ------
    filter_text 必须是 str，否则抛 TypeError。不 trim、不折叠空白、不规范化。
    """

    if not isinstance(filter_text, str):
        raise TypeError("filter_text must be str")

    found = []
    index = 0
    length = len(filter_text)
    while index < length:
        char = filter_text[index]
        if (
            char == "\\"
            and index + 2 < length
            and filter_text[index + 1] in _HEX_DIGITS
            and filter_text[index + 2] in _HEX_DIGITS
        ):
            index += 3
            continue
        if char == "*":
            code = "wildcard"
        elif char == "(":
            code = "left_paren"
        # 缺陷 7：右括号的闭合注入同样必须检出，不能只查左括号。
        elif char == ")":
            code = "right_paren"
        else:
            index += 1
            continue
        if code not in found:
            found.append(code)
        index += 1
    return found


def normalize(value: str) -> str:
    r"""规范化查询值：去掉首尾空白并折叠连续空白。

    规则
    ----
    - 使用 Python 的空白定义，包括空格、制表符、换行、回车与 Unicode 空白。
    - 先去掉首尾空白，再把内部一段或多段连续空白统一替换为一个 U+0020 空格。
    - 空串或全空白字符串返回空串。
    - 不做大小写折叠、不做 Unicode 规范化、不删除内部标点、不做转义、不改变
      非空白字符的顺序。

    容差 0
    ------
    value 必须是 str，其他类型抛 TypeError。除上述空白处理外，字符逐字符保持
    不变。
    """

    if not isinstance(value, str):
        raise TypeError("value must be str")
    # 缺陷 8：split() 去掉首尾空白并折叠内部连续空白，不改变非空白字符。
    return " ".join(value.split())


def validate_policy(policy: dict) -> list[str]:
    r"""检查安全策略，按固定顺序返回问题代码。

    策略字段与安全值
    ----------------
    - allow_raw_concat：必须为 False；为 True 表示允许把参数原样拼进过滤器。
    - allow_wildcard：必须为 False；为 True 表示不限制通配符。
    - escape_dn：必须为 True；为 False 表示标识名未转义。

    字段缺失时按安全值处理。字段一旦显式出现，值必须是 bool；其他类型按不安全
    值报告，不把字符串、数字或其他对象隐式转换成布尔值。

    问题代码
    --------
    按 raw_concat、wildcard、dn_escape 的固定顺序返回，不重复，不返回解释文本。
    安全策略返回 []。只校验，不修改 policy，不自动纠正。

    容差 0
    ------
    policy 必须是映射，否则抛 TypeError。只识别上述三个字段，未知字段不参与
    判定。
    """

    if not _is_mapping(policy):
        raise TypeError("policy must be a mapping")

    problems = []
    # 缺陷 9：allow_raw_concat 为 True（或非 bool）表示允许原样拼接，必须报出。
    if "allow_raw_concat" in policy and policy["allow_raw_concat"] is not False:
        problems.append("raw_concat")
    if "allow_wildcard" in policy and policy["allow_wildcard"] is not False:
        problems.append("wildcard")
    if "escape_dn" in policy and policy["escape_dn"] is not True:
        problems.append("dn_escape")
    return problems


def filter_batch(requests: list[dict], policy: dict) -> dict:
    r"""批量构造过滤器；每个请求独立解析、独立取值、独立转义。

    请求格式
    --------
    requests 是映射序列，每项包含：
    - id：非空 str，作为返回字典的键，必须唯一。
    - template：该请求自己的过滤器模板。
    - params：该请求自己的参数映射。

    行为
    ----
    - 先调用 validate_policy；存在问题代码时抛 ValueError，不构造任何过滤器。
    - 逐条调用 build_filter。不得缓存、复用或原地修改解析分段、params 或结果。
    - 返回 {id: filter_text}，按请求顺序插入。
    - 空请求序列返回 {}。

    错误
    ----
    requests 或单项不是映射抛 TypeError；缺少字段、id 为空、id 重复抛
    ValueError。模板、参数或策略错误按 build_filter 与 validate_policy 的契约
    向上抛。任何一条失败都不得返回部分结果。

    容差 0
    ------
    每个结果必须与单独调用 build_filter 完全一致；两批调用互不影响。
    """

    if isinstance(requests, (str, bytes, bytearray)):
        raise TypeError("requests must be a sequence of mappings")
    try:
        iterator = iter(requests)
    except TypeError:
        raise TypeError("requests must be a sequence of mappings") from None

    problems = validate_policy(policy)
    if problems:
        raise ValueError("unsafe policy: {0!r}".format(problems))

    # 缺陷 10：每个请求独立解析、独立取值，绝不复用上一次的分段或参数。
    result = {}
    seen = set()
    for request in iterator:
        if not _is_mapping(request):
            raise TypeError("request must be a mapping")
        for field in ("id", "template", "params"):
            if field not in request:
                raise ValueError("missing request field: {0}".format(field))
        request_id = request["id"]
        if not isinstance(request_id, str) or request_id == "":
            raise ValueError("request id must be a non-empty str")
        if request_id in seen:
            raise ValueError("duplicate request id: {0!r}".format(request_id))
        seen.add(request_id)
        result[request_id] = build_filter(request["template"], request["params"])
    return result
企业目录登录接进来之后，输入一个星号就能把所有账号列出来：值转义只处理反斜杠，通配与括号原样进入；转义用十六进制但不补两位，短码被截断；空字节不转义，过滤器被提前截断；标识名转义只处理逗号，等号与加号未处理；模板拼装把参数原样插入，未转义；模板解析允许任意位置占位符，结构被注入；注入检测只查左括号不查右括号，闭合注入漏检；规范化不去首尾空白，带空白值匹配失败；策略校验不检查是否允许原样拼接；批量构造复用模板分段，后一个请求命中前一个请求的参数。dirsvc/filter.py 是核心，tests/test_filter.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式

在仓库根目录执行 pytest tests -q。初始状态必须恰好是 15 failed，并且不能出现 collection、import 或 syntax error；8 个函数全部 raise NotImplementedError，因此 15 个用例都会在进入断言前直接失败。实现 src/dirsvc/filter.py 后应变成 15 passed，不允许修改 tests。

字段表

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言与框架：Python 3, pytest
环境可复现等级：无外部依赖

约束

tests 目录不可修改：不得增删用例、不得改断言、不得跳过，只能改 src/dirsvc/filter.py。本仓库采用 src 布局，实现包位于 src/dirsvc，导入路径由 pyproject.toml 的 pytest pythonpath 配置指定为 src，不使用 conftest.py，也不需要先安装。实现只允许使用标准库 re、base64 与 pytest，离线、无随机、不联网。## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |


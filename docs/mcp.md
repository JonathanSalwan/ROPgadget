# ROPgadget MCP Server

ROPgadget MCP Server 提供了 ROPgadget 的 AI Agent 接口，通过 Model Context Protocol (MCP) 实现程序化的 ROP gadget 查找和分析。

## 安装

### 依赖

```bash
pip install mcp
```

### 启动方式

```bash
python -m ropgadget.mcp --stdio
```

## 可用工具

### 1. find_gadgets
在二进制文件中查找 ROP gadgets。

```python
find_gadgets(binary_path="./binary", depth=5)
find_gadgets(binary_path="./binary", depth=5, only="pop rdi")
find_gadgets(binary_path="./binary", depth=5, range="0x400000-0x401000")
```

### 2. find_jop_gadgets
查找 JOP (Jump-Oriented Programming) gadgets。

```python
find_jop_gadgets(binary_path="./binary", depth=5)
```

### 3. find_syscall_gadgets
查找系统调用 gadgets。

```python
find_syscall_gadgets(binary_path="./binary")
```

### 4. get_binary_info
获取二进制文件信息。

```python
get_binary_info(binary_path="./binary")
# 返回: {"path": "./binary", "architecture": "x86", "endian": "Little", "bits": 64}
```

### 5. search_gadgets_by_pattern
按指令模式搜索 gadgets。

```python
search_gadgets_by_pattern(binary_path="./binary", pattern="pop rdi")
search_gadgets_by_pattern(binary_path="./binary", pattern="ret")
```

### 6. run_ropgadget_command
使用自定义参数运行 ROPgadget。

```python
run_ropgadget_command(binary_path="./binary", args=["--depth", "10", "--all"])
```

## 使用场景

### 1. AI 辅助 ROP 链构建
```python
# AI Agent 可以自动化查找所需的 gadgets
gadgets = find_gadgets(binary="./binary", depth=5)
pop_rdi = search_gadgets_by_pattern(binary="./binary", pattern="pop rdi")
ret = search_gadgets_by_pattern(binary="./binary", pattern="ret")
```

### 2. 自动化漏洞利用开发
```python
# 查找特定类型的 gadgets
jop_gadgets = find_jop_gadgets(binary="./binary")
syscall_gadgets = find_syscall_gadgets(binary="./binary")
```

### 3. 二进制分析
```python
# 获取二进制信息并分析
info = get_binary_info(binary="./binary")
gadgets = find_gadgets(binary="./binary", depth=5, range=f"{info['start']}-{info['end']}")
```

## 技术实现

### 架构
- 基于 MCP Python SDK
- 调用 ROPgadget 命令行工具
- 结构化 JSON 输出
- 支持 stdio 传输

### 核心功能
- ROP gadget 查找
- JOP gadget 查找
- 系统调用 gadget 查找
- 按模式过滤
- 地址范围限制

## 开发

### 添加新工具

在 `mcp/tools.py` 中实现新函数：

```python
def my_new_tool(binary_path: str, arg1: str = None) -> Dict[str, Any]:
    """工具描述"""
    try:
        cmd = ["ROPgadget", "--binary", binary_path]
        if arg1:
            cmd.extend(["--arg1", arg1])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # 解析输出
        return {"result": "..."}
    except Exception as e:
        return {"error": str(e)}
```

然后在 `TOOLS` 字典中注册：

```python
TOOLS = {
    "my_new_tool": {
        "function": my_new_tool,
        "description": "工具描述",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "二进制文件路径"},
                "arg1": {"type": "string", "description": "参数1"},
            },
            "required": ["binary_path"],
        },
    },
}
```

## 许可证

BSD 2-Clause License

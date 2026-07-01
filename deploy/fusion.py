"""
fusion.py - 调试器增强工具层

基于 core.py 现有 API 组合实现的 8 个增强工具，补充 LyScript 基础工具集缺失的能力：
1. get_all_registers        - 一次获取全部通用寄存器（减少 MCP 往返）
2. get_call_stack           - 获取当前调用栈
3. wait_breakpoint_snapshot - 断点命中后并行采集完整上下文快照
4. set_conditional_breakpoint - 设置条件断点（带命令注入防护）
5. compare_memory           - 比较两块内存区域差异
6. batch_read_memory        - 批量并发读取多个地址内存（带限流与边界校验）
7. get_memory_map_modules   - 获取内存映射模块列表
8. exec_with_retry          - 带重试的命令执行（区分幂等性）

设计原则：
- 复用 PeTools 已构造的 http_client/dbg/memory/script/dissasm 实例，不重复建连
- 所有工具异步执行，带超时保护，防止调试器忙碌时卡死
- 写操作/外部输入严格校验，防止命令注入
- 失败路径记录完整堆栈，不静默吞异常
"""

import asyncio
import json
import re
import logging
from typing import Union, List, Dict, Any

# 模块级日志器，用于记录异常完整堆栈（不静默吞错）
logger = logging.getLogger(__name__)


# ============================================================
# 内部辅助函数（避免与 main.py 循环导入，在此独立定义简单格式化器）
# ============================================================
def _fmt_success(result: Any) -> str:
    """格式化成功响应：{"status":"success","result":...}"""
    return json.dumps({
        "status": "success",
        "result": result
    }, ensure_ascii=False, indent=2)


def _fmt_error(message: str, details: Any = None) -> str:
    """格式化错误响应，details 非空时附加详情"""
    if details:
        msg = f"{message}（详情：{details}）"
    else:
        msg = message
    return json.dumps({
        "status": "error",
        "message": msg
    }, ensure_ascii=False, indent=2)


def _parse_addr(addr: str) -> int:
    """
    统一地址解析：地址统一按 16 进制解析。
    - "0x00401000" → 0x00401000
    - "00401000"   → 0x00401000（无前缀也按 16 进制）
    注意：十进制地址需调用方自行 int(addr, 10)，本函数默认 16 进制。
    """
    addr = addr.strip().lower()
    if addr.startswith("0x"):
        return int(addr, 16)
    # 无前缀也按 16 进制处理（与 x64dbg 地址习惯一致）
    return int(addr, 16)


def _build_addr_list(base_int: int, count: int, step: int) -> List[str]:
    """
    构造地址列表：从 base_int 起，按 step 步长生成 count 个地址字符串。
    ReadByte/ReadWord/ReadDword/ReadPtr 接收地址列表，每个地址读 1 个单元。
    """
    # 用 hex() 生成小写 0x 前缀地址，符合 ReadByte 校验规则
    return [hex(base_int + i * step) for i in range(count)]


# 只读命令前缀白名单：仅这些前缀的命令允许重试（幂等安全）
_READONLY_PREFIXES = ("disasm", "read", "get", "check", "show", "is_", "mem.read")
# 写操作命令前缀：副作用命令，强制不重试（max_retries=1）
_WRITE_PREFIXES = ("set", "write", "bp", "delete", "alloc", "free", "step", "run", "pause", "stop")


class FusionTools:
    """
    增强工具集 - 补充 LyScript 基础工具集缺失的能力。
    复用 PeTools 已构造的 API 实例，不重复建立 HTTP 连接。
    """

    def __init__(self, petools):
        """
        接收已初始化的 PeTools 实例，复用其 http_client 与各类 API 句柄。
        避免重复构造 Config/BaseHttpClient/Debugger/Memory/Script 等对象。
        """
        self.http_client = petools.http_client
        self.dbg = petools.dbg
        self.dissasm = petools.dissasm
        self.module = petools.module
        self.memory = petools.memory
        self.process = petools.process
        self.gui = petools.gui
        self.script = petools.script

    # ============================================================
    # 1. get_all_registers - 一次获取所有通用寄存器
    # ============================================================
    async def get_all_registers(self, timeout: float = 5.0) -> str:
        """
        功能：一次获取所有 64 位通用寄存器
        用途：断点分析、上下文捕获、快速状态检查
        调用示例：get_all_registers()
        返回：JSON 包含 rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp/r8-r15/rip/EFLAGS
        说明：LyScript get_register 支持列表入参，本工具一次批量获取减少往返；
              单个寄存器失败不影响整体（批量失败时降级为逐个获取）。
        """
        # 64 位通用寄存器列表（get_register 内部会转大写，返回键为大写）
        # 标志寄存器使用 EFLAGS（x64dbg 标准名称）
        reg_list = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                    "rbp", "rsp", "r8", "r9", "r10", "r11",
                    "r12", "r13", "r14", "r15", "rip", "EFLAGS"]
        try:
            # 优先批量获取（一次 HTTP 往返，效率最高）
            regs_data = await asyncio.to_thread(
                self.dbg.get_register, reg_list, timeout
            )
            # get_register 失败时 send_command 会抛异常，能走到这里说明整体成功
            if not isinstance(regs_data, dict):
                return _fmt_error("获取所有寄存器失败：返回类型异常", str(type(regs_data)))
        except Exception as batch_err:
            # 批量失败时降级为逐个获取：单个寄存器失败不影响整体
            logger.exception("批量获取寄存器失败，降级为逐个获取")
            regs_data = {}
            errors = []
            # 逐个并发获取，每个独立 try/except
            async def _get_one(reg_name: str) -> tuple:
                try:
                    r = await asyncio.to_thread(self.dbg.get_register, [reg_name], timeout)
                    # 返回键为大写，统一取大写
                    return reg_name.upper(), r.get(reg_name.upper()) if isinstance(r, dict) else None
                except Exception as e:
                    logger.exception("获取单个寄存器失败: %s", reg_name)
                    return reg_name.upper(), None
            results = await asyncio.gather(*[_get_one(r) for r in reg_list])
            for name, val in results:
                if val is None:
                    errors.append(name)
                else:
                    regs_data[name] = val
            if errors:
                regs_data["__failed__"] = errors

        # 整理成分组结构，便于阅读
        # get_register 返回键为大写，统一用大写取值
        formatted = {
            "general": {
                "rax": regs_data.get("RAX"),
                "rbx": regs_data.get("RBX"),
                "rcx": regs_data.get("RCX"),
                "rdx": regs_data.get("RDX"),
            },
            "index": {
                "rsi": regs_data.get("RSI"),
                "rdi": regs_data.get("RDI"),
            },
            "stack_frame": {
                "rbp": regs_data.get("RBP"),
                "rsp": regs_data.get("RSP"),
            },
            "extended": {
                "r8": regs_data.get("R8"),
                "r9": regs_data.get("R9"),
                "r10": regs_data.get("R10"),
                "r11": regs_data.get("R11"),
                "r12": regs_data.get("R12"),
                "r13": regs_data.get("R13"),
                "r14": regs_data.get("R14"),
                "r15": regs_data.get("R15"),
            },
            "instruction_pointer": {
                "rip": regs_data.get("RIP"),
            },
            "flags": {
                # EFLAGS 为标准名；若批量失败降级，可能记录在 __failed__ 中
                "EFLAGS": regs_data.get("EFLAGS"),
            }
        }
        return _fmt_success(formatted)

    # ============================================================
    # 2. get_call_stack - 获取当前调用栈
    # ============================================================
    async def get_call_stack(self, timeout: float = 5.0) -> str:
        """
        功能：获取当前调用栈
        用途：函数调用关系分析、漏洞根因定位、断点上下文理解
        调用示例：get_call_stack()
        返回：JSON 包含调用栈文本（地址/返回地址/函数名）
        说明：通过 Script.RunCmd 执行 x64dbg 的 k 命令获取调用栈。
        """
        try:
            # 注意：API 名为 RunCmd，不是 RunScriptCmd
            result = await asyncio.to_thread(
                self.script.RunCmd, "k", timeout
            )
            # RunCmd 返回 {"RunCmd": "..."} 或抛异常
            if isinstance(result, dict):
                # 取 RunCmd 字段，缺失则回退原结果
                stack_text = result.get("RunCmd", json.dumps(result, ensure_ascii=False))
            else:
                stack_text = str(result)
            return _fmt_success(stack_text)
        except Exception as e:
            logger.exception("获取调用栈失败")
            return _fmt_error("获取调用栈失败", e)

    # ============================================================
    # 3. wait_breakpoint_snapshot - 断点命中后并行采集完整上下文
    # ============================================================
    async def wait_breakpoint_snapshot(self, timeout: float = 30.0) -> str:
        """
        功能：等待断点命中并自动捕获完整上下文快照
        用途：高效调试，断点命中后一次获得寄存器/栈/反汇编/调用栈
        调用示例：wait_breakpoint_snapshot(timeout=30)
        返回：JSON 包含 breakpoint_hit/registers/call_stack/stack_data/current_disasm/errors
        说明：先 dbg.Wait 等待事件；拿到 rip/rsp 后，反汇编与栈读取 gather 真并行；
              任何子步骤失败记录到 errors 列表，不静默吞异常。
        """
        snapshot = {
            "breakpoint_hit": False,
            "registers": {},
            "call_stack": "",
            "stack_data": [],
            "current_disasm": "",
            "errors": []
        }
        try:
            # 第一步：等待断点/事件命中（send_command 失败会抛异常）
            wait_result = await asyncio.to_thread(self.dbg.Wait, timeout)
            # wait_result 形如 {"Wait":"Success","Event":"BreakpointHit"} 或 {"Wait":"Failed",...}
            if not isinstance(wait_result, dict) or wait_result.get("Wait", "").lower() != "success":
                # 未命中（如超时），返回当前快照与原因
                snapshot["errors"].append(f"Wait 未成功: {wait_result}")
                return _fmt_success(snapshot)

            snapshot["breakpoint_hit"] = True

            # 第二步：并行采集寄存器 + 调用栈（两者无依赖）
            reg_list = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                        "rbp", "rsp", "r8", "r9", "r10", "r11",
                        "r12", "r13", "r14", "r15", "rip", "EFLAGS"]
            regs_task = asyncio.to_thread(self.dbg.get_register, reg_list, 5.0)
            callstack_task = asyncio.to_thread(self.script.RunCmd, "k", 5.0)
            regs_result, callstack_result = await asyncio.gather(
                regs_task, callstack_task, return_exceptions=True
            )

            # 处理寄存器结果
            rip_val = None
            rsp_val = None
            if isinstance(regs_result, Exception):
                # 记录完整堆栈到日志，快照 errors 记录摘要
                logger.exception("快照：获取寄存器失败")
                snapshot["errors"].append(f"registers: {regs_result}")
            elif isinstance(regs_result, dict):
                snapshot["registers"] = regs_result
                rip_val = regs_result.get("RIP")
                rsp_val = regs_result.get("RSP")
            else:
                snapshot["errors"].append(f"registers: 返回类型异常 {type(regs_result)}")

            # 处理调用栈结果
            if isinstance(callstack_result, Exception):
                logger.exception("快照：获取调用栈失败")
                snapshot["call_stack"] = ""
                snapshot["errors"].append(f"call_stack: {callstack_result}")
            elif isinstance(callstack_result, dict):
                snapshot["call_stack"] = callstack_result.get("RunCmd", json.dumps(callstack_result, ensure_ascii=False))
            else:
                snapshot["call_stack"] = str(callstack_result)

            # 第三步：拿到 rip/rsp 后，反汇编与栈读取真并行（gather）
            # rip_val/rsp_val 判断改为 is not None and != ""（避免 0 地址被误判）
            phase2_tasks = []
            phase2_names = []

            if rip_val is not None and rip_val != "":
                # DisasmCountCode(address, count, timeout)：反汇编 5 条
                phase2_tasks.append(asyncio.to_thread(self.dissasm.DisasmCountCode, rip_val, 5, 5.0))
                phase2_names.append("disasm")
            else:
                snapshot["errors"].append("disasm: rip 为空，跳过反汇编")

            if rsp_val is not None and rsp_val != "":
                # ReadDword 接收地址列表，每个地址读 4 字节；64 个 dword = 256 字节栈
                try:
                    rsp_int = _parse_addr(str(rsp_val))
                    stack_addr_list = _build_addr_list(rsp_int, 64, 4)
                    phase2_tasks.append(asyncio.to_thread(self.memory.ReadDword, stack_addr_list, 5.0))
                    phase2_names.append("stack")
                except Exception as e:
                    logger.exception("快照：解析 rsp 构造栈地址列表失败")
                    snapshot["errors"].append(f"stack: 解析 rsp 失败 {e}")
            else:
                snapshot["errors"].append("stack: rsp 为空，跳过栈读取")

            # 并行执行第二阶段任务
            if phase2_tasks:
                phase2_results = await asyncio.gather(*phase2_tasks, return_exceptions=True)
                for name, res in zip(phase2_names, phase2_results):
                    if isinstance(res, Exception):
                        logger.exception("快照：%s 子任务失败", name)
                        snapshot["errors"].append(f"{name}: {res}")
                        continue
                    if name == "disasm":
                        # DisasmCountCode 返回 dict，取 result 字段或整体
                        if isinstance(res, dict):
                            snapshot["current_disasm"] = res.get("result", res)
                        else:
                            snapshot["current_disasm"] = str(res)
                    elif name == "stack":
                        # ReadDword 返回 {addr: "0x..."}，按地址列表顺序提取
                        if isinstance(res, dict):
                            stack_rows = []
                            for i, addr_str in enumerate(stack_addr_list):
                                val = res.get(addr_str)
                                if val is not None:
                                    stack_rows.append({
                                        "offset": i * 4,
                                        "addr": addr_str,
                                        "value": val
                                    })
                            snapshot["stack_data"] = stack_rows
                        else:
                            snapshot["errors"].append(f"stack: 返回类型异常 {type(res)}")

            return _fmt_success(snapshot)
        except Exception as e:
            logger.exception("断点快照捕获失败")
            return _fmt_error("断点快照捕获失败", e)

    # ============================================================
    # 4. set_conditional_breakpoint - 条件断点（带命令注入防护）
    # ============================================================
    # 地址白名单：仅允许 0x 前缀十六进制或纯数字
    _ADDR_RE = re.compile(r'^(0x[0-9a-fA-F]+|\d+)$')
    # 条件白名单：仅允许字母/数字/比较运算符/逻辑运算符/方括号/空格等安全字符
    _COND_RE = re.compile(r'^[a-zA-Z0-9_()==!<>+\-*/&|^% \[\]0x[0-9a-fA-F]+$')

    async def set_conditional_breakpoint(self, address: str,
                                         condition: str,
                                         timeout: float = 5.0) -> str:
        """
        功能：设置条件断点
        用途：只在特定条件满足时断下（如 eax==0x1234），提升调试效率
        调用示例：set_conditional_breakpoint(address="0x00401000", condition="eax==0x1234")
        返回：JSON 表示设置成功/失败
        说明：先 SetBreakPoint 设普通断点，再用 RunCmd 设置条件；
              对 address 与 condition 做正则白名单校验，防止命令注入。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(address, str) or not self._ADDR_RE.match(address.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", address)
            # 校验条件表达式（防止注入：禁止引号/分号/反引号等危险字符）
            if not isinstance(condition, str) or not self._COND_RE.match(condition.strip()):
                return _fmt_error("条件表达式含非法字符（仅允许字母数字与常用运算符）", condition)

            clean_addr = address.strip()
            clean_cond = condition.strip()

            # 第一步：设置普通断点
            bp_result = await asyncio.to_thread(
                self.dbg.SetBreakPoint, clean_addr, timeout
            )
            # SetBreakPoint 返回 {"SetBreakPoint":"Success",...} 或抛异常
            if isinstance(bp_result, dict) and bp_result.get("SetBreakPoint", "").lower() != "success":
                return _fmt_error("设置普通断点失败", bp_result)

            # 第二步：设置断点条件（用 RunCmd，不是 RunScriptCmd）
            # 条件已通过白名单校验，可安全拼接
            cmd = f"SetBreakpointCondition {clean_addr}, \"{clean_cond}\""
            cond_result = await asyncio.to_thread(
                self.script.RunCmd, cmd, timeout
            )

            return _fmt_success({
                "address": clean_addr,
                "condition": clean_cond,
                "breakpoint_set": True,
                "condition_set": cond_result
            })
        except Exception as e:
            logger.exception("设置条件断点失败")
            return _fmt_error("设置条件断点失败", e)

    # ============================================================
    # 5. compare_memory - 比较两块内存区域差异
    # ============================================================
    async def compare_memory(self, address1: str, address2: str,
                             size: int, timeout: float = 10.0) -> str:
        """
        功能：比较两块内存区域的差异
        用途：验证 patch 效果、对比原始代码与修改后代码
        调用示例：compare_memory(address1="0x00401000", address2="0x00402000", size=256)
        返回：JSON 包含差异列表（偏移/地址1的值/地址2的值）
        说明：ReadByte 接收地址列表，每个地址读 1 字节，返回 {地址: "0x41"} dict；
              本工具构造 [hex(base+i) for i in range(size)] 地址列表，并行读两块内存。
        """
        try:
            # 边界校验：size 必须为正整数，且限制上限避免单次请求过大
            if not isinstance(size, int) or size <= 0:
                return _fmt_error("size 必须为正整数", size)
            if size > 4096:
                return _fmt_error("size 超过上限 4096，请分批比较", size)

            # 解析两个基地址（统一 16 进制）
            try:
                base1 = _parse_addr(address1)
                base2 = _parse_addr(address2)
            except ValueError:
                return _fmt_error("地址解析失败（需为 16 进制）", f"{address1} / {address2}")

            # 构造地址列表：ReadByte 每个地址读 1 字节
            addr_list1 = _build_addr_list(base1, size, 1)
            addr_list2 = _build_addr_list(base2, size, 1)

            # 并行读取两块内存（ReadByte 无 size 参数，传地址列表）
            read1_task = asyncio.to_thread(self.memory.ReadByte, addr_list1, timeout)
            read2_task = asyncio.to_thread(self.memory.ReadByte, addr_list2, timeout)
            data1, data2 = await asyncio.gather(read1_task, read2_task)

            # ReadByte 返回 {地址字符串: "0x41"} dict
            if not isinstance(data1, dict) or not isinstance(data2, dict):
                return _fmt_error("内存读取失败：返回类型异常",
                                  f"data1={type(data1)} data2={type(data2)}")

            # 逐字节比较，按地址列表顺序提取值
            differences = []
            compared = 0
            for i in range(size):
                v1 = data1.get(addr_list1[i])
                v2 = data2.get(addr_list2[i])
                # 任一缺失则停止比较（读取不完整）
                if v1 is None or v2 is None:
                    break
                compared += 1
                if v1 != v2:
                    differences.append({
                        "offset": i,
                        "addr1": addr_list1[i],
                        "value1": v1,
                        "addr2": addr_list2[i],
                        "value2": v2,
                    })

            return _fmt_success({
                "total_compared": compared,
                "differences_count": len(differences),
                # 限制返回数量避免响应过大
                "differences": differences[:100],
                "truncated": len(differences) > 100
            })
        except Exception as e:
            logger.exception("内存比较失败")
            return _fmt_error("内存比较失败", e)

    # ============================================================
    # 6. batch_read_memory - 批量并发读取多个地址内存（限流 + 边界校验）
    # ============================================================
    # 类型 → (读取方法名, 单元步长)。未知类型不静默降级，直接报错
    _TYPE_MAP = {
        "byte": ("ReadByte", 1),
        "word": ("ReadWord", 2),
        "dword": ("ReadDword", 4),
        "ptr": ("ReadPtr", 8),
    }

    async def batch_read_memory(self, address_size_list: List[Dict[str, Any]],
                                timeout: float = 15.0) -> str:
        """
        功能：批量读取多个地址的内存
        用途：一次获取多个关键地址的数据（如同时读取多个全局变量）
        调用示例：batch_read_memory(address_size_list=[
            {"address": "0x00401000", "size": 16, "type": "byte"},
            {"address": "0x00402000", "size": 4, "type": "dword"}
        ])
        返回：JSON 包含每个地址的读取结果
        说明：type 支持 byte/word/dword/ptr；用 Semaphore(10) 限并发；
              空列表拒绝，列表上限 100；未知 type 直接报错不静默降级。
        """
        try:
            # 边界校验：空列表直接拒绝
            if not address_size_list:
                return _fmt_error("address_size_list 不能为空")
            # 列表长度上限 100，避免请求爆炸
            if len(address_size_list) > 100:
                return _fmt_error("address_size_list 长度超过上限 100", len(address_size_list))

            # 限流信号量：最多 10 个并发读取
            sem = asyncio.Semaphore(10)

            async def _read_one(item: Dict[str, Any]) -> Dict[str, Any]:
                """读取单个地址块，封装结果与错误"""
                # 用 .get() 取值，缺键记录错误
                addr = item.get("address")
                size = item.get("size", 1)
                read_type = item.get("type", "byte")

                entry = {
                    "address": addr,
                    "type": read_type,
                    "size": size
                }

                # 缺少必要键 address 记录错误
                if not addr or not isinstance(addr, str):
                    entry["status"] = "error"
                    entry["error"] = f"缺少有效 address 字段: {item}"
                    return entry

                # 未知 type 直接报错，不静默降级
                if read_type not in self._TYPE_MAP:
                    entry["status"] = "error"
                    entry["error"] = f"未知 type: {read_type}（支持 byte/word/dword/ptr）"
                    return entry

                # size 必须为正整数
                if not isinstance(size, int) or size <= 0:
                    entry["status"] = "error"
                    entry["error"] = f"size 非法: {size}"
                    return entry

                method_name, step = self._TYPE_MAP[read_type]
                try:
                    base_int = _parse_addr(addr)
                except ValueError as e:
                    entry["status"] = "error"
                    entry["error"] = f"地址解析失败: {e}"
                    return entry

                # 构造地址列表：每个地址读 1 个单元（1/2/4/8 字节）
                addr_list = _build_addr_list(base_int, size, step)
                # 取对应 Read 方法
                read_method = getattr(self.memory, method_name)

                async with sem:
                    try:
                        result = await asyncio.to_thread(read_method, addr_list, timeout)
                    except Exception as e:
                        logger.exception("批量读取单地址失败: %s", addr)
                        entry["status"] = "error"
                        entry["error"] = str(e)
                        return entry

                # Read* 返回 {地址: "0x..."} dict，按顺序提取值
                if isinstance(result, dict):
                    values = [result.get(a) for a in addr_list]
                    entry["status"] = "success"
                    entry["data"] = values
                else:
                    entry["status"] = "error"
                    entry["error"] = f"返回类型异常: {type(result)}"
                return entry

            # 并发执行所有读取任务（Semaphore 内部限流）
            results = await asyncio.gather(*[_read_one(item) for item in address_size_list])

            return _fmt_success({
                "total": len(results),
                "success_count": sum(1 for r in results if r.get("status") == "success"),
                "error_count": sum(1 for r in results if r.get("status") == "error"),
                "results": results
            })
        except Exception as e:
            logger.exception("批量内存读取失败")
            return _fmt_error("批量内存读取失败", e)

    # ============================================================
    # 7. get_memory_map_modules - 获取内存映射模块列表
    # ============================================================
    async def get_memory_map_modules(self, timeout: float = 5.0) -> str:
        """
        功能：获取内存映射中的所有模块
        用途：分析进程加载的所有模块、查找特定 DLL、内存布局分析
        调用示例：get_memory_map_modules()
        返回：JSON 包含内存映射信息
        说明：通过 Script.RunCmd 执行 x64dbg 的 memmap 命令获取内存映射。
        """
        try:
            # 注意：API 名为 RunCmd，不是 RunScriptCmd
            result = await asyncio.to_thread(
                self.script.RunCmd, "memmap", timeout
            )
            if isinstance(result, dict):
                text = result.get("RunCmd", json.dumps(result, ensure_ascii=False))
            else:
                text = str(result)
            return _fmt_success(text)
        except Exception as e:
            logger.exception("获取内存映射失败")
            return _fmt_error("获取内存映射失败", e)

    # ============================================================
    # 8. exec_with_retry - 带重试的命令执行（区分幂等性）
    # ============================================================
    async def exec_with_retry(self, command: str,
                              max_retries: int = 3,
                              retry_interval: float = 1.0,
                              timeout: float = 5.0) -> str:
        """
        功能：带重试机制的命令执行
        用途：调试器忙碌时自动重试只读命令，避免单次失败导致流程中断
        调用示例：exec_with_retry(command="disasm(0x00401000)", max_retries=3)
        返回：JSON 包含最终执行结果和重试次数
        说明：仅对只读命令（disasm/read/get/check/show/is_/mem.read）重试；
              写操作（set/write/bp/delete/alloc/free/step/run/pause/stop）强制 max_retries=1；
              不在白名单内的命令拒绝执行，防止命令注入。
        """
        try:
            if not isinstance(command, str) or not command.strip():
                return _fmt_error("command 不能为空")

            clean_cmd = command.strip()
            # 提取命令根名（取 "(" 之前部分），小写用于前缀匹配
            cmd_root = clean_cmd.split("(", 1)[0].strip().lower()

            # 分类命令：只读 / 写 / 未知
            is_readonly = any(cmd_root.startswith(p) for p in _READONLY_PREFIXES)
            is_write = any(cmd_root.startswith(p) for p in _WRITE_PREFIXES)

            if is_write:
                # 写操作有副作用，强制不重试
                effective_retries = 1
            elif is_readonly:
                # 只读幂等命令允许重试
                effective_retries = max(1, max_retries)
            else:
                # 不在白名单内：拒绝执行（防止命令注入）
                return _fmt_error("命令不在允许的白名单内（仅允许只读或已知写操作）", command)

            last_error = None
            for attempt in range(1, effective_retries + 1):
                try:
                    # 注意：API 名为 RunCmd，不是 RunScriptCmd
                    result = await asyncio.to_thread(
                        self.script.RunCmd, clean_cmd, timeout
                    )
                    # RunCmd 业务失败时 send_command 已抛异常，能走到这里即成功
                    if isinstance(result, dict):
                        out = result.get("RunCmd", result)
                    else:
                        out = str(result)
                    return _fmt_success({
                        "result": out,
                        "attempts": attempt,
                        "retriable": is_readonly
                    })
                except Exception as e:
                    # 记录完整堆栈，便于排查
                    logger.exception("exec_with_retry 第 %d 次失败: %s", attempt, clean_cmd)
                    last_error = e
                    # 写操作不重试；只读操作在未达上限时等待后重试
                    if attempt < effective_retries:
                        await asyncio.sleep(retry_interval)

            return _fmt_error(
                f"命令执行失败（重试 {effective_retries} 次后仍失败）",
                str(last_error)
            )
        except Exception as e:
            logger.exception("exec_with_retry 异常")
            return _fmt_error("重试执行异常", e)

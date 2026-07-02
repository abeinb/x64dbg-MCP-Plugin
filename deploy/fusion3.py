"""
fusion3.py - 第三轮融合增强工具集（深耕 x64dbg/x32dbg 深度能力）

针对 VMP 脱壳、卡密验证、反调试绕过三大场景，基于 core.py 真实 API 实现 20 个工具。

API 签名验证说明（已通过 Grep + Read 实际验证 core.py 第 5884-6142 行等位置）：
- Process.GetPid/GetTid(timeout)           -> {"GetPid":"1234"} / {"GetTid":"5678"}
- Process.GetPeb(pid:str, timeout)          -> {"GetPeb":"0x7FFDE000"}
- Process.GetTeb(tid:str, timeout)          -> {"GetTeb":"0x7FFDF000"}
- Memory.ReadByte/ReadWord/ReadDword/ReadPtr(addresses:str|list, timeout) -> {addr:"0x..."}
- Memory.WriteByte(address, value, timeout) -> {"WriteByte":"Success"} 或 {"WriteByte":"Failed","Reason":...}
- Memory.WriteDword(address, value, timeout)-> {"WriteDword":"Success"}
- Memory.WritePattern(pattern, address, length, timeout) -> {"WritePattern":"Success"} （pattern 不允许通配符）
- Memory.SetProtect(address, size, protect, timeout) -> {"SetProtect":"Success"}
- Memory.ScanModule(pattern, module_base, timeout) -> {"ScanModule":["0x...","0x..."]} （pattern 支持 ?? 通配符）
- Memory.GetXrefCountAt(addresses, timeout) -> {addr:"5"} （count 是字符串）
- Memory.GetXrefTypeAt(addresses, timeout)  -> {addr:["call","jump"]}
- Memory.GetFunctionTypeAt(addresses, timeout) -> {addr:"void (*)(int,char*)"}
- Memory.IsValidReadPtr(addresses, timeout) -> {addr:"True"}
- Memory.RemoteAlloc(address, size, timeout)-> {"RemoteAlloc":"0x00A35000"}
- Debugger.SetHardwareBreakPoint(address:str, break_type:int(1-4), timeout) -> {"SetHardwareBreakPoint":"Success",...}
- Debugger.DeleteHardwareBreakPoint(address, timeout) -> {"DeleteHardwareBreakPoint":"Success"}
- Debugger.get_register(registers:str|list, timeout) -> {REG:"0x..."} （键为大写）
- Debugger.Wait(timeout) -> {"Wait":"Success","Event":"BreakpointHit"}
- Debugger.Run(timeout) -> {"Run":"Success"}
- Debugger.StepOver(timeout) -> {"StepOver":"Success","NextAddress":"0x..."}
- Module.GetMainModuleInfoEx(timeout) -> {sections[], base_address, size, oep, entry_point}
- Module.GetMainModuleBase(timeout) -> {"base_address":"0x00400000"}
- Module.GetMainModuleSize(timeout) -> {"size":0x20000}
- Module.GetMainModuleEntry(timeout) -> {"entry_point":"0x00401000"}
- Module.GetSectionListFromAddr(address, timeout) -> {sections[]}
- Module.GetImport(module_name, timeout) -> {imports[]}
- Module.GetExport(module_name, timeout) -> {exports[]}
- Module.GetOEPFromName(module_name, timeout) -> {"oep":"0x00401000"}
- Module.GetModuleProcAddress(module_name, function_name, timeout) -> {"address":"0x..."}
- Script.RunCmd(cmd, timeout) -> {"RunCmd":"0x..."} 或 {"RunCmd":"Error","Reason":...}
- Dissassembly.DisasmOneCode(address:str|int, timeout) -> 反汇编信息
- Dissassembly.AssembleCodeHex(assembly_instruction, timeout) -> {"hex":"B801000000","size":5}
- Dissassembly.GetBranchDestination(address, timeout) -> 分支目标信息

设计原则：
- @property 延迟加载 petools 属性，让纯计算工具不依赖完整 petools
- 所有工具异步执行（asyncio.to_thread 包装同步 core.py 调用）
- 命令注入防护：地址/命令/条件均用正则白名单校验
- 错误处理：logger.exception 记录完整堆栈，不静默吞异常
- 中文注释，保留完整逻辑链，不简化
"""

import asyncio
import base64
import hashlib
import json
import logging
import re
from typing import Union, List, Dict, Any, Optional

# 模块级日志器，用于记录异常完整堆栈（不静默吞错）
logger = logging.getLogger(__name__)


# ============================================================
# 输入校验正则（防止命令注入，参考 fusion.py/fusion2.py）
# ============================================================
# 修复毒舌审查Bug: _ADDR_RE 与 _parse_addr 逻辑统一，允许无前缀十六进制
_ADDR_RE = re.compile(r'^(0x[0-9a-fA-F]+|[0-9a-fA-F]+|\d+)$')
# 修复毒舌审查Bug: _COND_RE 字符类错误修复——用分组表达 0x 前缀十六进制，而非字面量
# 条件表达式白名单：寄存器名(a-z,A-Z,0-9,_) + 比较运算符(==,!=,<,>) + 逻辑运算符(&,|,^,!) + 算术(+,-,*,/,%) + 0x 十六进制 + 空格 + 方括号
_COND_RE = re.compile(r'^(?:0x[0-9a-fA-F]+|[a-zA-Z0-9_\[\]()]==!<>+\-*/&|^% ])+$')
# 修复毒舌审查Bug: _ASM_RE 字符类错误修复——用分组表达 0x 前缀十六进制
# 汇编指令白名单：助记符 + 寄存器 + 立即数(0x 十六进制或十进制) + 内存寻址[] + 逗号空格
_ASM_RE = re.compile(r'^(?:0x[0-9a-fA-F]+|[a-zA-Z0-9_,\[\]\s+\-*/])+$')
# 字节模式白名单：允许十六进制字符与空格（用于 WritePattern）
_BYTE_PATTERN_RE = re.compile(r'^[0-9a-fA-F ]+$')
# 模块名白名单：允许字母数字、点、下划线、连字符
_MODULE_NAME_RE = re.compile(r'^[a-zA-Z0-9_.\-]+$')
# 函数名白名单：允许字母数字、下划线
_FUNC_NAME_RE = re.compile(r'^[a-zA-Z0-9_]+$')


# ============================================================
# 内部辅助函数（避免与 main.py/fusion.py/fusion2.py 循环导入，在此独立定义）
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
    统一地址解析：
    - 纯十进制（全数字）按 10 进制
    - 0x 前缀按 16 进制
    - 无前缀但含 a-f 按 16 进制
    """
    if not isinstance(addr, str):
        raise ValueError(f"地址必须是字符串，收到 {type(addr).__name__}")
    addr = addr.strip()
    if not addr:
        raise ValueError("地址不能为空")
    # 纯十进制（全数字）
    if addr.isdigit():
        return int(addr, 10)
    # 0x 前缀十六进制
    if addr.lower().startswith("0x"):
        return int(addr, 16)
    # 无前缀但含 a-f，按十六进制
    try:
        return int(addr, 16)
    except ValueError:
        raise ValueError(f"无法解析地址: {addr}")


def _fmt_addr(val: int) -> str:
    """格式化地址为 0x 前缀十六进制字符串（大写）"""
    return f"0x{val:X}"


def _build_addr_list(base_int: int, count: int, step: int) -> List[str]:
    """
    构造地址列表：从 base_int 起，按 step 步长生成 count 个地址字符串。
    ReadByte/ReadWord/ReadDword/ReadPtr 接收地址列表，每个地址读 1 个单元。
    用 hex() 生成小写 0x 前缀地址，符合 Read 系列校验规则。
    """
    return [hex(base_int + i * step) for i in range(count)]


def _extract_value(result: Any) -> Any:
    """
    从 core.py API 返回值中提取实际数据（处理无 status 字段的情况）。
    单 key dict 直接取值；多 key dict 按常见数据字段名优先级提取。
    """
    if isinstance(result, dict):
        keys = list(result.keys())
        # 单 key dict：直接取值
        # 适用于 {"GetPeb":"0x..."} / {"GetTeb":"0x..."} / {"GetPid":"1234"} 等
        if len(keys) == 1:
            return result[keys[0]]
        # 多 key dict 按常见数据字段名优先级尝试提取
        for preferred_key in ("sections", "imports", "exports", "instructions",
                              "modules", "result", "value", "data", "oep",
                              "entry_point", "base_address", "size", "address"):
            if preferred_key in result:
                return result[preferred_key]
        # 找不到优先 key，返回 None
        return None
    return result


def _extract_scan_results(scan_result: Any) -> List[str]:
    """从 ScanModule 返回值中提取匹配地址列表"""
    if isinstance(scan_result, dict):
        # 格式：{"ScanModule": ["0x...", "0x..."]}
        for key, val in scan_result.items():
            if isinstance(val, list):
                return val
        return []
    elif isinstance(scan_result, list):
        return scan_result
    return []


def _is_success(result: Any, key: str) -> bool:
    """
    判断 core.py 写操作返回是否成功。
    例如 WriteByte 返回 {"WriteByte":"Success"}，key="WriteByte"。
    """
    if isinstance(result, dict):
        val = result.get(key, "")
        if isinstance(val, str):
            return val.lower() == "success"
    return False


def _get_dict_value(result: Any, key: str, default: Any = None) -> Any:
    """安全从 dict 取值，非 dict 返回 default"""
    if isinstance(result, dict):
        return result.get(key, default)
    return default


class FusionTools3:
    """
    第三轮融合增强工具集 - 深耕 x64dbg/x32dbg 深度能力
    针对 VMP 脱壳、卡密验证、反调试绕过三大场景。

    复用 PeTools 的 API 实例（通过 @property 延迟加载），
    让纯计算工具不依赖完整 petools。
    """

    def __init__(self, petools):
        """
        接收 PeTools 实例，使用 @property 延迟访问其 API 实例。
        这样即使 petools 不完整（如纯计算场景），相关工具也能工作。
        """
        self.petools = petools
        # 延迟访问 petools 的 API 实例，只有实际调用相关工具时才需要
        self._dbg = None
        self._dissasm = None
        self._module = None
        self._memory = None
        self._process = None
        self._gui = None
        self._script = None
        # 修复毒舌审查P0 Bug: 调试器状态操作并发安全锁
        # x64dbg 是单实例状态机，多个工具同时 Wait/Run/SetBreakPoint 会竞态翻车
        # 所有调试器状态操作（SetHardwareBreakPoint/Wait/Run/StepOver/DeleteHardwareBreakPoint）
        # 必须通过此锁串行化
        # 修复毒舌审查P0 Bug-2: 锁必须提到 PeTools 层级，让所有 FusionTools 共用同一把锁
        # 否则 fusion/fusion2/fusion3 各持自己的锁仍会跨工具并发竞态
        self._debugger_lock = petools.debugger_lock

    # ============================================================
    # @property 延迟加载（参考 fusion2.py）
    # ============================================================
    @property
    def dbg(self):
        if self._dbg is None:
            self._dbg = getattr(self.petools, 'dbg', None)
        return self._dbg

    @property
    def dissasm(self):
        if self._dissasm is None:
            self._dissasm = getattr(self.petools, 'dissasm', None)
        return self._dissasm

    @property
    def module(self):
        if self._module is None:
            self._module = getattr(self.petools, 'module', None)
        return self._module

    @property
    def memory(self):
        if self._memory is None:
            self._memory = getattr(self.petools, 'memory', None)
        return self._memory

    @property
    def process(self):
        if self._process is None:
            self._process = getattr(self.petools, 'process', None)
        return self._process

    @property
    def gui(self):
        if self._gui is None:
            self._gui = getattr(self.petools, 'gui', None)
        return self._gui

    @property
    def script(self):
        if self._script is None:
            self._script = getattr(self.petools, 'script', None)
        return self._script

    # ============================================================
    # P0 必做：反调试绕过核心
    # ============================================================
    # 1. check_anti_debug_status - 反调试状态全面检测
    # ============================================================
    async def check_anti_debug_status(self, timeout: float = 5.0) -> str:
        """
        功能：反调试状态全面检测
        用途：检测进程是否被反调试机制发现，定位需要绕过的字段
        调用示例：check_anti_debug_status()
        返回：JSON 包含 peb_base/being_debugged/nt_global_flag/heap_flags/teb_base/seh_chain_head
        说明：调用 GetPeb + GetTeb + ReadByte/ReadDword 读取关键反调试字段：
              - PEB.BeingDebugged (PEB+0x2, byte)
              - PEB.NtGlobalFlag (PEB+0x68, dword)
              - ProcessHeap.Flags (PEB+0x30 拿 heap base, heap+0x70 拿 flags, dword)
              - TEB.NtTib.ExceptionList (TEB+0x0, ptr) - x86 SEH 链头
              偏移基于 x64 进程（任务要求），x86 场景需调用方自行调整。
        """
        try:
            # 校验依赖的 API 实例是否可用
            if self.process is None or self.memory is None:
                return _fmt_error("petools 缺少 process/memory 实例")

            # 第一步：获取 PID 和 TID（GetPid/GetTid 无参数，仅 timeout）
            pid_result = await asyncio.to_thread(self.process.GetPid, timeout)
            tid_result = await asyncio.to_thread(self.process.GetTid, timeout)
            # GetPid 返回 {"GetPid":"1234"}，提取实际值
            pid_str = str(_extract_value(pid_result))
            tid_str = str(_extract_value(tid_result))

            # 第二步：获取 PEB 和 TEB 基地址
            # GetPeb/GetTeb 要求 pid/tid 为字符串
            peb_result = await asyncio.to_thread(self.process.GetPeb, pid_str, timeout)
            teb_result = await asyncio.to_thread(self.process.GetTeb, tid_str, timeout)
            peb_base_str = str(_extract_value(peb_result))
            teb_base_str = str(_extract_value(teb_result))
            peb_base = _parse_addr(peb_base_str)
            teb_base = _parse_addr(teb_base_str)

            # 第三步：读取 PEB.BeingDebugged (PEB+0x2, 1 byte)
            being_debugged_addr = _fmt_addr(peb_base + 0x2)
            bd_result = await asyncio.to_thread(self.memory.ReadByte, being_debugged_addr, timeout)
            being_debugged = _get_dict_value(bd_result, being_debugged_addr, "0x0")

            # 第四步：读取 PEB.NtGlobalFlag (PEB+0x68, 4 bytes)
            nt_global_flag_addr = _fmt_addr(peb_base + 0x68)
            ngf_result = await asyncio.to_thread(self.memory.ReadDword, nt_global_flag_addr, timeout)
            nt_global_flag = _get_dict_value(ngf_result, nt_global_flag_addr, "0x0")

            # 第五步：读取 ProcessHeap 基地址 (PEB+0x30, ptr) 再读 Heap.Flags (heap+0x70, dword)
            process_heap_ptr_addr = _fmt_addr(peb_base + 0x30)
            ph_result = await asyncio.to_thread(self.memory.ReadPtr, process_heap_ptr_addr, timeout)
            process_heap_str = _get_dict_value(ph_result, process_heap_ptr_addr, "0x0")
            heap_flags = "0x0"
            if process_heap_str and process_heap_str != "0x0":
                heap_base = _parse_addr(process_heap_str)
                heap_flags_addr = _fmt_addr(heap_base + 0x70)
                hf_result = await asyncio.to_thread(self.memory.ReadDword, heap_flags_addr, timeout)
                heap_flags = _get_dict_value(hf_result, heap_flags_addr, "0x0")

            # 第六步：读取 TEB.NtTib.ExceptionList (TEB+0x0, ptr) - x86 SEH 链头
            seh_head_addr = _fmt_addr(teb_base + 0x0)
            seh_result = await asyncio.to_thread(self.memory.ReadPtr, seh_head_addr, timeout)
            seh_chain_head = _get_dict_value(seh_result, seh_head_addr, "0x0")

            # 整理结果
            return _fmt_success({
                "peb_base": peb_base_str,
                "being_debugged": being_debugged,
                "nt_global_flag": nt_global_flag,
                "process_heap": process_heap_str,
                "heap_flags": heap_flags,
                "teb_base": teb_base_str,
                "seh_chain_head": seh_chain_head,
                "is_being_debugged": being_debugged not in ("0x0", "0", "0x00"),
                "has_anti_debug_flags": nt_global_flag not in ("0x0", "0")
            })
        except Exception as e:
            logger.exception("反调试状态检测失败")
            return _fmt_error("反调试状态检测失败", e)

    # ============================================================
    # 2. bypass_anti_debug_peb - 绕过 PEB 反调试标志
    # ============================================================
    async def bypass_anti_debug_peb(self, timeout: float = 5.0) -> str:
        """
        功能：绕过 PEB 反调试标志（仅对查 PEB 的简单反调试有效）
        用途：清除 BeingDebugged/NtGlobalFlag/Heap.Flags 让进程认为未被调试
        调用示例：bypass_anti_debug_peb()
        返回：JSON 包含 peb_base 和 patched_fields 列表（每个字段含 field/offset/old/new/status）
        说明：先读原值再写 0，记录 old 值。调用 GetPeb + WriteByte/WriteDword。
              - PEB.BeingDebugged (PEB+0x2): WriteByte 改为 0
              - PEB.NtGlobalFlag (PEB+0x68): WriteDword 改为 0
              - ProcessHeap.Flags (heap+0x70): WriteDword 改为 0
        重要限制（修复毒舌审查P1 Bug: 文档必须明确说明适用范围）：
              本工具仅对直接调用 IsDebuggerPresent / 检查 PEB.BeingDebugged 的简单反调试有效。
              以下场景无效：
              - VMP 3.x 加壳：VMP 使用 direct syscall 绕过 ntdll 导出函数，
                直接调用 NtQueryInformationProcess 查 ProcessDebugPort，不查 PEB
              - ScyllaHide/TitanHide 已 hook 的场景：可能重复 patch 导致状态不一致
              - 检测 PEB.BeingDebugged 通过 NtQueryInformationProcess(ProcessDebugPort)
                的反调试：需另外 patch ProcessDebugPort
              - 主动校验 Heap.Flags 一致性的反调试：本工具写 0 后可能被检测到不一致
              对 VMP 3.x 卡密验证，应使用内存断点定位验证函数 + 直接 patch 验证逻辑，
              不能依赖本工具。
        """
        try:
            if self.process is None or self.memory is None:
                return _fmt_error("petools 缺少 process/memory 实例")

            # 获取 PID 和 PEB 基地址
            pid_result = await asyncio.to_thread(self.process.GetPid, timeout)
            pid_str = str(_extract_value(pid_result))
            peb_result = await asyncio.to_thread(self.process.GetPeb, pid_str, timeout)
            peb_base_str = str(_extract_value(peb_result))
            peb_base = _parse_addr(peb_base_str)

            patched_fields = []

            # 字段1：PEB.BeingDebugged (PEB+0x2, byte) - 先读后写
            bd_addr = _fmt_addr(peb_base + 0x2)
            old_bd_result = await asyncio.to_thread(self.memory.ReadByte, bd_addr, timeout)
            old_bd = _get_dict_value(old_bd_result, bd_addr, "0x0")
            # WriteByte 的 value 必须是字符串
            write_bd_result = await asyncio.to_thread(self.memory.WriteByte, bd_addr, "0x0", timeout)
            patched_fields.append({
                "field": "BeingDebugged",
                "offset": "PEB+0x2",
                "address": bd_addr,
                "old": old_bd,
                "new": "0x0",
                "status": "Success" if _is_success(write_bd_result, "WriteByte") else "Failed"
            })

            # 字段2：PEB.NtGlobalFlag (PEB+0x68, dword) - 先读后写
            ngf_addr = _fmt_addr(peb_base + 0x68)
            old_ngf_result = await asyncio.to_thread(self.memory.ReadDword, ngf_addr, timeout)
            old_ngf = _get_dict_value(old_ngf_result, ngf_addr, "0x0")
            write_ngf_result = await asyncio.to_thread(self.memory.WriteDword, ngf_addr, "0x0", timeout)
            patched_fields.append({
                "field": "NtGlobalFlag",
                "offset": "PEB+0x68",
                "address": ngf_addr,
                "old": old_ngf,
                "new": "0x0",
                "status": "Success" if _is_success(write_ngf_result, "WriteDword") else "Failed"
            })

            # 字段3：ProcessHeap.Flags (heap+0x70, dword) - 需先读 heap base
            ph_ptr_addr = _fmt_addr(peb_base + 0x30)
            ph_result = await asyncio.to_thread(self.memory.ReadPtr, ph_ptr_addr, timeout)
            process_heap_str = _get_dict_value(ph_result, ph_ptr_addr, "0x0")
            if process_heap_str and process_heap_str != "0x0":
                heap_base = _parse_addr(process_heap_str)
                hf_addr = _fmt_addr(heap_base + 0x70)
                old_hf_result = await asyncio.to_thread(self.memory.ReadDword, hf_addr, timeout)
                old_hf = _get_dict_value(old_hf_result, hf_addr, "0x0")
                write_hf_result = await asyncio.to_thread(self.memory.WriteDword, hf_addr, "0x0", timeout)
                patched_fields.append({
                    "field": "ProcessHeap.Flags",
                    "offset": "heap+0x70",
                    "address": hf_addr,
                    "old": old_hf,
                    "new": "0x0",
                    "status": "Success" if _is_success(write_hf_result, "WriteDword") else "Failed"
                })

            return _fmt_success({
                "peb_base": peb_base_str,
                "patched_fields": patched_fields,
                "patched_count": len(patched_fields)
            })
        except Exception as e:
            logger.exception("绕过 PEB 反调试失败")
            return _fmt_error("绕过 PEB 反调试失败", e)

    # ============================================================
    # 3. set_memory_access_breakpoint - 内存访问硬件断点
    # ============================================================
    async def set_memory_access_breakpoint(self, address: str, break_type: int,
                                           wait_timeout: float = 10.0,
                                           max_hits: int = 1,
                                           timeout: float = 5.0) -> str:
        """
        功能：内存访问硬件断点
        用途：监控某地址被读写时谁在操作（卡密验证场景定位 flag 写入者）
        调用示例：set_memory_access_breakpoint(address="0x12345678", break_type=2, max_hits=3)
        返回：JSON 包含 address/break_type/hit/hit_count/registers/disasm_at_hit
        说明：break_type: 1=Execute/2=Write/3=Read/4=ReadWrite
              设置后 Wait 命中，采集 rip + 寄存器 + DisasmOneCode，最后清理断点。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(address, str) or not _ADDR_RE.match(address.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", address)
            # 校验 break_type 范围
            if break_type not in (1, 2, 3, 4):
                return _fmt_error("break_type 必须为 1-4", str(break_type))
            if max_hits < 1 or max_hits > 100:
                return _fmt_error("max_hits 必须在 1-100 之间")

            if self.dbg is None or self.dissasm is None:
                return _fmt_error("petools 缺少 dbg/dissasm 实例")

            clean_addr = address.strip()

            # 修复毒舌审查P0 Bug: 调试器状态操作加锁，防止多工具并发竞态
            async with self._debugger_lock:
                # 第一步：设置硬件断点（break_type 是 int）
                set_result = await asyncio.to_thread(
                    self.dbg.SetHardwareBreakPoint, clean_addr, break_type, timeout
                )
                if not _is_success(set_result, "SetHardwareBreakPoint"):
                    return _fmt_error("设置硬件断点失败", set_result)

                hit_records = []
                hit_count = 0
                try:
                    # 第二步：循环 Wait + 采集，直到 max_hits 或超时
                    for i in range(max_hits):
                        # Wait 等待断点命中
                        wait_result = await asyncio.to_thread(self.dbg.Wait, wait_timeout)
                        wait_status = _get_dict_value(wait_result, "Wait", "")
                        if wait_status.lower() != "success":
                            # 超时或失败，结束循环
                            break

                        hit_count += 1

                        # 采集 rip 寄存器（get_register 参数是 registers 复数）
                        rip_result = await asyncio.to_thread(
                            self.dbg.get_register, "rip", timeout
                        )
                        rip_val = _get_dict_value(rip_result, "RIP", "0x0")

                        # 采集关键寄存器（批量获取）
                        reg_list = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                    "rbp", "rsp", "r8", "r9", "r10", "r11"]
                        regs_result = await asyncio.to_thread(
                            self.dbg.get_register, reg_list, timeout
                        )

                        # 反汇编命中处指令
                        disasm_result = None
                        try:
                            disasm_result = await asyncio.to_thread(
                                self.dissasm.DisasmOneCode, rip_val, timeout
                            )
                        except Exception:
                            logger.exception("反汇编命中处指令失败")

                        hit_records.append({
                            "hit_index": hit_count,
                            "rip": rip_val,
                            "registers": regs_result if isinstance(regs_result, dict) else {},
                            "disasm": disasm_result
                        })

                        # 如果还需要继续命中，Run 恢复执行
                        if i < max_hits - 1:
                            run_result = await asyncio.to_thread(self.dbg.Run, timeout)
                            if not _is_success(run_result, "Run"):
                                break
                finally:
                    # 第三步：清理硬件断点（无论成功失败都清理）
                    try:
                        await asyncio.to_thread(self.dbg.DeleteHardwareBreakPoint, clean_addr, timeout)
                    except Exception:
                        logger.exception("清理硬件断点失败")

            return _fmt_success({
                "address": clean_addr,
                "break_type": break_type,
                "hit": hit_count > 0,
                "hit_count": hit_count,
                "hit_records": hit_records
            })
        except Exception as e:
            logger.exception("内存访问硬件断点失败")
            return _fmt_error("内存访问硬件断点失败", e)

    # ============================================================
    # 4. set_conditional_hardware_breakpoint - 条件硬件断点
    # ============================================================
    async def set_conditional_hardware_breakpoint(self, address: str, break_type: int,
                                                  condition: str,
                                                  timeout: float = 5.0) -> str:
        """
        功能：条件硬件断点
        用途：只在特定条件满足时硬件断点断下（如 rax==0x1234 时监控内存写）
        调用示例：set_conditional_hardware_breakpoint(address="0x12345678", break_type=2, condition="rax==0x1234")
        返回：JSON 包含 address/break_type/condition/set
        说明：调用 SetHardwareBreakPoint + RunCmd(SetHardwareBreakpointCondition)。
              condition 用正则白名单校验（参考 fusion.py _COND_RE），防注入。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(address, str) or not _ADDR_RE.match(address.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", address)
            # 校验 break_type 范围
            if break_type not in (1, 2, 3, 4):
                return _fmt_error("break_type 必须为 1-4", str(break_type))
            # 校验条件表达式（防止注入：禁止引号/分号/反引号等危险字符）
            if not isinstance(condition, str) or not _COND_RE.match(condition.strip()):
                return _fmt_error("条件表达式含非法字符（仅允许字母数字与常用运算符）", condition)

            if self.dbg is None or self.script is None:
                return _fmt_error("petools 缺少 dbg/script 实例")

            clean_addr = address.strip()
            clean_cond = condition.strip()

            # 第一步：设置硬件断点（break_type 是 int）
            set_result = await asyncio.to_thread(
                self.dbg.SetHardwareBreakPoint, clean_addr, break_type, timeout
            )
            if not _is_success(set_result, "SetHardwareBreakPoint"):
                return _fmt_error("设置硬件断点失败", set_result)

            # 第二步：设置断点条件（用 RunCmd）
            # 条件已通过白名单校验，可安全拼接
            cmd = f"SetHardwareBreakpointCondition {clean_addr}, \"{clean_cond}\""
            cond_result = await asyncio.to_thread(self.script.RunCmd, cmd, timeout)

            # 判断条件设置是否成功（RunCmd 返回 {"RunCmd":"..."} 或 {"RunCmd":"Error","Reason":...}）
            cond_status = "Success"
            if isinstance(cond_result, dict):
                runcmd_val = cond_result.get("RunCmd", "")
                if isinstance(runcmd_val, str) and runcmd_val.lower() == "error":
                    cond_status = "Failed"

            return _fmt_success({
                "address": clean_addr,
                "break_type": break_type,
                "condition": clean_cond,
                "hardware_bp_set": True,
                "condition_set": cond_result,
                "condition_status": cond_status
            })
        except Exception as e:
            logger.exception("设置条件硬件断点失败")
            return _fmt_error("设置条件硬件断点失败", e)

    # ============================================================
    # 5. exec_x64dbg_command_safe - 安全执行 x64dbg 命令（扩展白名单）
    # ============================================================
    # 修复毒舌审查P0 Bug: 原白名单只校验前缀，x64dbg 分号串联命令可绕过
    # 例如 "findref(0x401000); mov [0x401000], 0x90" 会通过前缀校验但执行任意写
    # 修复：1. 禁止分号/换行/反引号等命令分隔符 2. 移除危险命令 mov/alloc/free/dump
    #       3. 用整条命令正则校验而非只校验前缀
    _SAFE_CMD_PREFIXES = (
        "findref", "findmem", "findop", "findall", "analfunc",
        "bp", "bpx", "bpm", "bphws", "bc",
        "SetBreakpointCondition", "SetHardwareBreakpointCondition",
        "hide", "ref",
        "TraceIntoConditions", "TraceOverConditions", "TraceCount",
        "disasm", "cf"
    )
    # 命令分隔符黑名单：x64dbg 支持分号/换行串联多条命令，必须禁止
    _CMD_SEPARATOR_RE = re.compile(r'[;\n\r`]')
    # 整条命令安全字符白名单：字母数字 + 空格 + 括号 + 逗号 + 0x 十六进制 + 引号 + 运算符
    # 毒舌批评修复: 必须加 + 量词和 $ 结尾锚点，否则只校验第一个字符
    # 原 .match 只锚开头，"findref(0x401000)<任意垃圾>" 全部通过
    _CMD_FULL_RE = re.compile(r'^(?:0x[0-9a-fA-F]+|[a-zA-Z0-9_(),\s\[\]\-+*/.:"])+$')

    async def exec_x64dbg_command_safe(self, cmd: str, timeout: float = 10.0) -> str:
        """
        功能：安全执行 x64dbg 命令（扩展白名单，防注入）
        用途：执行 x64dbg 原生命令（findref/findmem/bp/hide/ref 等）
        调用示例：exec_x64dbg_command_safe(cmd="findref(0x401000)")
                  exec_x64dbg_command_safe(cmd="hide")
        返回：JSON 包含 command/output/status
        说明：修复毒舌审查P0 Bug——原版只校验前缀，分号串联命令可绕过。
              修复后：1. 禁止分号/换行/反引号等命令分隔符
                     2. 移除危险命令 mov/alloc/free/dump（可写内存/操纵资源）
                     3. 用整条命令正则校验而非只校验前缀
                     4. 白名单仅保留只读/查询/断点类命令
        """
        try:
            if not isinstance(cmd, str) or not cmd.strip():
                return _fmt_error("命令不能为空")
            if self.script is None:
                return _fmt_error("petools 缺少 script 实例")

            clean_cmd = cmd.strip()

            # 修复毒舌审查P0 Bug: 第一步检查命令分隔符（防分号串联注入）
            if self._CMD_SEPARATOR_RE.search(clean_cmd):
                return _fmt_error(
                    "命令含非法分隔符（禁止分号/换行/反引号，防止串联注入）",
                    clean_cmd
                )

            # 第二步：提取命令前缀（取第一个空格或左括号前的部分）
            prefix = clean_cmd.split("(")[0].split(" ")[0].strip()

            # 第三步：校验命令前缀是否在白名单内
            if prefix not in self._SAFE_CMD_PREFIXES:
                return _fmt_error(
                    f"命令前缀不在白名单内（仅允许只读/查询/断点类命令: {', '.join(self._SAFE_CMD_PREFIXES)}）",
                    prefix
                )

            # 修复毒舌审查P0 Bug: 第四步整条命令字符白名单校验（防绕过）
            # 毒舌批评修复: 用 fullmatch 替代 match，配合 $ 锚点确保整条命令校验
            if not self._CMD_FULL_RE.fullmatch(clean_cmd):
                return _fmt_error("命令含非法字符", clean_cmd)

            # 执行命令
            result = await asyncio.to_thread(self.script.RunCmd, clean_cmd, timeout)

            # 判断执行状态
            status = "Success"
            output = result
            if isinstance(result, dict):
                runcmd_val = result.get("RunCmd", "")
                if isinstance(runcmd_val, str) and runcmd_val.lower() == "error":
                    status = "Error"
                    output = result.get("Reason", result)

            return _fmt_success({
                "command": clean_cmd,
                "prefix": prefix,
                "output": output,
                "status": status
            })
        except Exception as e:
            logger.exception("安全执行 x64dbg 命令失败")
            return _fmt_error("安全执行 x64dbg 命令失败", e)

    # ============================================================
    # P1 高优先级：脱壳侦察 + dump + patch
    # ============================================================
    # 6. find_oep_by_section_attr - 基于段属性找 OEP / 检测壳
    # ============================================================
    async def find_oep_by_section_attr(self, timeout: float = 5.0) -> str:
        """
        功能：基于段属性找 OEP / 检测壳
        用途：判断程序是否加壳，识别壳类型（VMP/UPX/Themida/ASPack）
        调用示例：find_oep_by_section_attr()
        返回：JSON 包含 is_packed/packer/vmp_sections/oep_declared/entry_actual/sections
        说明：调用 GetMainModuleInfoEx 拿所有段，检查段名是否含 vmp0/vmp1/vmp2/UPX/Themida/ASPack。
              调用 GetMainModuleEntry 拿实际入口点，GetOEPFromName 拿声明 OEP。
              壳检测后若 oep_declared != entry_actual，可能需要脱壳找真 OEP。
        """
        try:
            if self.module is None:
                return _fmt_error("petools 缺少 module 实例")

            # 第一步：获取主模块扩展信息（含 sections）
            info_result = await asyncio.to_thread(self.module.GetMainModuleInfoEx, timeout)
            # GetMainModuleInfoEx 返回多 key dict，直接用整个 dict
            if not isinstance(info_result, dict):
                return _fmt_error("获取主模块信息失败：返回类型异常", str(type(info_result)))

            sections = info_result.get("sections", [])
            module_name = info_result.get("module_name", "")
            base_address = info_result.get("base_address", "")

            # 第二步：检测壳特征（检查段名）
            packer_signatures = {
                "vmp0": "VMProtect", "vmp1": "VMProtect", "vmp2": "VMProtect",
                "UPX0": "UPX", "UPX1": "UPX",
                "Themida": "Themida", "WinLicen": "Themida",
                ".aspack": "ASPack", ".adata": "ASPack",
                ".nsp0": "NsPack", ".nsp1": "NsPack",
                ".enigma1": "Enigma", ".enigma2": "Enigma",
            }
            detected_packer = None
            vmp_sections = []
            for sec in sections:
                sec_name = sec.get("section_name", "") if isinstance(sec, dict) else ""
                # 检测 VMP 段
                if sec_name.lower().startswith("vmp"):
                    vmp_sections.append(sec_name)
                    if detected_packer is None:
                        detected_packer = "VMProtect"
                # 检测其他壳
                for sig, packer_name in packer_signatures.items():
                    if sig.lower() in sec_name.lower():
                        if detected_packer is None:
                            detected_packer = packer_name
                        break

            # 第三步：获取实际入口点
            entry_result = await asyncio.to_thread(self.module.GetMainModuleEntry, timeout)
            entry_actual = _get_dict_value(entry_result, "entry_point", "")

            # 第四步：获取声明 OEP（通过模块名）
            oep_declared = ""
            try:
                if module_name:
                    oep_result = await asyncio.to_thread(self.module.GetOEPFromName, module_name, timeout)
                    oep_declared = _get_dict_value(oep_result, "oep", "")
            except Exception:
                logger.exception("获取声明 OEP 失败")

            # 判断是否加壳
            is_packed = detected_packer is not None or len(vmp_sections) > 0

            return _fmt_success({
                "is_packed": is_packed,
                "packer": detected_packer if detected_packer else "None",
                "vmp_sections": vmp_sections,
                "oep_declared": oep_declared,
                "entry_actual": entry_actual,
                "oep_mismatch": oep_declared != "" and entry_actual != "" and oep_declared != entry_actual,
                "module_name": module_name,
                "base_address": base_address,
                "section_count": len(sections),
                "sections": sections
            })
        except Exception as e:
            logger.exception("基于段属性找 OEP 失败")
            return _fmt_error("基于段属性找 OEP 失败", e)

    # ============================================================
    # 7. get_pe_full_info - PE 完整信息一次拿
    # ============================================================
    async def get_pe_full_info(self, timeout: float = 10.0) -> str:
        """
        功能：PE 完整信息一次拿
        用途：脱壳侦察时一次获取 PE 所有关键信息，减少 MCP 往返
        调用示例：get_pe_full_info()
        返回：JSON 包含 dos_magic/pe_magic/e_lfanew/sections/imports/exports/oep/entry
        说明：调用 GetMainModuleBase + ReadWord(e_magic) + ReadDword(e_lfanew) + ReadDword(pe_signature)
              + GetSectionListFromAddr + GetImport + GetExport + GetOEPFromName + GetMainModuleInfoEx
        """
        try:
            if self.module is None or self.memory is None:
                return _fmt_error("petools 缺少 module/memory 实例")

            # 第一步：获取主模块基址
            base_result = await asyncio.to_thread(self.module.GetMainModuleBase, timeout)
            base_str = _get_dict_value(base_result, "base_address", "0x0")
            base = _parse_addr(base_str)
            module_name = _get_dict_value(base_result, "module_name", "")

            # 第二步：读取 DOS header e_magic (base+0x0, 2 bytes "MZ"=0x5A4D)
            magic_addr = _fmt_addr(base + 0x0)
            magic_result = await asyncio.to_thread(self.memory.ReadWord, magic_addr, timeout)
            dos_magic = _get_dict_value(magic_result, magic_addr, "0x0")

            # 第三步：读取 e_lfanew (base+0x3C, 4 bytes, PE header offset)
            lfanew_addr = _fmt_addr(base + 0x3C)
            lfanew_result = await asyncio.to_thread(self.memory.ReadDword, lfanew_addr, timeout)
            e_lfanew_str = _get_dict_value(lfanew_result, lfanew_addr, "0x0")
            e_lfanew = _parse_addr(e_lfanew_str) if e_lfanew_str else 0

            # 第四步：读取 PE signature (base+e_lfanew, 4 bytes "PE\0\0"=0x4550)
            pe_sig_addr = _fmt_addr(base + e_lfanew)
            pe_sig_result = await asyncio.to_thread(self.memory.ReadDword, pe_sig_addr, timeout)
            pe_magic = _get_dict_value(pe_sig_result, pe_sig_addr, "0x0")

            # 第五步：获取段列表
            sections = []
            try:
                sec_result = await asyncio.to_thread(self.module.GetSectionListFromAddr, base_str, timeout)
                if isinstance(sec_result, dict):
                    sections = sec_result.get("sections", [])
            except Exception:
                logger.exception("获取段列表失败")

            # 第六步：获取导入表
            imports = []
            if module_name:
                try:
                    imp_result = await asyncio.to_thread(self.module.GetImport, module_name, timeout)
                    if isinstance(imp_result, dict):
                        imports = imp_result.get("imports", [])
                except Exception:
                    logger.exception("获取导入表失败")

            # 第七步：获取导出表
            exports = []
            if module_name:
                try:
                    exp_result = await asyncio.to_thread(self.module.GetExport, module_name, timeout)
                    if isinstance(exp_result, dict):
                        exports = exp_result.get("exports", [])
                except Exception:
                    logger.exception("获取导出表失败")

            # 第八步：获取 OEP 和入口点
            oep = ""
            if module_name:
                try:
                    oep_result = await asyncio.to_thread(self.module.GetOEPFromName, module_name, timeout)
                    oep = _get_dict_value(oep_result, "oep", "")
                except Exception:
                    logger.exception("获取 OEP 失败")

            entry_result = await asyncio.to_thread(self.module.GetMainModuleEntry, timeout)
            entry = _get_dict_value(entry_result, "entry_point", "")

            return _fmt_success({
                "base": base_str,
                "module_name": module_name,
                "dos_magic": dos_magic,
                "is_valid_dos": dos_magic.upper() in ("0x5A4D", "0x5a4d"),
                "e_lfanew": e_lfanew_str,
                "pe_magic": pe_magic,
                "is_valid_pe": pe_magic.upper() in ("0x4550",),
                "sections": sections,
                "section_count": len(sections),
                "imports": imports,
                "import_count": len(imports),
                "exports": exports,
                "export_count": len(exports),
                "oep": oep,
                "entry": entry
            })
        except Exception as e:
            logger.exception("获取 PE 完整信息失败")
            return _fmt_error("获取 PE 完整信息失败", e)

    # ============================================================
    # 8. detect_tlscallback - TLS Callback 检测
    # ============================================================
    async def detect_tlscallback(self, timeout: float = 10.0) -> str:
        """
        功能：TLS Callback 检测
        用途：检测 TLS 回调函数（壳/反调试常用 TLS 在 OEP 前执行代码）
        调用示例：detect_tlscallback()
        返回：JSON 包含 tls_directory_rva/tls_directory_va/callback_count/callbacks
        说明：PE32+ 偏移计算：
              - e_lfanew 在 base+0x3C
              - OptionalHeader 在 e_lfanew+0x18
              - DataDirectory 在 OptionalHeader+0x70 (PE32+)
              - TLS Directory 是 DataDirectory[9]，每项 8 字节（RVA+Size）
              - TLS Directory RVA 在 e_lfanew+0x18+0x70+9*8
              读 AddressOfCallBacks（TLS Directory+0x18），循环读 callback 数组直到 NULL。
        修复毒舌审查P1 Bug: 原代码用 `< base` 判断 RVA/VA 不可靠——加壳后字段可能被改成
              虚假值（如 0xFFFFFFFF），既不是 RVA 也不是 VA，会读到无效地址崩溃。
              修复后：读 OptionalHeader.SizeOfImage 做范围检查——
              - 值 < SizeOfImage：当 RVA 处理（实际地址 = base + rva）
              - 值在 [base, base+SizeOfImage)：当 VA 处理
              - 否则：报错"无法判断 RVA/VA（值超出合理范围）"
              AddressOfCallBacks 字段同样做范围检查。
              注意：DataDirectory 的 VirtualAddress 字段在 PE 规范中本就是 RVA，
              但加壳后可能被改为 VA 或被破坏，所以需要双向检测。
        """
        try:
            if self.module is None or self.memory is None:
                return _fmt_error("petools 缺少 module/memory 实例")

            # 第一步：获取主模块基址
            base_result = await asyncio.to_thread(self.module.GetMainModuleBase, timeout)
            base_str = _get_dict_value(base_result, "base_address", "0x0")
            base = _parse_addr(base_str)

            # 第二步：读取 e_lfanew (base+0x3C)
            lfanew_addr = _fmt_addr(base + 0x3C)
            lfanew_result = await asyncio.to_thread(self.memory.ReadDword, lfanew_addr, timeout)
            e_lfanew_str = _get_dict_value(lfanew_result, lfanew_addr, "0x0")
            e_lfanew = _parse_addr(e_lfanew_str) if e_lfanew_str else 0

            # 修复毒舌审查P1 Bug: 读取 SizeOfImage 用于 RVA/VA 范围检查
            # PE32+ OptionalHeader.SizeOfImage 在 e_lfanew+0x18+0x50
            size_of_image_addr = _fmt_addr(base + e_lfanew + 0x18 + 0x50)
            soi_result = await asyncio.to_thread(self.memory.ReadDword, size_of_image_addr, timeout)
            soi_str = _get_dict_value(soi_result, size_of_image_addr, "0x0")
            size_of_image = _parse_addr(soi_str) if soi_str else 0

            # 定义 RVA/VA 转换辅助函数（基于 SizeOfImage 范围检查）
            def _rva_to_va(field_val: int, field_name: str) -> int:
                """
                根据 SizeOfImage 判断字段值是 RVA 还是 VA，并返回实际 VA。
                - 值 < SizeOfImage：当 RVA，返回 base + val
                - 值在 [base, base+SizeOfImage)：当 VA，返回 val
                - 否则：抛 ValueError
                """
                if size_of_image > 0:
                    # 优先按 RVA 判断（PE 规范）
                    if field_val < size_of_image:
                        return field_val + base
                    # 再按 VA 判断
                    if base <= field_val < base + size_of_image:
                        return field_val
                    # 都不在合理范围，加壳后字段被破坏
                    raise ValueError(
                        f"{field_name} 值 0x{field_val:X} 既不是合法 RVA "
                        f"(应 < SizeOfImage=0x{size_of_image:X}) 也不是合法 VA "
                        f"(应在 [0x{base:X}, 0x{base + size_of_image:X}))"
                    )
                # SizeOfImage 读取失败，降级为原 < base 判断
                if field_val < base:
                    return field_val + base
                return field_val

            # 第三步：计算 TLS Directory 在 DataDirectory 中的位置
            # PE32+: DataDirectory 在 e_lfanew+0x18+0x70，TLS 是 DataDirectory[9]
            # 每个 DataDirectory 项 8 字节，所以偏移 = 0x18 + 0x70 + 9*8 = 0x18 + 0x70 + 0x48 = 0xD0
            tls_dir_entry_offset = 0x18 + 0x70 + 9 * 8
            tls_dir_entry_addr = _fmt_addr(base + e_lfanew + tls_dir_entry_offset)

            # 读取 TLS Directory 的 RVA/VA（前 4 字节是地址，后 4 字节是 size）
            tls_dir_result = await asyncio.to_thread(self.memory.ReadDword, tls_dir_entry_addr, timeout)
            tls_dir_rva_str = _get_dict_value(tls_dir_result, tls_dir_entry_addr, "0x0")

            if not tls_dir_rva_str or tls_dir_rva_str == "0x0":
                # 无 TLS Directory
                return _fmt_success({
                    "base": base_str,
                    "e_lfanew": e_lfanew_str,
                    "size_of_image": soi_str,
                    "tls_directory_rva": "0x0",
                    "callback_count": 0,
                    "callbacks": [],
                    "note": "未检测到 TLS Directory"
                })

            # 第四步：计算 TLS Directory 的实际地址（带范围检查）
            tls_dir_addr_int = _parse_addr(tls_dir_rva_str)
            try:
                tls_dir_va = _rva_to_va(tls_dir_addr_int, "TLS Directory VirtualAddress")
            except ValueError as ve:
                return _fmt_error("TLS Directory RVA/VA 无法判断（值超出合理范围）", str(ve))

            # 第五步：读 AddressOfCallBacks（TLS Directory+0x18，ptr）
            # TLS Directory 结构（x64）：
            # +0x00 StartAddressOfRawData (8 bytes)
            # +0x08 EndAddressOfRawData (8 bytes)
            # +0x10 AddressOfIndex (8 bytes)
            # +0x18 AddressOfCallBacks (8 bytes)
            # 注意：这里读 ptr（8字节，x64），用 ReadPtr
            callbacks_ptr_addr = _fmt_addr(tls_dir_va + 0x18)
            cb_ptr_result = await asyncio.to_thread(self.memory.ReadPtr, callbacks_ptr_addr, timeout)
            callbacks_array_str = _get_dict_value(cb_ptr_result, callbacks_ptr_addr, "0x0")

            callbacks = []
            if callbacks_array_str and callbacks_array_str != "0x0":
                # 第六步：循环读 callback 数组，每个元素是 ptr，直到 NULL
                cb_array_int = _parse_addr(callbacks_array_str)
                # 修复毒舌审查P1 Bug: AddressOfCallBacks 也做范围检查
                try:
                    cb_array_int = _rva_to_va(cb_array_int, "AddressOfCallBacks")
                except ValueError as ve:
                    return _fmt_error("AddressOfCallBacks RVA/VA 无法判断（值超出合理范围）", str(ve))

                # 最多读 64 个 callback 防止无限循环
                for i in range(64):
                    cb_entry_addr = _fmt_addr(cb_array_int + i * 8)
                    cb_result = await asyncio.to_thread(self.memory.ReadPtr, cb_entry_addr, timeout)
                    cb_val_str = _get_dict_value(cb_result, cb_entry_addr, "0x0")
                    if not cb_val_str or cb_val_str == "0x0":
                        # NULL 结束
                        break
                    callbacks.append({
                        "index": i,
                        "callback_address": cb_val_str,
                        "entry_address": cb_entry_addr
                    })

            return _fmt_success({
                "base": base_str,
                "e_lfanew": e_lfanew_str,
                "size_of_image": soi_str,
                "tls_directory_rva": tls_dir_rva_str,
                "tls_directory_va": _fmt_addr(tls_dir_va),
                "callbacks_array_address": callbacks_array_str,
                "callback_count": len(callbacks),
                "callbacks": callbacks
            })
        except Exception as e:
            logger.exception("TLS Callback 检测失败")
            return _fmt_error("TLS Callback 检测失败", e)

    # ============================================================
    # 9. dump_module_memory - dump 主模块内存（返回 base64）
    # ============================================================
    # 修复毒舌审查P0 Bug: 1. 默认 max_size 从 1MB 降到 64KB（防撑爆 MCP 消息上限）
    #                    2. 用 ReadDword 批量读（4字节/次）替代 ReadByte（1字节/次），提速 4 倍
    #                    3. chunk_size 从 4096 降到 1024（减少单次 HTTP 请求体大小）
    async def dump_module_memory(self, max_size: int = 0x10000,
                                 timeout: float = 30.0) -> str:
        """
        功能：dump 主模块内存（返回 base64，分块读取）
        用途：脱壳后 dump 内存重建 PE 文件
        调用示例：dump_module_memory(max_size=0x10000)
        返回：JSON 包含 base/size/bytes_dumped/base64_data/md5
        说明：修复毒舌审查P0 Bug——原版默认 1MB 撑爆 MCP 消息上限（1MB base64≈1.33MB）。
              修复后：1. 默认 max_size=64KB（base64≈85KB，安全在 MCP 消息上限内）
                     2. 用 ReadDword 批量读（4字节/次）替代 ReadByte，提速 4 倍
                     3. chunk_size=1024 减少 HTTP 请求体大小
                     4. 如需 dump 更大范围，调用方显式传 max_size，并自行分块调用
        """
        try:
            if self.module is None or self.memory is None:
                return _fmt_error("petools 缺少 module/memory 实例")

            # 第一步：获取主模块基址和大小
            base_result = await asyncio.to_thread(self.module.GetMainModuleBase, timeout)
            base_str = _get_dict_value(base_result, "base_address", "0x0")
            base = _parse_addr(base_str)

            size_result = await asyncio.to_thread(self.module.GetMainModuleSize, timeout)
            size_val = _get_dict_value(size_result, "size", 0)
            if isinstance(size_val, str):
                size_val = _parse_addr(size_val)
            module_size = int(size_val)

            # 应用 max_size 上限
            dump_size = min(module_size, max_size)

            # 修复毒舌审查P0 Bug: 用 ReadDword（4字节/次）替代 ReadByte（1字节/次）
            # 每次 1024 个 dword = 4096 字节，HTTP 请求体小且效率高
            all_bytes = bytearray()
            bytes_dumped = 0
            dword_count_per_chunk = 1024  # 每次 1024 个 dword = 4096 字节
            chunk_byte_size = dword_count_per_chunk * 4

            while bytes_dumped < dump_size:
                current_chunk_bytes = min(chunk_byte_size, dump_size - bytes_dumped)
                current_dwords = current_chunk_bytes // 4
                # 构造 dword 地址列表（每个地址读 4 字节）
                addrs = _build_addr_list(base + bytes_dumped, current_dwords, 4)
                chunk_result = await asyncio.to_thread(self.memory.ReadDword, addrs, timeout)

                if not isinstance(chunk_result, dict):
                    break

                # 按地址顺序提取 dword 值，拆成 4 字节
                for addr in addrs:
                    dword_str = chunk_result.get(addr, "0x0")
                    if isinstance(dword_str, str):
                        try:
                            dword_val = int(dword_str, 16) if dword_str.lower().startswith("0x") else int(dword_str)
                            # 拆成 4 字节（小端序）
                            all_bytes.append(dword_val & 0xFF)
                            all_bytes.append((dword_val >> 8) & 0xFF)
                            all_bytes.append((dword_val >> 16) & 0xFF)
                            all_bytes.append((dword_val >> 24) & 0xFF)
                        except ValueError:
                            all_bytes.extend(b'\x00\x00\x00\x00')
                    else:
                        all_bytes.extend(b'\x00\x00\x00\x00')

                bytes_dumped += current_dwords * 4

            # 第三步：base64 编码 + md5 校验
            b64_data = base64.b64encode(bytes(all_bytes)).decode('ascii')
            md5_hash = hashlib.md5(bytes(all_bytes)).hexdigest()

            return _fmt_success({
                "base": base_str,
                "module_size": module_size,
                "dump_size": dump_size,
                "bytes_dumped": bytes_dumped,
                "base64_data": b64_data,
                "base64_size": len(b64_data),
                "md5": md5_hash,
                "truncated": module_size > max_size,
                "note": f"默认上限 64KB 防撑爆 MCP 消息，如需更大范围请显式传 max_size 并分块调用"
            })
        except Exception as e:
            logger.exception("dump 主模块内存失败")
            return _fmt_error("dump 主模块内存失败", e)

    # ============================================================
    # 10. set_memory_protect_rw - 一键改内存为可读写
    # ============================================================
    async def set_memory_protect_rw(self, address: str, size: int,
                                    protect: str = "0x40",
                                    timeout: float = 5.0) -> str:
        """
        功能：一键改内存为可读写
        用途：patch 代码前需要先改内存保护属性为可写
        调用示例：set_memory_protect_rw(address="0x401000", size=16, protect="0x40")
        返回：JSON 包含 address/size/old_protect/new_protect/status
        说明：调用 SetProtect(address, size, protect)。
              protect 默认 "0x40" (PAGE_EXECUTE_READWRITE)。
              常用值：0x40=ERW, 0x04=R, 0x02=W, 0x10=RX, 0x20=RW
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(address, str) or not _ADDR_RE.match(address.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", address)
            if not isinstance(size, int) or size <= 0 or size > 0x10000000:
                return _fmt_error("size 必须为正整数且不超过 256MB")
            # 校验 protect 格式（仅允许 0x 十六进制或纯数字）
            if not isinstance(protect, str) or not _ADDR_RE.match(protect.strip()):
                return _fmt_error("protect 格式非法（仅允许 0x 十六进制或纯数字）", protect)

            if self.memory is None:
                return _fmt_error("petools 缺少 memory 实例")

            clean_addr = address.strip()
            # SetProtect 的 size 参数必须是字符串
            size_str = str(size)

            # 先读原保护属性（通过 GetSection，若失败则记 None）
            old_protect = None
            try:
                if self.module is not None:
                    sec_result = await asyncio.to_thread(self.module.GetSection, clean_addr, timeout)
                    if isinstance(sec_result, dict):
                        old_protect = sec_result.get("attributes", None)
            except Exception:
                logger.exception("读取原保护属性失败")

            # 调用 SetProtect 改保护属性
            result = await asyncio.to_thread(
                self.memory.SetProtect, clean_addr, size_str, protect.strip(), timeout
            )

            status = "Success" if _is_success(result, "SetProtect") else "Failed"

            return _fmt_success({
                "address": clean_addr,
                "size": size,
                "old_protect": old_protect,
                "new_protect": protect.strip(),
                "status": status,
                "raw_result": result
            })
        except Exception as e:
            logger.exception("改内存保护属性失败")
            return _fmt_error("改内存保护属性失败", e)

    # ============================================================
    # 11. patch_code_with_assemble - 汇编指令 patch
    # ============================================================
    async def patch_code_with_assemble(self, address: str, instruction: str,
                                       timeout: float = 5.0) -> str:
        """
        功能：汇编指令 patch（带备份与回滚）
        用途：用汇编指令修改代码（如把 call 改为 nop/nop/nop/nop/nop）
        调用示例：patch_code_with_assemble(address="0x401000", instruction="mov eax,1")
        返回：JSON 包含 address/instruction/original_bytes/new_bytes/status/rolled_back
        说明：调用 AssembleCodeHex(instruction) 算机器码，
              调用 ReadByte 读原字节备份，
              调用 WritePattern 写入新机器码。
        修复毒舌审查P1 Bug: 原代码写入失败不恢复 original_bytes，且 SetProtect 后不恢复原保护属性。
              修复后：try/finally 包裹，写入失败时自动恢复 original_bytes；
              SetProtect 前/后记录原保护属性并在 finally 中恢复。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(address, str) or not _ADDR_RE.match(address.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", address)
            # 校验汇编指令（防止注入）
            if not isinstance(instruction, str) or not _ASM_RE.match(instruction.strip()):
                return _fmt_error("汇编指令含非法字符", instruction)

            if self.dissasm is None or self.memory is None:
                return _fmt_error("petools 缺少 dissasm/memory 实例")

            clean_addr = address.strip()
            clean_instr = instruction.strip()

            # 第一步：汇编指令为机器码 hex
            asm_result = await asyncio.to_thread(
                self.dissasm.AssembleCodeHex, clean_instr, timeout
            )
            # AssembleCodeHex 返回 {"hex":"B801000000","size":5}
            new_hex = _get_dict_value(asm_result, "hex", "")
            new_size = _get_dict_value(asm_result, "size", 0)
            if isinstance(new_size, str):
                new_size = _parse_addr(new_size)

            if not new_hex:
                return _fmt_error("汇编指令失败", asm_result)

            # 第二步：读取原字节备份
            addr_int = _parse_addr(clean_addr)
            original_addrs = _build_addr_list(addr_int, int(new_size), 1)
            orig_result = await asyncio.to_thread(self.memory.ReadByte, original_addrs, timeout)
            original_bytes = []
            if isinstance(orig_result, dict):
                for addr in original_addrs:
                    byte_str = orig_result.get(addr, "0x0")
                    original_bytes.append(byte_str)

            # 第三步：写入新机器码
            # WritePattern 的 pattern 不允许通配符，length 必须是字符串
            # new_hex 可能是 "B801000000" 格式，需要转成 "B8 01 00 00 00" 格式
            formatted_pattern = " ".join(new_hex[i:i + 2] for i in range(0, len(new_hex), 2))
            length_str = str(int(new_size))

            # 先读原保护属性（用于 finally 恢复）
            old_protect = None
            try:
                if self.module is not None:
                    sec_result = await asyncio.to_thread(self.module.GetSection, clean_addr, timeout)
                    if isinstance(sec_result, dict):
                        old_protect = sec_result.get("attributes", None)
            except Exception:
                logger.exception("读取原保护属性失败")

            # 修复毒舌审查P1 Bug: try/finally 包裹写入逻辑，失败回滚 original_bytes
            rolled_back = False
            write_status = "Failed"
            write_result = None
            try:
                # 改保护属性为可读写（patch 代码段通常需要）
                try:
                    await asyncio.to_thread(
                        self.memory.SetProtect, clean_addr, length_str, "0x40", timeout
                    )
                except Exception:
                    logger.exception("改保护属性失败（可能已可写，继续尝试 patch）")

                # 写入新机器码
                write_result = await asyncio.to_thread(
                    self.memory.WritePattern, formatted_pattern, clean_addr, length_str, timeout
                )
                write_status = "Success" if _is_success(write_result, "WritePattern") else "Failed"

                # 写入失败则回滚 original_bytes
                if write_status == "Failed" and original_bytes:
                    rollback_pattern = " ".join(
                        b.upper().replace("0X", "") if b.upper().startswith("0X") else b.upper()
                        for b in original_bytes
                    )
                    try:
                        await asyncio.to_thread(
                            self.memory.WritePattern, rollback_pattern, clean_addr, length_str, timeout
                        )
                        rolled_back = True
                    except Exception:
                        logger.exception("回滚 original_bytes 失败")
            finally:
                # 恢复原保护属性（无论写入成功或失败，都不应保留 0x40）
                if old_protect is not None:
                    try:
                        old_protect_str = str(old_protect) if isinstance(old_protect, str) else hex(int(old_protect))
                        await asyncio.to_thread(
                            self.memory.SetProtect, clean_addr, length_str, old_protect_str, timeout
                        )
                    except Exception:
                        logger.exception("恢复原保护属性失败")

            return _fmt_success({
                "address": clean_addr,
                "instruction": clean_instr,
                "new_hex": new_hex,
                "new_size": int(new_size),
                "original_bytes": original_bytes,
                "new_bytes": formatted_pattern,
                "old_protect": old_protect,
                "status": write_status,
                "rolled_back": rolled_back,
                "write_result": write_result
            })
        except Exception as e:
            logger.exception("汇编指令 patch 失败")
            return _fmt_error("汇编指令 patch 失败", e)

    # ============================================================
    # 12. nop_code_range - 批量 NOP
    # ============================================================
    async def nop_code_range(self, address: str, length: int,
                             timeout: float = 5.0) -> str:
        """
        功能：批量 NOP（带备份与回滚）
        用途：把指定范围的代码全部填 NOP（0x90），用于禁用某段代码
        调用示例：nop_code_range(address="0x401000", length=5)
        返回：JSON 包含 address/length/original_bytes/status/rolled_back
        说明：调用 WritePattern("90 90 90 ...", address, length)。
              自动构造 length 个 0x90 的 pattern。
        修复毒舌审查P1 Bug: 原代码不读原字节备份，写失败无法恢复。
              修复后：先 ReadByte 读原字节备份；try/finally 包裹，写入失败时回滚原字节；
              并在 finally 中恢复原保护属性。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(address, str) or not _ADDR_RE.match(address.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", address)
            if not isinstance(length, int) or length <= 0 or length > 0x1000:
                return _fmt_error("length 必须为正整数且不超过 4096")

            if self.memory is None:
                return _fmt_error("petools 缺少 memory 实例")

            clean_addr = address.strip()
            # 构造 NOP pattern：length 个 "90"
            nop_pattern = " ".join(["90"] * length)
            length_str = str(length)

            # 修复毒舌审查P1 Bug: 先读原字节备份，写失败可回滚
            addr_int = _parse_addr(clean_addr)
            backup_addrs = _build_addr_list(addr_int, length, 1)
            backup_result = await asyncio.to_thread(self.memory.ReadByte, backup_addrs, timeout)
            original_bytes = []
            if isinstance(backup_result, dict):
                for addr in backup_addrs:
                    byte_str = backup_result.get(addr, "0x0")
                    original_bytes.append(byte_str)

            # 读原保护属性（用于 finally 恢复）
            old_protect = None
            try:
                if self.module is not None:
                    sec_result = await asyncio.to_thread(self.module.GetSection, clean_addr, timeout)
                    if isinstance(sec_result, dict):
                        old_protect = sec_result.get("attributes", None)
            except Exception:
                logger.exception("读取原保护属性失败")

            # try/finally 包裹，写入失败回滚 original_bytes
            rolled_back = False
            write_status = "Failed"
            write_result = None
            try:
                # 先改保护属性为可读写
                try:
                    await asyncio.to_thread(
                        self.memory.SetProtect, clean_addr, length_str, "0x40", timeout
                    )
                except Exception:
                    logger.exception("改保护属性失败（可能已可写，继续尝试 NOP）")

                # 写入 NOP
                write_result = await asyncio.to_thread(
                    self.memory.WritePattern, nop_pattern, clean_addr, length_str, timeout
                )
                write_status = "Success" if _is_success(write_result, "WritePattern") else "Failed"

                # 写入失败则回滚 original_bytes
                if write_status == "Failed" and original_bytes:
                    rollback_pattern = " ".join(
                        b.upper().replace("0X", "") if b.upper().startswith("0X") else b.upper()
                        for b in original_bytes
                    )
                    try:
                        await asyncio.to_thread(
                            self.memory.WritePattern, rollback_pattern, clean_addr, length_str, timeout
                        )
                        rolled_back = True
                    except Exception:
                        logger.exception("回滚 original_bytes 失败")
            finally:
                # 恢复原保护属性
                if old_protect is not None:
                    try:
                        old_protect_str = str(old_protect) if isinstance(old_protect, str) else hex(int(old_protect))
                        await asyncio.to_thread(
                            self.memory.SetProtect, clean_addr, length_str, old_protect_str, timeout
                        )
                    except Exception:
                        logger.exception("恢复原保护属性失败")

            return _fmt_success({
                "address": clean_addr,
                "length": length,
                "nop_pattern": nop_pattern,
                "original_bytes": original_bytes,
                "old_protect": old_protect,
                "status": write_status,
                "rolled_back": rolled_back,
                "write_result": write_result
            })
        except Exception as e:
            logger.exception("批量 NOP 失败")
            return _fmt_error("批量 NOP 失败", e)

    # ============================================================
    # P2 中优先级：交叉引用 + 跟踪 + SEH + IAT
    # ============================================================
    # 13. get_xrefs_combined - 交叉引用完整信息
    # ============================================================
    async def get_xrefs_combined(self, addresses: Union[str, List[str]],
                                 timeout: float = 10.0) -> str:
        """
        功能：交叉引用完整信息
        用途：一次获取地址的 xref 数量 + xref 类型 + 函数类型
        调用示例：get_xrefs_combined(addresses="0x401000")
                  get_xrefs_combined(addresses=["0x401000", "0x402000"])
        返回：JSON 包含每个地址的 {xref_count, xref_types, function_type}
        说明：调用 GetXrefCountAt + GetXrefTypeAt + GetFunctionTypeAt。
        """
        try:
            # 统一为列表
            if isinstance(addresses, str):
                addr_list = [addresses.strip()]
            elif isinstance(addresses, list):
                addr_list = [a.strip() if isinstance(a, str) else str(a) for a in addresses]
            else:
                return _fmt_error("addresses 必须是字符串或字符串列表")

            # 校验每个地址格式
            for addr in addr_list:
                if not _ADDR_RE.match(addr):
                    return _fmt_error("地址格式非法", addr)

            if self.memory is None:
                return _fmt_error("petools 缺少 memory 实例")

            # 第一步：获取 xref 数量
            count_result = await asyncio.to_thread(self.memory.GetXrefCountAt, addr_list, timeout)
            # 第二步：获取 xref 类型
            type_result = await asyncio.to_thread(self.memory.GetXrefTypeAt, addr_list, timeout)
            # 第三步：获取函数类型
            func_type_result = await asyncio.to_thread(self.memory.GetFunctionTypeAt, addr_list, timeout)

            # 整理结果
            combined = {}
            for addr in addr_list:
                combined[addr] = {
                    "xref_count": _get_dict_value(count_result, addr, "0"),
                    "xref_types": _get_dict_value(type_result, addr, []),
                    "function_type": _get_dict_value(func_type_result, addr, "")
                }

            return _fmt_success({
                "addresses": addr_list,
                "combined": combined
            })
        except Exception as e:
            logger.exception("获取交叉引用完整信息失败")
            return _fmt_error("获取交叉引用完整信息失败", e)

    # ============================================================
    # 14. find_xrefs_via_x64dbg - 通过 findref 命令查引用
    # ============================================================
    async def find_xrefs_via_x64dbg(self, address: str,
                                    timeout: float = 15.0) -> str:
        """
        功能：通过 findref 命令查引用
        用途：用 x64dbg 内置 findref 命令查找地址引用（补充 GetXrefTypeAt 静态分析）
        调用示例：find_xrefs_via_x64dbg(address="0x401000")
        返回：JSON 包含 address/references/raw_output
        说明：调用 RunCmd("findref(0xADDR)") 执行 x64dbg 内置 findref 命令。
              修复毒舌审查P1 Bug: RunCmd 实际只返回 {"RunCmd":"<文本输出>"} 或
              {"RunCmd":"Error","Reason":"..."} 两种格式，不返回 list 字段。
              原代码遍历其他 key 的 list 字段永远不会命中。
              修复后：仅从 RunCmd 文本输出用正则提取地址，并过滤掉查找的目标地址本身。
              注意：findref 是 x64dbg 命令，输出文本格式可能因版本而异。
              若输出为空或为 "0x..."（仅目标地址自身），则视为无引用。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(address, str) or not _ADDR_RE.match(address.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", address)

            if self.script is None:
                return _fmt_error("petools 缺少 script 实例")

            clean_addr = address.strip()
            # 转成大写十六进制（去掉前导0，保留 0x）
            addr_int = _parse_addr(clean_addr)
            addr_hex = _fmt_addr(addr_int)

            # 构造 findref 命令（x64dbg 语法）
            cmd = f"findref({addr_hex})"
            result = await asyncio.to_thread(self.script.RunCmd, cmd, timeout)

            # 修复毒舌审查P1 Bug: RunCmd 实际只返回字符串文本，不返回 list 字段
            # 移除原代码中遍历其他 key 的 list 字段（永远不会命中）
            references = []
            if isinstance(result, dict):
                runcmd_val = result.get("RunCmd", "")
                # RunCmd 错误判断（注意：错误时 RunCmd="Error"，且会有 Reason 字段）
                if isinstance(runcmd_val, str):
                    if runcmd_val.lower() == "error":
                        return _fmt_error("findref 命令执行失败", result.get("Reason", result))
                    # 从输出文本中正则提取所有 0x 前缀的十六进制地址
                    found_addrs = re.findall(r'0x[0-9a-fA-F]+', runcmd_val)
                    # 去重并过滤掉目标地址自身（findref 输出通常包含目标地址）
                    target_upper = addr_hex.upper()
                    seen = set()
                    for addr_str in found_addrs:
                        # 统一格式为大写便于比较
                        normalized = addr_str.upper()
                        # 跳过目标地址自身
                        if normalized == target_upper:
                            continue
                        if normalized not in seen:
                            seen.add(normalized)
                            references.append(addr_str)

            return _fmt_success({
                "address": clean_addr,
                "address_hex": addr_hex,
                "command": cmd,
                "reference_count": len(references),
                "references": references,
                "raw_output": result
            })
        except Exception as e:
            logger.exception("通过 findref 查引用失败")
            return _fmt_error("通过 findref 查引用失败", e)

    # ============================================================
    # 15. monitor_global_flag_write - 全局 flag 写入监控（卡密验证核心）
    # ============================================================
    async def monitor_global_flag_write(self, flag_addr: str,
                                        max_writes: int = 5,
                                        wait_timeout: float = 10.0,
                                        timeout: float = 5.0) -> str:
        """
        功能：全局 flag 写入监控（卡密验证核心）
        用途：监控卡密验证 flag 变量的写入者，定位验证逻辑
        调用示例：monitor_global_flag_write(flag_addr="0x12345678", max_writes=5)
        返回：JSON 包含 flag_addr/write_count/write_records
        说明：调用 SetHardwareBreakPoint(flag_addr, break_type=2=写) 设写断点，
              循环 Wait + Run + 采集寄存器+反汇编，记录写入者。
              最后 DeleteHardwareBreakPoint 清理。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(flag_addr, str) or not _ADDR_RE.match(flag_addr.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", flag_addr)
            if max_writes < 1 or max_writes > 50:
                return _fmt_error("max_writes 必须在 1-50 之间")

            if self.dbg is None or self.dissasm is None:
                return _fmt_error("petools 缺少 dbg/dissasm 实例")

            clean_addr = flag_addr.strip()

            # 修复毒舌审查P0 Bug: 调试器状态操作加锁，防止多工具并发竞态
            # x64dbg 是单实例状态机，SetHardwareBreakPoint/Wait/Run/DeleteHardwareBreakPoint
            # 必须串行化，否则多个工具同时操作调试器状态会翻车
            write_records = []
            write_count = 0
            async with self._debugger_lock:
                # 第一步：设置写断点（break_type=2=Write）
                set_result = await asyncio.to_thread(
                    self.dbg.SetHardwareBreakPoint, clean_addr, 2, timeout
                )
                if not _is_success(set_result, "SetHardwareBreakPoint"):
                    return _fmt_error("设置写断点失败", set_result)

                try:
                    # 第二步：循环 Wait + 采集，直到 max_writes 或超时
                    for i in range(max_writes):
                        wait_result = await asyncio.to_thread(self.dbg.Wait, wait_timeout)
                        wait_status = _get_dict_value(wait_result, "Wait", "")
                        if wait_status.lower() != "success":
                            break

                        write_count += 1

                        # 采集 rip
                        rip_result = await asyncio.to_thread(self.dbg.get_register, "rip", timeout)
                        rip_val = _get_dict_value(rip_result, "RIP", "0x0")

                        # 采集关键寄存器（写入者标识：rax/rbx/rcx/rdx/rsi/rdi + 写入值相关）
                        reg_list = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                    "rbp", "rsp", "r8", "r9", "r10", "r11", "r12"]
                        regs_result = await asyncio.to_thread(self.dbg.get_register, reg_list, timeout)

                        # 反汇编命中处指令（看是 mov 还是其他写操作）
                        disasm_result = None
                        try:
                            disasm_result = await asyncio.to_thread(
                                self.dissasm.DisasmOneCode, rip_val, timeout
                            )
                        except Exception:
                            logger.exception("反汇编命中处指令失败")

                        write_records.append({
                            "write_index": write_count,
                            "rip": rip_val,
                            "disasm": disasm_result,
                            "registers": regs_result if isinstance(regs_result, dict) else {}
                        })

                        # 继续运行等待下一次写入
                        if i < max_writes - 1:
                            run_result = await asyncio.to_thread(self.dbg.Run, timeout)
                            if not _is_success(run_result, "Run"):
                                break
                finally:
                    # 第三步：清理断点（必须在锁内，防止其他工具抢占调试器状态）
                    try:
                        await asyncio.to_thread(self.dbg.DeleteHardwareBreakPoint, clean_addr, timeout)
                    except Exception:
                        logger.exception("清理写断点失败")

            return _fmt_success({
                "flag_addr": clean_addr,
                "write_count": write_count,
                "write_records": write_records
            })
        except Exception as e:
            logger.exception("全局 flag 写入监控失败")
            return _fmt_error("全局 flag 写入监控失败", e)

    # ============================================================
    # 16. trace_into_with_filter - 带过滤的单步跟踪
    # ============================================================
    async def trace_into_with_filter(self, start_addr: str,
                                     max_steps: int = 100,
                                     module_filter: bool = True,
                                     timeout: float = 5.0) -> str:
        """
        功能：带过滤的单步跟踪
        用途：单步跟踪执行流，只在主模块内记录（过滤系统模块）
        调用示例：trace_into_with_filter(start_addr="0x401000", max_steps=100)
        返回：JSON 包含 trace_count/instructions/stop_reason
        说明：循环 Wait + get_register(rip) + DisasmOneCode + StepOver。
              过滤：只在主模块内记录（用 GetMainModuleBase/Size 判断范围）。
              注意：调用前应已设置好断点并在目标地址暂停。
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(start_addr, str) or not _ADDR_RE.match(start_addr.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", start_addr)
            if max_steps < 1 or max_steps > 1000:
                return _fmt_error("max_steps 必须在 1-1000 之间")

            if self.dbg is None or self.dissasm is None:
                return _fmt_error("petools 缺少 dbg/dissasm 实例")

            clean_addr = start_addr.strip()

            # 获取主模块范围（用于过滤）
            mod_base = 0
            mod_size = 0
            if module_filter and self.module is not None:
                try:
                    base_result = await asyncio.to_thread(self.module.GetMainModuleBase, timeout)
                    base_str = _get_dict_value(base_result, "base_address", "0x0")
                    mod_base = _parse_addr(base_str)

                    size_result = await asyncio.to_thread(self.module.GetMainModuleSize, timeout)
                    size_val = _get_dict_value(size_result, "size", 0)
                    if isinstance(size_val, str):
                        size_val = _parse_addr(size_val)
                    mod_size = int(size_val)
                except Exception:
                    logger.exception("获取主模块范围失败，将不进行过滤")
                    module_filter = False

            instructions = []
            trace_count = 0
            stop_reason = "max_steps_reached"

            # 修复毒舌审查P0 Bug: 调试器状态操作加锁，防止多工具并发竞态
            # 循环中的 get_register/StepOver 都是调试器状态操作，必须串行化
            async with self._debugger_lock:
                for i in range(max_steps):
                    # 采集当前 rip
                    rip_result = await asyncio.to_thread(self.dbg.get_register, "rip", timeout)
                    rip_val = _get_dict_value(rip_result, "RIP", "0x0")
                    rip_int = _parse_addr(rip_val) if rip_val else 0

                    # 判断是否在主模块内
                    in_main_module = True
                    if module_filter:
                        in_main_module = mod_base <= rip_int < (mod_base + mod_size)

                    # 只记录主模块内的指令
                    if in_main_module:
                        disasm_result = None
                        try:
                            disasm_result = await asyncio.to_thread(
                                self.dissasm.DisasmOneCode, rip_val, timeout
                            )
                        except Exception:
                            logger.exception("反汇编指令失败")

                        instructions.append({
                            "step": i + 1,
                            "rip": rip_val,
                            "disasm": disasm_result
                        })
                        trace_count += 1

                    # StepOver 单步执行
                    step_result = await asyncio.to_thread(self.dbg.StepOver, timeout)
                    if not _is_success(step_result, "StepOver"):
                        stop_reason = "step_failed"
                        break

            return _fmt_success({
                "start_addr": clean_addr,
                "max_steps": max_steps,
                "trace_count": trace_count,
                "instructions": instructions,
                "stop_reason": stop_reason,
                "module_filter": module_filter,
                "mod_base": _fmt_addr(mod_base) if mod_base else "0x0",
                "mod_size": mod_size
            })
        except Exception as e:
            logger.exception("带过滤的单步跟踪失败")
            return _fmt_error("带过滤的单步跟踪失败", e)

    # ============================================================
    # 17. get_seh_chain - SEH 链分析
    # ============================================================
    async def get_seh_chain(self, timeout: float = 5.0) -> str:
        """
        功能：SEH 链分析（同时支持 x86 和 x64 进程）
        用途：分析 SEH 异常处理链（壳/反调试常用 SEH 检测）
        调用示例：get_seh_chain()
        返回：JSON 包含 teb_base/arch/chain_head/chain/chain_length
        说明：调用 GetTeb + ReadPtr(teb+0x0) 拿链头。
              根据 TEB 地址范围自动判断架构：
              - x86: TEB < 0x100000000，节点 next 在 +0x0，handler 在 +0x4，链尾 = 0xFFFFFFFF
              - x64: TEB >= 0x100000000，节点 next 在 +0x0，handler 在 +0x8，链尾 = 0xFFFFFFFFFFFFFFFF
              注意：x64 进程通常用 VEH 而非 SEH，TEB+0x0 在 x64 上可能为空或无效。
              x64 进程上本工具返回的 chain 多半为空，仅供确认。
        """
        try:
            if self.process is None or self.memory is None:
                return _fmt_error("petools 缺少 process/memory 实例")

            # 第一步：获取 TID 和 TEB 基地址
            tid_result = await asyncio.to_thread(self.process.GetTid, timeout)
            tid_str = str(_extract_value(tid_result))
            teb_result = await asyncio.to_thread(self.process.GetTeb, tid_str, timeout)
            teb_base_str = str(_extract_value(teb_result))
            teb_base = _parse_addr(teb_base_str)

            # 修复毒舌审查P1 Bug: 根据 TEB 地址范围判断架构，正确选择偏移与链尾标志
            # x86 进程 TEB 通常在 0x7FFD0000 附近（< 4GB）
            # x64 进程 TEB 通常在 0x7FFD_00000000 以上（>= 4GB）
            is_x64 = teb_base >= 0x100000000
            arch = "x64" if is_x64 else "x86"
            # x86: handler 偏移 +0x4，链尾 0xFFFFFFFF
            # x64: handler 偏移 +0x8，链尾 0xFFFFFFFFFFFFFFFF
            handler_offset = 0x8 if is_x64 else 0x4
            chain_tail = 0xFFFFFFFFFFFFFFFF if is_x64 else 0xFFFFFFFF

            # 第二步：读取 SEH 链头 (TEB+0x0, ptr)
            chain_head_addr = _fmt_addr(teb_base + 0x0)
            ch_result = await asyncio.to_thread(self.memory.ReadPtr, chain_head_addr, timeout)
            chain_head_str = _get_dict_value(ch_result, chain_head_addr, "0x0")

            chain = []
            # 第三步：遍历 SEH 链
            # x86 SEH 链节点结构：+0x0 next (ptr), +0x4 handler (ptr)，链尾 next = 0xFFFFFFFF
            # x64 SEH 链节点结构：+0x0 next (ptr), +0x8 handler (ptr)，链尾 next = 0xFFFFFFFFFFFFFFFF
            if chain_head_str and chain_head_str != "0x0":
                curr_str = chain_head_str
                # 最多遍历 64 个节点防止无限循环
                for i in range(64):
                    try:
                        curr_int = _parse_addr(curr_str)
                    except ValueError:
                        break
                    # next = curr+0x0
                    next_addr = _fmt_addr(curr_int + 0x0)
                    next_result = await asyncio.to_thread(self.memory.ReadPtr, next_addr, timeout)
                    next_str = _get_dict_value(next_result, next_addr, "0x0")

                    # handler = curr+handler_offset（x86:+0x4 / x64:+0x8）
                    handler_addr = _fmt_addr(curr_int + handler_offset)
                    handler_result = await asyncio.to_thread(self.memory.ReadPtr, handler_addr, timeout)
                    handler_str = _get_dict_value(handler_result, handler_addr, "0x0")

                    chain.append({
                        "index": i,
                        "node": curr_str,
                        "next": next_str,
                        "handler": handler_str
                    })

                    # 检查链尾标志（x86: 0xFFFFFFFF / x64: 0xFFFFFFFFFFFFFFFF）
                    if not next_str:
                        break
                    try:
                        next_int = _parse_addr(next_str)
                        if next_int == chain_tail:
                            break
                        curr_str = next_str
                    except ValueError:
                        break

            return _fmt_success({
                "teb_base": teb_base_str,
                "arch": arch,
                "chain_head": chain_head_str,
                "chain": chain,
                "chain_length": len(chain)
            })
        except Exception as e:
            logger.exception("SEH 链分析失败")
            return _fmt_error("SEH 链分析失败", e)

    # ============================================================
    # 18. scan_iat_and_resolve - IAT 扫描与解析
    # ============================================================
    async def scan_iat_and_resolve(self, timeout: float = 30.0) -> str:
        """
        功能：IAT 扫描与解析
        用途：扫描 call [iat] 指令并解析每个 IAT 项对应的 API 名（脱壳后重建 IAT）
        调用示例：scan_iat_and_resolve()
        返回：JSON 包含 iat_entries（每个含 thunk_addr/api_addr/api_name/module）
        说明：调用 GetImport 拿原始导入表的 (module, function_name) 列表，
              调用 ScanModule("FF 15 ?? ?? ?? ??", base) 扫 call [iat]，
              对每个匹配，ReadPtr 读 thunk 值拿运行时 API 地址，
              然后对每个 (module, function_name) 调用 GetModuleProcAddress 实时查询
              运行时 API 地址，构建运行时 addr -> api 反查表。
        修复毒舌审查P1 Bug: 原代码用 GetImport 返回的静态 address（磁盘 PE 地址）
              与 ReadPtr 读出的运行时地址（含 ASLR 重定位）比较，ASLR 下永远不匹配。
              修复后改用 GetModuleProcAddress 实时查询每个依赖模块导出函数的运行时地址。
        """
        try:
            if self.module is None or self.memory is None:
                return _fmt_error("petools 缺少 module/memory 实例")

            # 第一步：获取主模块基址和模块名
            base_result = await asyncio.to_thread(self.module.GetMainModuleBase, timeout)
            base_str = _get_dict_value(base_result, "base_address", "0x0")
            module_name = _get_dict_value(base_result, "module_name", "")
            base = _parse_addr(base_str)

            # 第二步：获取原始导入表的 (module, function_name) 列表
            # 仅用于拿到依赖模块名和函数名，不再使用静态 address 字段
            imports = []
            if module_name:
                try:
                    imp_result = await asyncio.to_thread(self.module.GetImport, module_name, timeout)
                    if isinstance(imp_result, dict):
                        imports = imp_result.get("imports", [])
                except Exception:
                    logger.exception("获取导入表失败")

            # 修复毒舌审查P1 Bug: 改用 GetModuleProcAddress 实时查询运行时 API 地址
            # 构建运行时 addr -> (module, api_name) 反查表
            # GetModuleProcAddress(module_name, function_name, timeout) -> {"address":"0x..."}
            addr_to_api = {}
            resolve_errors = []
            for dep in imports:
                if not isinstance(dep, dict):
                    continue
                dep_module = dep.get("dependency_module", "")
                if not dep_module:
                    continue
                for func in dep.get("functions", []):
                    if not isinstance(func, dict):
                        continue
                    func_name = func.get("function_name", "")
                    if not func_name:
                        continue
                    try:
                        proc_result = await asyncio.to_thread(
                            self.module.GetModuleProcAddress, dep_module, func_name, timeout
                        )
                        if isinstance(proc_result, dict):
                            runtime_addr = proc_result.get("address", "")
                            if runtime_addr and runtime_addr != "0x0":
                                # 统一大写作为 key
                                addr_to_api[runtime_addr.upper()] = (dep_module, func_name)
                    except Exception:
                        # 单个函数解析失败不影响整体
                        resolve_errors.append(f"{dep_module}!{func_name}")

            # 第三步：扫描 call [iat] 指令（机器码 FF 15 ?? ?? ?? ??）
            # FF 15 = call dword ptr [rip+disp32] (x64) 或 call dword ptr [disp32] (x86)
            # 用 ScanModule 扫描，pattern 支持 ?? 通配符
            scan_pattern = "FF 15 ?? ?? ?? ??"
            scan_result = await asyncio.to_thread(
                self.memory.ScanModule, scan_pattern, base_str, timeout
            )
            scan_addrs = _extract_scan_results(scan_result)

            # 第四步：对每个匹配地址，读取 call 指令的操作数（IAT thunk 地址）
            # FF 15 后跟 4 字节相对偏移（x64 RIP 相对寻址）
            # thunk 实际地址 = 下一条指令地址 + disp32
            # 下一条指令地址 = 匹配地址 + 6
            iat_entries = []
            # 限制最多处理 256 个匹配，防止超时
            for match_addr_str in scan_addrs[:256]:
                try:
                    match_addr = _parse_addr(match_addr_str)
                    # 读取 disp32（call 指令的第 2-5 字节，即 match_addr+2）
                    disp_addr = _fmt_addr(match_addr + 2)
                    disp_result = await asyncio.to_thread(self.memory.ReadDword, disp_addr, timeout)
                    disp_str = _get_dict_value(disp_result, disp_addr, "0x0")
                    disp32 = _parse_addr(disp_str) if disp_str else 0

                    # x64: thunk_addr = next_insn_addr + disp32 = (match_addr + 6) + disp32
                    # 注意：disp32 是有符号的，这里用无符号处理（大多数情况足够）
                    next_insn = match_addr + 6
                    thunk_addr_int = next_insn + disp32
                    # 处理有符号（若 disp32 > 0x7FFFFFFF 则是负数）
                    if disp32 > 0x7FFFFFFF:
                        thunk_addr_int = next_insn - (0x100000000 - disp32)

                    thunk_addr_str = _fmt_addr(thunk_addr_int)

                    # 读取 thunk 指向的 API 地址
                    api_addr_result = await asyncio.to_thread(
                        self.memory.ReadPtr, thunk_addr_str, timeout
                    )
                    api_addr_str = _get_dict_value(api_addr_result, thunk_addr_str, "0x0")

                    # 反查 API 名（用运行时地址匹配）
                    api_name = "unknown"
                    dep_module = "unknown"
                    if api_addr_str:
                        lookup_key = api_addr_str.upper()
                        if lookup_key in addr_to_api:
                            dep_module, api_name = addr_to_api[lookup_key]

                    iat_entries.append({
                        "call_addr": match_addr_str,
                        "thunk_addr": thunk_addr_str,
                        "api_addr": api_addr_str,
                        "api_name": api_name,
                        "module": dep_module
                    })
                except Exception:
                    logger.exception("解析 IAT 项失败: %s", match_addr_str)
                    continue

            return _fmt_success({
                "base": base_str,
                "module_name": module_name,
                "import_count": len(imports),
                "runtime_resolved_count": len(addr_to_api),
                "resolve_errors": resolve_errors,
                "scan_pattern": scan_pattern,
                "scan_match_count": len(scan_addrs),
                "iat_resolved_count": len(iat_entries),
                "iat_entries": iat_entries
            })
        except Exception as e:
            logger.exception("IAT 扫描与解析失败")
            return _fmt_error("IAT 扫描与解析失败", e)

    # ============================================================
    # P3 低优先级：便捷工具
    # ============================================================
    # 19. bypass_anti_debug_via_runcmd - 通过 x64dbg 命令绕过反调试
    # ============================================================
    async def bypass_anti_debug_via_runcmd(self, timeout: float = 5.0) -> str:
        """
        功能：通过 x64dbg 命令绕过反调试
        用途：用 x64dbg 内置 hide/SetPEBCorrection 命令一键绕过常见反调试
        调用示例：bypass_anti_debug_via_runcmd()
        返回：JSON 包含 commands_executed/results
        说明：调用 RunCmd("hide") + RunCmd("SetPEBCorrection")。
              hide: 隐藏调试器（绕过 IsDebuggerPresent/CheckRemoteDebuggerPresent）
              SetPEBCorrection: 修正 PEB 反调试标志
        """
        try:
            if self.script is None:
                return _fmt_error("petools 缺少 script 实例")

            commands = ["hide", "SetPEBCorrection"]
            results = []

            for cmd in commands:
                try:
                    result = await asyncio.to_thread(self.script.RunCmd, cmd, timeout)
                    status = "Success"
                    if isinstance(result, dict):
                        runcmd_val = result.get("RunCmd", "")
                        if isinstance(runcmd_val, str) and runcmd_val.lower() == "error":
                            status = "Error"
                    results.append({
                        "command": cmd,
                        "status": status,
                        "result": result
                    })
                except Exception as cmd_err:
                    logger.exception("执行命令失败: %s", cmd)
                    results.append({
                        "command": cmd,
                        "status": "Exception",
                        "error": str(cmd_err)
                    })

            success_count = sum(1 for r in results if r["status"] == "Success")

            return _fmt_success({
                "commands_executed": len(commands),
                "success_count": success_count,
                "results": results
            })
        except Exception as e:
            logger.exception("通过 x64dbg 命令绕过反调试失败")
            return _fmt_error("通过 x64dbg 命令绕过反调试失败", e)

    # ============================================================
    # 20. dump_memory_range - dump 任意地址范围
    # ============================================================
    # 修复毒舌审查P0 Bug: 与 dump_module_memory 同步修复——默认 64KB + ReadDword 提速
    async def dump_memory_range(self, start_addr: str, size: int,
                                max_size: int = 0x10000,
                                timeout: float = 30.0) -> str:
        """
        功能：dump 任意地址范围（分块读取，防撑爆 MCP 消息）
        用途：dump 指定地址范围的内存（脱壳后 dump 特定段）
        调用示例：dump_memory_range(start_addr="0x401000", size=0x1000)
        返回：JSON 包含 start/size/bytes_dumped/base64_data/md5
        说明：修复毒舌审查P0 Bug——原版默认 1MB 撑爆 MCP 消息上限。
              修复后：1. 默认 max_size=64KB（base64≈85KB，安全在 MCP 消息上限内）
                     2. 用 ReadDword 批量读（4字节/次）替代 ReadByte，提速 4 倍
                     3. 如需 dump 更大范围，调用方显式传 size 并分块调用
        """
        try:
            # 校验地址格式（防止注入）
            if not isinstance(start_addr, str) or not _ADDR_RE.match(start_addr.strip()):
                return _fmt_error("地址格式非法（仅允许 0x 十六进制或纯数字）", start_addr)
            if not isinstance(size, int) or size <= 0:
                return _fmt_error("size 必须为正整数")
            if size > max_size:
                return _fmt_error(f"size 超过最大限制 {max_size}（防撑爆 MCP 消息，如需更大请分块调用）", str(size))

            if self.memory is None:
                return _fmt_error("petools 缺少 memory 实例")

            clean_addr = start_addr.strip()

            # 第一步：校验地址可读
            valid_result = await asyncio.to_thread(self.memory.IsValidReadPtr, clean_addr, timeout)
            is_valid = _get_dict_value(valid_result, clean_addr, "False")
            if isinstance(is_valid, str) and is_valid.lower() != "true":
                return _fmt_error("地址不可读", f"{clean_addr} -> {valid_result}")

            # 修复毒舌审查P0 Bug: 用 ReadDword 批量读（4字节/次）替代 ReadByte
            base_int = _parse_addr(clean_addr)
            all_bytes = bytearray()
            bytes_dumped = 0
            dword_count_per_chunk = 1024  # 每次 1024 个 dword = 4096 字节
            chunk_byte_size = dword_count_per_chunk * 4

            while bytes_dumped < size:
                current_chunk_bytes = min(chunk_byte_size, size - bytes_dumped)
                current_dwords = current_chunk_bytes // 4
                addrs = _build_addr_list(base_int + bytes_dumped, current_dwords, 4)
                chunk_result = await asyncio.to_thread(self.memory.ReadDword, addrs, timeout)

                if not isinstance(chunk_result, dict):
                    break

                for addr in addrs:
                    dword_str = chunk_result.get(addr, "0x0")
                    if isinstance(dword_str, str):
                        try:
                            dword_val = int(dword_str, 16) if dword_str.lower().startswith("0x") else int(dword_str)
                            all_bytes.append(dword_val & 0xFF)
                            all_bytes.append((dword_val >> 8) & 0xFF)
                            all_bytes.append((dword_val >> 16) & 0xFF)
                            all_bytes.append((dword_val >> 24) & 0xFF)
                        except ValueError:
                            all_bytes.extend(b'\x00\x00\x00\x00')
                    else:
                        all_bytes.extend(b'\x00\x00\x00\x00')

                bytes_dumped += current_dwords * 4

            # 第三步：base64 编码 + md5 校验
            b64_data = base64.b64encode(bytes(all_bytes)).decode('ascii')
            md5_hash = hashlib.md5(bytes(all_bytes)).hexdigest()

            return _fmt_success({
                "start": clean_addr,
                "size": size,
                "bytes_dumped": bytes_dumped,
                "base64_data": b64_data,
                "base64_size": len(b64_data),
                "md5": md5_hash,
                "truncated": bytes_dumped < size
            })
        except Exception as e:
            logger.exception("dump 任意地址范围失败")
            return _fmt_error("dump 任意地址范围失败", e)

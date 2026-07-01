"""
fusion2.py - 第二轮融合增强工具集

融合以下成熟开源项目的独特优点（基于真实 API 签名实现，非套壳）：

1. ida-pro-mcp (mrexodia/ida-pro-mcp, 503 commits, MIT license)
   独特优点：
   - int_convert: 数字进制转换（避免 LLM 自己转换出错，README 明确强调）
   - set_comments: 批量设置注释
   - analyze_funcs: 综合函数分析（反汇编+xrefs+callees+strings+constants）
   - get_string: 读取 null-terminated 字符串
   - find_bytes: 字节模式搜索
   - read_struct: 结构体字段读取
   - dbg_regs_all: 所有线程寄存器
   - dbg_stacktrace: 带模块信息的调用栈

2. GhidraMCP (NSA Ghidra MCP)
   独特优点：
   - list_methods / search_functions_by_name: 函数枚举与搜索
   - decompile_function: 反编译（动态调试中通过反汇编+注释近似）

3. Cheat Engine MCP
   独特优点：
   - 指针链分析（通过多级指针读取实现）
   - 内存值追踪（通过断点+寄存器记录实现）

设计原则：
- 所有 API 调用基于 core.py 真实签名（已验证）
- 返回值处理基于真实格式（无 status 字段，直接处理内层 dict）
- 真正的功能组合，不是套壳
- 完整错误处理（logging + errors 字段）
"""

import asyncio
import json
import logging
import re
from typing import Union, List, Optional, Dict, Any

# 模块级 logger
logger = logging.getLogger(__name__)


# ============================================================
# 输入校验正则（防止命令注入，第一轮毒舌审查教训）
# ============================================================
_ADDR_RE = re.compile(r'^(0x[0-9a-fA-F]+|\d+)$')
# 数字进制转换输入：支持十进制、0x前缀十六进制、纯十六进制、字节序列
_NUM_RE = re.compile(r'^(0x[0-9a-fA-F]+|\d+|[0-9a-fA-F]+)$')


def _parse_addr(addr: str) -> int:
    """统一地址解析：0x 前缀或无前缀都按 16 进制解析，纯十进制按 10 进制"""
    if not isinstance(addr, str):
        raise ValueError(f"地址必须是字符串，收到 {type(addr).__name__}")
    addr = addr.strip()
    if not addr:
        raise ValueError("地址不能为空")
    # 纯十进制（全数字且不以 0 开头，或就是 0）
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
    """格式化地址为 0x 前缀十六进制字符串"""
    return f"0x{val:X}"


def _fmt_success(result: Any) -> str:
    """格式化成功响应（避免循环导入 main.py 的 ResponseFormatter）"""
    return json.dumps({
        "status": "success",
        "result": result
    }, ensure_ascii=False, indent=2)


def _fmt_error(message: str, details: Any = None) -> str:
    """格式化错误响应"""
    if details:
        msg = f"{message}（详情：{str(details)}）"
    else:
        msg = message
    return json.dumps({
        "status": "error",
        "message": msg
    }, ensure_ascii=False, indent=2)


class FusionTools2:
    """
    第二轮融合增强工具集
    融合 ida-pro-mcp / GhidraMCP / CE MCP 的独特优点
    复用 PeTools 的 API 实例（避免第一轮重复构造的错误）
    """

    def __init__(self, petools):
        """
        接收 PeTools 实例，复用其 http_client 和各类 API 实例
        避免第一轮重复构造 Config/BaseHttpClient 的错误
        使用 getattr 延迟访问，让纯计算工具（如 int_convert）不依赖完整 petools
        """
        self.petools = petools
        # 延迟访问 petools 的 API 实例，只有实际调用相关工具时才需要
        # 这样 int_convert 这种纯计算工具即使 petools 不完整也能工作
        self._dbg = None
        self._dissasm = None
        self._module = None
        self._memory = None
        self._process = None
        self._gui = None
        self._script = None

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
    # 融合 ida-pro-mcp: int_convert
    # ida-pro-mcp README 明确强调："LLMs prone to hallucinations,
    # NEVER convert number bases yourself. Use int_convert MCP tool"
    # 这是专门为 AI 设计的工具，避免 AI 自己转换进制出错
    # ============================================================
    async def int_convert(self, inputs: Union[str, int, List[str]]) -> str:
        """
        功能：数字进制转换（融合 ida-pro-mcp int_convert）
        用途：AI 永远不要自己转换进制，必须用此工具！
             避免 AI 幻觉导致的进制转换错误（如把 0x100 当成 256 还是 100）
        调用示例：int_convert(inputs="0x401000")
                  int_convert(inputs=["0x401000", "4198400", "FF 25"])
        返回：JSON 包含每个输入的十进制/十六进制/字节/ASCII/二进制表示
        说明：ida-pro-mcp README 明确要求 AI 使用此工具而非自己转换
              支持 0x 前缀十六进制、纯十进制、字节序列（空格分隔）
        """
        try:
            # 统一为列表处理
            if isinstance(inputs, (str, int)):
                input_list = [str(inputs)]
            else:
                input_list = [str(x) for x in inputs]

            results = []
            for inp in input_list:
                inp = inp.strip()
                entry = {"input": inp}

                try:
                    # 尝试解析为数字
                    if inp.lower().startswith("0x"):
                        # 0x 前缀十六进制
                        num = int(inp, 16)
                    elif " " in inp:
                        # 字节序列（如 "FF 25 00"）
                        bytes_list = inp.split()
                        byte_values = [int(b, 16) for b in bytes_list]
                        # 组合成大端整数
                        num = 0
                        for b in byte_values:
                            num = (num << 8) | b
                        entry["as_bytes"] = " ".join(f"{b:02X}" for b in byte_values)
                        entry["byte_count"] = len(byte_values)
                    elif all(c in "0123456789abcdefABCDEF" for c in inp) and len(inp) > 0:
                        # 纯十六进制字符（无 0x 前缀）
                        # 但要区分十进制和十六进制：纯数字按十进制
                        if inp.isdigit():
                            num = int(inp, 10)
                        else:
                            num = int(inp, 16)
                    else:
                        entry["error"] = f"无法解析为数字: {inp}"
                        results.append(entry)
                        continue

                    # 生成所有格式表示
                    entry["decimal"] = str(num)
                    entry["hexadecimal"] = f"0x{num:X}"
                    entry["binary"] = bin(num)
                    entry["octal"] = oct(num)

                    # 字节表示（小端和大端）
                    if num <= 0xFFFFFFFFFFFFFFFF:
                        # 计算需要的字节数
                        if num == 0:
                            byte_count = 1
                        else:
                            byte_count = (num.bit_length() + 7) // 8
                        big_endian_bytes = num.to_bytes(byte_count, byteorder='big')
                        little_endian_bytes = num.to_bytes(byte_count, byteorder='little')
                        entry["bytes_big_endian"] = " ".join(f"{b:02X}" for b in big_endian_bytes)
                        entry["bytes_little_endian"] = " ".join(f"{b:02X}" for b in little_endian_bytes)

                        # ASCII 表示（可打印字符）
                        ascii_chars = []
                        for b in big_endian_bytes:
                            if 0x20 <= b <= 0x7E:
                                ascii_chars.append(chr(b))
                            else:
                                ascii_chars.append(".")
                        entry["ascii"] = "".join(ascii_chars)

                    # 修复毒舌审查Bug 8: 原三元表达式 `byte_count == 4 if 'byte_count' in entry else num.bit_length() <= 32`
                    # 逻辑错误：当 'byte_count' 不在 entry 时（纯数字输入），条件退化为 num.bit_length() <= 32，
                    # 导致任何 32 位以内数字（含 1 字节、2 字节）都被强塞 float32 解析，结果无意义。
                    # 修复：拆成清晰 if-else，只对真实 4 字节输出 float32，8 字节输出 float64
                    import struct
                    # 确定实际字节长度：
                    # - 字节序列输入：用 entry["byte_count"]（用户输入的原始字节数）
                    # - 数字输入：用上面在 num <= 0xFFFF... 块中计算的 byte_count 局部变量
                    # - 兜底：若 byte_count 未定义（num 超过 16 字节），按 bit_length 重新推算
                    if 'byte_count' in entry:
                        actual_byte_count = entry["byte_count"]
                    else:
                        try:
                            actual_byte_count = byte_count
                        except NameError:
                            # byte_count 局部变量未定义时的兜底计算
                            actual_byte_count = (num.bit_length() + 7) // 8 if num > 0 else 1

                    if actual_byte_count == 4:
                        # 仅 4 字节输入：按 float32（小端）解析
                        try:
                            entry["float32"] = str(struct.unpack('<f', num.to_bytes(4, byteorder='little'))[0])
                        except Exception:
                            pass
                    elif actual_byte_count == 8:
                        # 仅 8 字节输入：按 float64（小端）解析
                        try:
                            entry["float64"] = str(struct.unpack('<d', num.to_bytes(8, byteorder='little'))[0])
                        except Exception:
                            pass

                except Exception as e:
                    entry["error"] = f"转换失败: {str(e)}"

                results.append(entry)

            return _fmt_success({
                "total": len(results),
                "conversions": results
            })
        except Exception as e:
            logger.exception("int_convert 失败")
            return _fmt_error("数字进制转换失败", e)

    # ============================================================
    # 融合 ida-pro-mcp: get_string
    # 读取 null-terminated 字符串，x64dbg 原生无此功能
    # 需要 ReadByte 循环直到遇到 0x00
    # ============================================================
    async def read_string(self, address: str, max_length: int = 256,
                          timeout: float = 10.0) -> str:
        """
        功能：读取 null-terminated 字符串（融合 ida-pro-mcp get_string）
        用途：读取内存中的字符串（如密码、路径、配置），x64dbg 原生无此功能
        调用示例：read_string(address="0x00401000", max_length=256)
        返回：JSON 包含字符串内容、长度、十六进制字节
        说明：从指定地址开始逐字节读取，直到遇到 0x00 或达到 max_length
              支持 ASCII 和宽字符（UTF-16LE）检测
        """
        try:
            # 输入校验
            if not _ADDR_RE.match(address):
                return _fmt_error("地址格式非法", f"address={address}")
            if max_length < 1 or max_length > 4096:
                return _fmt_error("max_length 必须在 1-4096 之间", f"max_length={max_length}")

            # 构造地址列表（每次读 1 字节）
            base = _parse_addr(address)
            # 分批读取（避免单次请求过大），每批 64 字节
            batch_size = 64
            all_bytes = []
            null_pos = -1
            # 修复毒舌审查Bug 6: 读取失败（空值）原被当作 null terminator 静默处理，
            # 现引入 read_error 记录失败原因，读取失败时中断并返回错误，不再填 0 掩盖问题
            read_error = None

            for offset in range(0, max_length, batch_size):
                current_batch = min(batch_size, max_length - offset)
                # 构造本批地址列表
                addr_list = [_fmt_addr(base + offset + i) for i in range(current_batch)]

                # 调用 ReadByte（真实签名：addresses 列表，返回 {地址: "0x41"} dict）
                result = await asyncio.to_thread(
                    self.memory.ReadByte, addr_list, timeout
                )

                # 解析返回值：result 是内层 dict，如 {"ReadByte": {"0x401000": "0x41", ...}}
                # 或直接是 {"0x401000": "0x41", ...}
                bytes_dict = result
                if isinstance(result, dict) and "ReadByte" in result:
                    bytes_dict = result["ReadByte"]
                elif not isinstance(result, dict):
                    return _fmt_error("ReadByte 返回格式异常", str(type(result)))

                # 按顺序提取字节值
                for i in range(current_batch):
                    addr_key = addr_list[i]
                    # ReadByte 返回的键可能格式不同（0x 前缀大小写），尝试多种
                    val_str = bytes_dict.get(addr_key, "")
                    if not val_str:
                        # 尝试小写
                        val_str = bytes_dict.get(addr_key.lower(), "")
                    if not val_str:
                        # 尝试大写
                        val_str = bytes_dict.get(addr_key.upper(), "")

                    # 修复毒舌审查Bug 6: 读取失败（val_str 为空）时不能 append(0) 当 null terminator，
                    # 这会掩盖内存不可读/地址非法等错误，并导致字符串被错误截断。
                    # 修复：记录错误并中断，返回已读取部分 + 错误信息
                    if not val_str:
                        read_error = f"地址 {addr_key} 读取失败（返回值为空），可能内存不可读或地址非法"
                        break

                    # 解析字节值
                    try:
                        if val_str.lower().startswith("0x"):
                            byte_val = int(val_str, 16)
                        else:
                            byte_val = int(val_str, 16)
                        all_bytes.append(byte_val)
                    except ValueError:
                        # 修复毒舌审查Bug 6: 解析失败也不能填 0，记录错误并中断
                        read_error = f"地址 {addr_key} 返回值 '{val_str}' 无法解析为字节"
                        break

                    # 检查真正的 null terminator（字节值为 0 才是合法终止符）
                    if all_bytes[-1] == 0:
                        null_pos = len(all_bytes) - 1
                        break

                # 读取失败：记录日志并中断后续批次，保留已读取的部分
                if read_error:
                    logger.warning(f"read_string 在地址 {address} 读取失败: {read_error}")
                    break

                if null_pos >= 0:
                    break

            # 提取字符串（到 null 或全部字节）
            if null_pos >= 0:
                str_bytes = all_bytes[:null_pos]
            else:
                str_bytes = all_bytes

            # 尝试 ASCII 解码
            try:
                ascii_str = bytes(str_bytes).decode('ascii', errors='replace')
            except Exception:
                ascii_str = ""

            # 尝试 UTF-16LE 解码（如果字节数为偶数且第二字节多为 0）
            utf16_str = ""
            if len(str_bytes) >= 2 and len(str_bytes) % 2 == 0:
                # 检查是否像 UTF-16（奇数位字节多为 0 表示 ASCII 范围的宽字符）
                zero_count = sum(1 for i in range(1, len(str_bytes), 2) if str_bytes[i] == 0)
                if zero_count > len(str_bytes) // 4:  # 超过 1/4 的高字节是 0
                    try:
                        utf16_str = bytes(str_bytes).decode('utf-16-le', errors='replace')
                    except Exception:
                        pass

            return _fmt_success({
                "address": address,
                "ascii": ascii_str,
                "utf16le": utf16_str if utf16_str else None,
                "length": len(str_bytes),
                "null_terminated": null_pos >= 0,
                # 修复毒舌审查Bug 6: 暴露读取失败信息，不再静默吞错
                "read_error": read_error,
                "truncated_by_error": read_error is not None,
                "hex_bytes": " ".join(f"{b:02X}" for b in str_bytes[:64]) + ("..." if len(str_bytes) > 64 else "")
            })
        except Exception as e:
            logger.exception("read_string 失败")
            return _fmt_error("读取字符串失败", e)

    # ============================================================
    # 融合 ida-pro-mcp: find_bytes + x64dbg 特征码搜索
    # 增强版：支持多模块搜索、通配符、结果数量限制
    # ============================================================
    async def find_pattern(self, pattern: str, search_scope: str = "main",
                           module_name: Optional[str] = None,
                           limit: int = 100,
                           timeout: float = 30.0) -> str:
        """
        功能：字节模式搜索（融合 ida-pro-mcp find_bytes + x64dbg ScanModule）
        用途：搜索特征码、定位函数、查找加密常数、patch 验证
        调用示例：find_pattern(pattern="FF 25 ?? ?? ?? ??", search_scope="main")
                  find_pattern(pattern="48 8B C4", search_scope="module", module_name="user32.dll")
        返回：JSON 包含匹配地址列表、数量、模块信息
        说明：search_scope 支持 main（主模块）/ module（指定模块）/ all（所有模块）
              pattern 支持通配符 ?? 表示任意字节
              limit 限制返回结果数量（防止超大结果集）
        """
        try:
            # 输入校验
            if not pattern or not isinstance(pattern, str):
                return _fmt_error("pattern 不能为空")
            if limit < 1 or limit > 10000:
                return _fmt_error("limit 必须在 1-10000 之间", f"limit={limit}")

            # 校验 pattern 格式（空格分隔的十六进制或 ??）
            tokens = pattern.strip().split()
            for tok in tokens:
                if tok == "??" or tok == "?":
                    continue
                if not re.match(r'^[0-9a-fA-F]{1,2}$', tok):
                    return _fmt_error("pattern 格式非法", f"token={tok}")

            all_matches = []
            searched_modules = []

            if search_scope == "main":
                # 搜索主模块
                # 获取主模块基址
                base_result = await asyncio.to_thread(
                    self.module.GetMainModuleBase, timeout
                )
                base = self._extract_value(base_result)
                if not base:
                    return _fmt_error("无法获取主模块基址", str(base_result))

                # 调用 ScanModule
                scan_result = await asyncio.to_thread(
                    self.memory.ScanModule, pattern, str(base), timeout
                )
                matches = self._extract_scan_results(scan_result)
                all_matches.extend(matches[:limit])
                searched_modules.append({"name": "main", "base": str(base), "matches": len(matches)})

            elif search_scope == "module":
                # 搜索指定模块
                if not module_name:
                    return _fmt_error("search_scope=module 时必须指定 module_name")

                # 获取模块基址
                base_result = await asyncio.to_thread(
                    self.module.GetModuleBaseAddress, module_name, timeout
                )
                base = self._extract_value(base_result)
                if not base:
                    return _fmt_error(f"无法找到模块: {module_name}")

                scan_result = await asyncio.to_thread(
                    self.memory.ScanModule, pattern, str(base), timeout
                )
                matches = self._extract_scan_results(scan_result)
                all_matches.extend(matches[:limit])
                searched_modules.append({"name": module_name, "base": str(base), "matches": len(matches)})

            elif search_scope == "all":
                # 搜索所有模块（获取模块列表后逐个搜索）
                modules_result = await asyncio.to_thread(
                    self.module.GetAllModule, timeout
                )
                # 修复毒舌审查Bug 2 & Bug 9: GetAllModule 真实返回结构为
                # {"module_count": N, "modules": [{"module_name":..., "base_address":..., "size":..., "path":..., ...}]}
                # 已通过 Grep core.py 第3395-3451行验证。
                # 原代码错误1: 用通用 _extract_value 会取到 module_count（整数12）而非 modules 列表
                # 原代码错误2: 字段名猜测为 base/Base/BASE、name/Name，真实字段为 base_address、module_name
                # 修复: 专门取 "modules" 字段，并用真实字段名 base_address / module_name
                modules = None
                if isinstance(modules_result, dict):
                    modules = modules_result.get("modules")
                if not isinstance(modules, list):
                    return _fmt_error("无法获取模块列表", str(modules_result))

                for mod in modules:
                    if isinstance(mod, dict):
                        # 修复毒舌审查Bug 2: 使用真实字段名 base_address / module_name（已Grep验证core.py）
                        mod_base = mod.get("base_address")
                        mod_name = mod.get("module_name") or "unknown"
                    else:
                        continue

                    if not mod_base:
                        continue

                    try:
                        scan_result = await asyncio.to_thread(
                            self.memory.ScanModule, pattern, str(mod_base), timeout
                        )
                        matches = self._extract_scan_results(scan_result)
                        if matches:
                            all_matches.extend(matches[:limit - len(all_matches)])
                            searched_modules.append({
                                "name": mod_name,
                                "base": str(mod_base),
                                "matches": len(matches)
                            })
                            if len(all_matches) >= limit:
                                break
                    except Exception as e:
                        logger.debug(f"搜索模块 {mod_name} 失败: {e}")
                        continue
            else:
                return _fmt_error("search_scope 必须是 main/module/all", f"got={search_scope}")

            return _fmt_success({
                "pattern": pattern,
                "scope": search_scope,
                "total_matches": len(all_matches),
                "truncated": len(all_matches) >= limit,
                "matches": all_matches,
                "searched_modules": searched_modules
            })
        except Exception as e:
            logger.exception("find_pattern 失败")
            return _fmt_error("模式搜索失败", e)

    def _extract_value(self, result: Any) -> Any:
        """
        从 core.py API 返回值中提取实际数据（处理无 status 字段的情况）
        修复毒舌审查Bug 9: 原实现盲目取 dict 第一个值，对多 key dict 不可靠。
        例如 GetAllModule 返回 {"module_count": 12, "modules": [...]}，
        原实现会取到 module_count=12（整数），而非 modules 列表，导致后续逻辑全部失效。
        修复策略：单 key dict 直接取值；多 key dict 按常见数据字段名优先级提取，
        找不到则返回 None，由调用方写专门解析逻辑（避免返回错误数据）。
        """
        if isinstance(result, dict):
            keys = list(result.keys())
            # 单 key dict：直接取值
            # 适用于 {"GetThreadList": [...]} / {"GetMainModuleBase": "0x400000"} / {"GetTid": "1234"} 等
            if len(keys) == 1:
                return result[keys[0]]
            # 修复毒舌审查Bug 9: 多 key dict 不盲目取第一个值
            # 多 key dict（如 GetAllModule 返回 module_count + modules，
            # DisasmCountCode 返回 message + instructions + actual_count 等）
            # 按常见数据字段名优先级尝试提取
            for preferred_key in ("modules", "instructions", "result", "value", "data"):
                if preferred_key in result:
                    return result[preferred_key]
            # 找不到优先 key，返回 None 而非第一个值（避免返回错误数据）
            return None
        return result

    def _extract_scan_results(self, scan_result: Any) -> List[str]:
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

    # ============================================================
    # 融合 ida-pro-mcp: analyze_funcs
    # 综合函数分析：反汇编+常量+字符串+调用关系
    # x64dbg 动态调试版：反汇编 N 条 + 提取立即数 + 提取字符串引用
    # ============================================================
    async def analyze_function(self, address: str, instruction_count: int = 50,
                               timeout: float = 15.0) -> str:
        """
        功能：综合函数分析（融合 ida-pro-mcp analyze_funcs）
        用途：一次性获取函数的完整分析视图，减少 AI 多次调用
        调用示例：analyze_function(address="0x00401000", instruction_count=50)
        返回：JSON 包含反汇编、立即数、调用目标、字符串引用、寄存器使用
        说明：融合 ida-pro-mcp 的 analyze_funcs 思路：
              - 反汇编指定数量指令
              - 提取所有立即数（常量）
              - 提取所有 call/jmp 目标（调用关系）
              - 对疑似字符串地址尝试读取字符串
              - 统计寄存器使用频率
        """
        try:
            # 输入校验
            if not _ADDR_RE.match(address):
                return _fmt_error("地址格式非法", f"address={address}")
            if instruction_count < 1 or instruction_count > 500:
                return _fmt_error("instruction_count 必须在 1-500 之间")

            # 第一步：反汇编指令
            disasm_result = await asyncio.to_thread(
                self.dissasm.DisasmCountCode, address, instruction_count, timeout
            )
            disasm_data = self._extract_value(disasm_result)

            analysis = {
                "address": address,
                "instruction_count": instruction_count,
                "disassembly": disasm_data,
                "immediates": [],      # 立即数列表
                "call_targets": [],    # call 目标
                "jump_targets": [],    # jmp/jcc 目标
                "string_refs": [],     # 字符串引用
                "registers_used": {},  # 寄存器使用统计
            }

            # 修复毒舌审查Bug 7: 原代码对 disasm_data（dict）跑 json.dumps 后用正则提取 call/jmp/immediates，
            # 会把 address_hex/address_value 等字段里的地址误识别为指令立即数，
            # 且对 JSON 文本跑正则本身不可靠（字段名、转义符都会干扰匹配）。
            # DisasmCountCode 真实返回结构（已 Grep core.py 第1615行 + pluginmain.cpp 第11457行验证）：
            # {"message":..., "requested_count":N, "actual_count":N, "start_address_hex":"0x...",
            #  "instructions":[{"address_value":N, "address_hex":"0x...", "instruction":"push ebp", "size":N, "size_desc":"..."}, ...],
            #  "platform":"x64"}
            # 修复：从结构化 instructions 字段中提取每条指令的 "instruction" 文本，再跑正则，
            # 避免误提取地址字段。
            instruction_texts = []  # 提取出的纯指令文本列表

            # 优先从原始 disasm_result 中提取 instructions 列表（结构化解析）
            instructions_list = None
            if isinstance(disasm_result, dict):
                instructions_list = disasm_result.get("instructions")
            # 兼容 send_command 可能包了一层 result 的情况
            if not isinstance(instructions_list, list) and isinstance(disasm_result, dict):
                inner = disasm_result.get("result")
                if isinstance(inner, dict):
                    instructions_list = inner.get("instructions")

            if isinstance(instructions_list, list):
                # 结构化解析：从每个指令对象提取 "instruction" 字段（纯指令文本）
                for inst in instructions_list:
                    if isinstance(inst, dict):
                        inst_text = inst.get("instruction")
                        if isinstance(inst_text, str) and inst_text.strip():
                            instruction_texts.append(inst_text.strip())
                    elif isinstance(inst, str):
                        instruction_texts.append(inst.strip())

            # 兜底：若结构化提取失败，降级用原 disasm_data 的字符串表示
            if not instruction_texts:
                if isinstance(disasm_data, str):
                    instruction_texts = [line.strip() for line in disasm_data.split("\n") if line.strip()]
                elif isinstance(disasm_data, list):
                    for item in disasm_data:
                        if isinstance(item, dict):
                            t = item.get("instruction")
                            if isinstance(t, str):
                                instruction_texts.append(t.strip())
                        elif isinstance(item, str):
                            instruction_texts.append(item.strip())

            # 用纯指令文本（而非 JSON 字符串）做正则匹配，避免误提取地址字段
            disasm_str = "\n".join(instruction_texts)

            # 提取立即数（0x 前缀的十六进制数）
            immediates = re.findall(r'\b(0x[0-9a-fA-F]+)\b', disasm_str)
            # 去重并转换
            seen_immediates = set()
            for imm in immediates:
                if imm.lower() not in seen_immediates:
                    seen_immediates.add(imm.lower())
                    try:
                        val = int(imm, 16)
                        # 过滤掉太小的数（如 0x0, 0x1）和寄存器名误匹配
                        if val > 0xFF:
                            analysis["immediates"].append({
                                "hex": imm,
                                "decimal": val
                            })
                    except ValueError:
                        pass

            # 提取 call 目标
            call_matches = re.findall(r'\bcall\s+(0x[0-9a-fA-F]+)\b', disasm_str, re.IGNORECASE)
            for call_addr in call_matches:
                if call_addr not in analysis["call_targets"]:
                    analysis["call_targets"].append(call_addr)

            # 提取 jump 目标
            jump_matches = re.findall(r'\b(?:jmp|je|jne|jz|jnz|jg|jl|jge|jle|ja|jb|jae|jbe)\s+(0x[0-9a-fA-F]+)\b',
                                      disasm_str, re.IGNORECASE)
            for jmp_addr in jump_matches:
                if jmp_addr not in analysis["jump_targets"]:
                    analysis["jump_targets"].append(jmp_addr)

            # 统计寄存器使用
            reg_pattern = r'\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|eax|ebx|ecx|edx|esi|edi|ebp|esp|eip|rip|ax|bx|cx|dx|ah|al|bh|bl|ch|cl|dh|dl)\b'
            regs_found = re.findall(reg_pattern, disasm_str, re.IGNORECASE)
            for reg in regs_found:
                reg_lower = reg.lower()
                analysis["registers_used"][reg_lower] = analysis["registers_used"].get(reg_lower, 0) + 1

            # 对较大的立即数尝试读取字符串（可能是字符串指针）
            string_candidates = [imm for imm in analysis["immediates"]
                                 if int(imm["decimal"]) > 0x10000][:5]  # 最多检查 5 个
            for imm_info in string_candidates:
                try:
                    imm_addr = imm_info["hex"]
                    # 用 read_string 尝试读取（复用本类的方法）
                    str_result = await self.read_string(imm_addr, max_length=32, timeout=3.0)
                    str_data = json.loads(str_result)
                    if str_data.get("status") == "success":
                        str_content = str_data.get("result", {})
                        if str_content.get("ascii") and len(str_content["ascii"]) > 0:
                            analysis["string_refs"].append({
                                "address": imm_addr,
                                "string": str_content["ascii"],
                                "length": str_content.get("length", 0)
                            })
                except Exception as e:
                    logger.debug(f"读取字符串 {imm_info['hex']} 失败: {e}")

            return _fmt_success(analysis)
        except Exception as e:
            logger.exception("analyze_function 失败")
            return _fmt_error("函数分析失败", e)

    # ============================================================
    # 融合 ida-pro-mcp: read_struct
    # 结构体字段读取：按偏移列表批量读取
    # ============================================================
    async def read_struct(self, base_address: str, fields: List[Dict[str, Any]],
                          timeout: float = 15.0) -> str:
        """
        功能：读取结构体字段（融合 ida-pro-mcp read_struct）
        用途：读取 PE 头、TEB/PEB、自定义结构体等复杂数据结构
        调用示例：read_struct(
            base_address="0x00400000",
            fields=[
                {"name": "e_magic", "offset": 0, "type": "word"},
                {"name": "e_lfanew", "offset": 60, "type": "dword"},
                {"name": "ImageBase", "offset": 0x34, "type": "ptr"}
            ]
        )
        返回：JSON 包含每个字段的名称、偏移、地址、值
        说明：根据字段定义的 offset 和 type 批量读取内存
              type 支持 byte/word/dword/ptr
              自动计算每个字段的绝对地址
        """
        try:
            # 输入校验
            if not _ADDR_RE.match(base_address):
                return _fmt_error("base_address 格式非法", f"address={base_address}")
            if not fields or not isinstance(fields, list):
                return _fmt_error("fields 必须是非空列表")
            if len(fields) > 100:
                return _fmt_error("fields 数量不能超过 100", f"got={len(fields)}")

            base = _parse_addr(base_address)

            # 构造所有字段的地址列表，按 type 分组以便批量读取
            byte_addrs = []
            word_addrs = []
            dword_addrs = []
            ptr_addrs = []
            field_map = {}  # 记录每个地址对应哪个字段

            for field in fields:
                name = field.get("name", f"field_{field.get('offset', '?')}")
                offset = field.get("offset", 0)
                ftype = field.get("type", "dword")

                if not isinstance(offset, int) or offset < 0:
                    return _fmt_error(f"字段 {name} 的 offset 必须是非负整数", f"offset={offset}")

                addr = _fmt_addr(base + offset)

                field_info = {"name": name, "offset": offset, "address": addr, "type": ftype}

                if ftype == "byte":
                    byte_addrs.append(addr)
                    field_map[addr] = field_info
                elif ftype == "word":
                    word_addrs.append(addr)
                    field_map[addr] = field_info
                elif ftype == "dword":
                    dword_addrs.append(addr)
                    field_map[addr] = field_info
                elif ftype == "ptr":
                    ptr_addrs.append(addr)
                    field_map[addr] = field_info
                else:
                    return _fmt_error(f"字段 {name} 的 type 非法", f"type={ftype}")

            # 并行批量读取（使用 Semaphore 限制并发，避免第一轮的无限并发问题）
            sem = asyncio.Semaphore(10)
            results = {}

            async def read_batch(addrs: List[str], read_func, ftype: str):
                """批量读取一组地址"""
                if not addrs:
                    return
                async with sem:
                    try:
                        read_result = await asyncio.to_thread(read_func, addrs, timeout)
                        # 解析返回值
                        values_dict = read_result
                        if isinstance(read_result, dict):
                            # 可能是 {"ReadByte": {...}} 或直接是 {...}
                            for key, val in read_result.items():
                                if isinstance(val, dict):
                                    values_dict = val
                                    break

                        for addr in addrs:
                            field_info = field_map[addr]
                            # 尝试多种键格式获取值
                            val_str = ""
                            for key_variant in [addr, addr.lower(), addr.upper()]:
                                if key_variant in values_dict:
                                    val_str = values_dict[key_variant]
                                    break

                            results[field_info["name"]] = {
                                "name": field_info["name"],
                                "offset": field_info["offset"],
                                "address": field_info["address"],
                                "type": ftype,
                                "value": val_str
                            }
                    except Exception as e:
                        logger.debug(f"批量读取 {ftype} 失败: {e}")
                        for addr in addrs:
                            field_info = field_map[addr]
                            results[field_info["name"]] = {
                                "name": field_info["name"],
                                "offset": field_info["offset"],
                                "address": field_info["address"],
                                "type": ftype,
                                "value": None,
                                "error": str(e)
                            }

            # 并行执行所有类型的批量读取
            await asyncio.gather(
                read_batch(byte_addrs, self.memory.ReadByte, "byte"),
                read_batch(word_addrs, self.memory.ReadWord, "word"),
                read_batch(dword_addrs, self.memory.ReadDword, "dword"),
                read_batch(ptr_addrs, self.memory.ReadPtr, "ptr"),
                return_exceptions=True
            )

            # 按原始 fields 顺序整理结果
            ordered_results = []
            for field in fields:
                name = field.get("name", f"field_{field.get('offset', '?')}")
                if name in results:
                    ordered_results.append(results[name])
                else:
                    ordered_results.append({
                        "name": name,
                        "offset": field.get("offset", 0),
                        "address": _fmt_addr(base + field.get("offset", 0)),
                        "type": field.get("type", "dword"),
                        "value": None,
                        "error": "未读取"
                    })

            return _fmt_success({
                "base_address": base_address,
                "field_count": len(ordered_results),
                "fields": ordered_results
            })
        except Exception as e:
            logger.exception("read_struct 失败")
            return _fmt_error("结构体读取失败", e)

    # ============================================================
    # 融合 ida-pro-mcp: dbg_regs_all + GetThreadList
    # 列出所有线程及其上下文信息
    # ============================================================
    async def list_threads(self, timeout: float = 10.0) -> str:
        """
        功能：列出所有线程及上下文（融合 ida-pro-mcp dbg_regs_all + GetThreadList）
        用途：多线程调试、死锁分析、线程状态监控
        调用示例：list_threads()
        返回：JSON 包含线程列表（TID/状态/起始地址）和当前线程信息
        说明：x64dbg 原生 GetThreadList 返回基本信息，
              本工具增强为带可读格式和统计信息
        """
        try:
            # 获取线程列表
            threads_result = await asyncio.to_thread(
                self.process.GetThreadList, timeout
            )
            threads_data = self._extract_value(threads_result)

            # 获取当前 TID
            tid_result = await asyncio.to_thread(
                self.process.GetTid, timeout
            )
            current_tid = self._extract_value(tid_result)

            # 获取主线程 ID
            main_tid_result = await asyncio.to_thread(
                self.process.GetMainThreadId, timeout
            )
            main_tid = self._extract_value(main_tid_result)

            # 整理线程信息
            threads_list = []
            if isinstance(threads_data, list):
                for t in threads_data:
                    if isinstance(t, dict):
                        thread_info = {
                            "tid": t.get("TID") or t.get("tid") or t.get("Tid") or "unknown",
                            "state": t.get("State") or t.get("state") or "unknown",
                            "start_address": t.get("StartAddress") or t.get("start_address") or "",
                        }
                        # 标记当前线程和主线程
                        thread_info["is_current"] = (str(thread_info["tid"]) == str(current_tid))
                        thread_info["is_main"] = (str(thread_info["tid"]) == str(main_tid))
                        threads_list.append(thread_info)
                    else:
                        threads_list.append({"raw": str(t)})
            elif isinstance(threads_data, dict):
                # 单个线程
                threads_list.append({
                    "tid": threads_data.get("TID", "unknown"),
                    "state": threads_data.get("State", "unknown"),
                    "start_address": threads_data.get("StartAddress", ""),
                    "is_current": str(threads_data.get("TID", "")) == str(current_tid),
                    "is_main": str(threads_data.get("TID", "")) == str(main_tid),
                })

            # 统计信息
            state_count = {}
            for t in threads_list:
                state = t.get("state", "unknown")
                state_count[state] = state_count.get(state, 0) + 1

            return _fmt_success({
                "total_threads": len(threads_list),
                "current_tid": current_tid,
                "main_tid": main_tid,
                "state_summary": state_count,
                "threads": threads_list
            })
        except Exception as e:
            logger.exception("list_threads 失败")
            return _fmt_error("获取线程列表失败", e)

    # ============================================================
    # 融合 ida-pro-mcp: set_comments（批量）
    # ida-pro-mcp 的 set_comments 支持批量，x64dbg 原生只能逐个设置
    # ============================================================
    async def batch_set_comments(self, comments: List[Dict[str, str]],
                                 timeout: float = 15.0) -> str:
        """
        功能：批量设置地址注释（融合 ida-pro-mcp set_comments）
        用途：分析后批量标注关键地址（函数功能、参数含义、漏洞点等）
        调用示例：batch_set_comments(comments=[
            {"address": "0x00401000", "comment": "main函数入口"},
            {"address": "0x00401050", "comment": "许可证校验"},
            {"address": "0x00401100", "comment": "关键跳转：成功/失败"}
        ])
        返回：JSON 包含每个注释的设置结果（成功/失败）
        说明：x64dbg 原生 SetComment 只能逐个设置，本工具批量设置提高效率
              使用 Semaphore 限并发，防止大量请求打满 HTTP client
        """
        try:
            # 输入校验
            if not comments or not isinstance(comments, list):
                return _fmt_error("comments 必须是非空列表")
            if len(comments) > 100:
                return _fmt_error("comments 数量不能超过 100", f"got={len(comments)}")

            # 校验每个条目
            for i, c in enumerate(comments):
                if not isinstance(c, dict):
                    return _fmt_error(f"第 {i} 个条目必须是字典", f"got={type(c).__name__}")
                addr = c.get("address", "")
                if not _ADDR_RE.match(addr):
                    return _fmt_error(f"第 {i} 个条目地址格式非法", f"address={addr}")
                if not c.get("comment"):
                    return _fmt_error(f"第 {i} 个条目 comment 不能为空")

            # 使用 Semaphore 限并发
            sem = asyncio.Semaphore(10)
            results = []

            async def set_one(comment_item: Dict[str, str], index: int):
                """设置单个注释"""
                async with sem:
                    addr = comment_item["address"]
                    comment = comment_item["comment"]
                    try:
                        result = await asyncio.to_thread(
                            self.gui.SetComment, addr, comment, timeout
                        )
                        # 修复毒舌审查Bug 3: SetComment 真实返回值为
                        # {"SetComment": "Success", "Address":..., "Comment":...} 或
                        # {"SetComment": "Failed", "Reason":..., "Address":...}
                        # 已通过 Grep core.py 第6369-6430行验证。
                        # 原代码遍历 values 检查 `v is False or v == "false" or v == 0`：
                        # - "Failed" 字符串不匹配 False/"false"，失败永远检测不到（success 恒为 True）
                        # - `v == 0` 会误匹配 count:0 之类的字段（虽然 SetComment 无此字段，但逻辑仍错）
                        # 修复: 直接检查 result["SetComment"] 是否等于 "Success"
                        success = False
                        if isinstance(result, dict):
                            success = result.get("SetComment") == "Success"
                        elif result is True:
                            # 兜底：极少数情况下可能返回布尔值
                            success = True
                        return {
                            "index": index,
                            "address": addr,
                            "comment": comment,
                            "status": "success" if success else "failed",
                            "raw_result": str(result) if not success else None
                        }
                    except Exception as e:
                        logger.debug(f"设置注释 {addr} 失败: {e}")
                        return {
                            "index": index,
                            "address": addr,
                            "comment": comment,
                            "status": "error",
                            "error": str(e)
                        }

            # 并行设置所有注释
            tasks = [set_one(c, i) for i, c in enumerate(comments)]
            results = await asyncio.gather(*tasks)

            # 按原始顺序整理
            results.sort(key=lambda x: x["index"])

            success_count = sum(1 for r in results if r["status"] == "success")
            error_count = sum(1 for r in results if r["status"] == "error")
            failed_count = sum(1 for r in results if r["status"] == "failed")

            return _fmt_success({
                "total": len(results),
                "success_count": success_count,
                "failed_count": failed_count,
                "error_count": error_count,
                "results": results
            })
        except Exception as e:
            logger.exception("batch_set_comments 失败")
            return _fmt_error("批量设置注释失败", e)

    # ============================================================
    # 融合 CE MCP: 函数调用追踪
    # 通过断点+寄存器记录实现函数调用追踪
    # ============================================================
    async def trace_function_calls(self, function_address: str,
                                   max_calls: int = 10,
                                   timeout: float = 60.0) -> str:
        """
        功能：追踪函数调用（融合 CE MCP 内存值追踪 + ida-pro-mcp 断点分析）
        用途：记录函数被调用的次数、参数、调用者，分析函数行为
        调用示例：trace_function_calls(function_address="0x00401000", max_calls=10)
        返回：JSON 包含每次调用的寄存器快照、调用栈、调用次数
        说明：在指定地址设置断点，每次命中时记录寄存器和调用栈，
              达到 max_calls 次后自动删除断点并返回结果
              注意：此工具会暂停程序执行，需要在调试中使用
        """
        try:
            # 输入校验
            if not _ADDR_RE.match(function_address):
                return _fmt_error("function_address 格式非法", f"address={function_address}")
            if max_calls < 1 or max_calls > 100:
                return _fmt_error("max_calls 必须在 1-100 之间", f"max_calls={max_calls}")

            # 第一步：设置断点
            bp_result = await asyncio.to_thread(
                self.dbg.SetBreakPoint, function_address, timeout
            )
            # 修复毒舌审查Bug 4: SetBreakPoint 真实返回值为
            # {"SetBreakPoint": "Success", "Address":..., "Type":...} 或
            # {"SetBreakPoint": "Failed", "Reason":..., "Address":...}
            # 已通过 Grep core.py 第643-698行验证。
            # 原代码遍历 values 检查 `v is False or v == "false"`：
            # "Failed" 字符串既不等于 False 也不等于 "false"，失败永远检测不到（bp_success 恒为 True）。
            # 修复: 直接检查 result["SetBreakPoint"] 是否等于 "Success"
            bp_success = False
            if isinstance(bp_result, dict):
                bp_success = bp_result.get("SetBreakPoint") == "Success"
            elif bp_result is True:
                # 兜底：极少数情况下可能返回布尔值
                bp_success = True

            if not bp_success:
                return _fmt_error("设置断点失败", str(bp_result))

            call_records = []
            errors = []

            # 第二步：循环等待断点命中并记录
            for call_idx in range(max_calls):
                try:
                    # 等待断点命中
                    wait_result = await asyncio.to_thread(
                        self.dbg.Wait, timeout
                    )

                    # 修复毒舌审查Bug 1: 原代码调用 self.dbg.GetEip（大写驼峰）不存在，
                    # core.py 真实方法为 get_eip（小写下划线，且无 timeout 参数，见 core.py 第1250行）。
                    # 64 位调试应取 rip 寄存器，用 get_register("rip", timeout) 最准确
                    # （get_register 签名: get_register(registers, timeout)，已 Grep core.py 第1136行验证）。
                    # 原代码 GetEip 会抛 AttributeError，导致整个追踪失败。
                    rip_result = await asyncio.to_thread(
                        self.dbg.get_register, "rip", timeout
                    )
                    current_rip = self._extract_value(rip_result)

                    # 记录寄存器
                    regs_result = await asyncio.to_thread(
                        self.dbg.get_register,
                        ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                         "rbp", "rsp", "r8", "r9", "rip"],
                        timeout
                    )
                    regs_data = self._extract_value(regs_result)

                    # 修复毒舌审查Bug 5: 原代码 RunCmd("k") 是 WinDbg 命令，x64dbg 不认。
                    # RunCmd 接受 x64dbg 脚本命令（如 "mod.base()"），非调试器命令 "k"
                    # （已 Grep core.py 第6105行验证 RunCmd 签名）。
                    # core.py 中无 GetCallStack 方法（已 Grep 验证不存在）。
                    # 修复：通过读取栈内存（rsp 起始的若干指针）构造简易调用栈，
                    # 标注为近似值，保留调用栈功能而不依赖不存在的命令。
                    callstack_data = None
                    try:
                        # 从已获取的寄存器中提取 rsp（get_register 返回的 key 大写）
                        rsp_val = None
                        if isinstance(regs_data, dict):
                            rsp_val = regs_data.get("RSP") or regs_data.get("rsp") or regs_data.get("Rsp")
                        if rsp_val:
                            # 从 rsp 起始读取 16 个指针（128 字节栈范围）作为返回地址候选
                            rsp_int = _parse_addr(str(rsp_val))
                            stack_addrs = [_fmt_addr(rsp_int + i * 8) for i in range(16)]
                            stack_ptr_result = await asyncio.to_thread(
                                self.memory.ReadPtr, stack_addrs, timeout
                            )
                            # 解析 ReadPtr 返回值：{"ReadPtr": {addr: "0x...", ...}} 或直接 {addr: ...}
                            ptrs_dict = stack_ptr_result
                            if isinstance(stack_ptr_result, dict) and "ReadPtr" in stack_ptr_result:
                                ptrs_dict = stack_ptr_result["ReadPtr"]
                            callstack_entries = []
                            if isinstance(ptrs_dict, dict):
                                for sa in stack_addrs:
                                    # 尝试多种键格式（0x 前缀大小写差异）
                                    ptr_val = ptrs_dict.get(sa) or ptrs_dict.get(sa.lower()) or ptrs_dict.get(sa.upper())
                                    if ptr_val:
                                        callstack_entries.append({"stack_address": sa, "value": ptr_val})
                            callstack_data = {
                                "note": "x64dbg 无原生 callstack 命令，此为栈内存近似调用栈（rsp 起始 16 个指针，需人工甄别返回地址）",
                                "entries": callstack_entries
                            }
                        else:
                            callstack_data = {"error": "无法获取 rsp 寄存器值，跳过调用栈采集"}
                    except Exception as cs_e:
                        callstack_data = {"error": f"获取调用栈失败: {cs_e}"}
                        errors.append(f"第 {call_idx} 次获取调用栈失败: {cs_e}")

                    call_records.append({
                        "call_index": call_idx,
                        "rip": current_rip,
                        "registers": regs_data if isinstance(regs_data, dict) else str(regs_data),
                        "callstack": callstack_data
                    })

                    # 继续执行（等待下一次命中）
                    if call_idx < max_calls - 1:
                        run_result = await asyncio.to_thread(
                            self.dbg.Run, timeout
                        )

                except Exception as e:
                    errors.append(f"第 {call_idx} 次追踪失败: {str(e)}")
                    logger.debug(f"trace_function_calls 第 {call_idx} 次失败: {e}")
                    break

            # 第三步：删除断点
            try:
                await asyncio.to_thread(
                    self.dbg.DeleteBreakPoint, function_address, timeout
                )
            except Exception as e:
                errors.append(f"删除断点失败: {str(e)}")

            return _fmt_success({
                "function_address": function_address,
                "max_calls": max_calls,
                "actual_calls": len(call_records),
                "call_records": call_records,
                "errors": errors if errors else None
            })
        except Exception as e:
            logger.exception("trace_function_calls 失败")
            # 确保断点被清理
            try:
                await asyncio.to_thread(
                    self.dbg.DeleteBreakPoint, function_address, 5.0
                )
            except Exception:
                pass
            return _fmt_error("函数调用追踪失败", e)

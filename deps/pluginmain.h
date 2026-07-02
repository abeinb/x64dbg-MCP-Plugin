#ifndef _PLUGINMAIN_H
#define _PLUGINMAIN_H

#include "_plugins.h"
#include "_plugin_types.h"
#include "_dbgfunctions.h"
#include "bridgemain.h"
#include "bridgegraph.h"
#include "bridgelist.h"

// Script API 子模块（header.h 和 pluginmain.cpp 中用到的所有 Script:: 命名空间）
#include "_scriptapi.h"
#include "_scriptapi_assembler.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_flag.h"
#include "_scriptapi_function.h"
#include "_scriptapi_gui.h"
#include "_scriptapi_label.h"
#include "_scriptapi_memory.h"
#include "_scriptapi_misc.h"
#include "_scriptapi_module.h"
#include "_scriptapi_register.h"
#include "_scriptapi_stack.h"
#include "_scriptapi_symbol.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_bookmark.h"
#include "_scriptapi_argument.h"
#include "_scriptapi_pattern.h"

// 插件元信息宏定义（必须在 pluginmain.cpp 使用之前定义）
// 原代码将这些宏放在 pluginit 函数内部（第 15029 行），导致第 14944 行使用时未定义
// 此处提前定义，确保所有引用都能正确解析
#ifndef PLUGIN_NAME
#define PLUGIN_NAME "LyScript AI"
#endif
#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION "2.0.0"
#endif
#ifndef PLUGIN_AUTHOR
#define PLUGIN_AUTHOR "RuiWang"
#endif
#ifndef PLUGIN_WEBSITE
#define PLUGIN_WEBSITE "https://github.com/abeinb/x64dbg-MCP-Plugin"
#endif
#ifndef PLUGIN_COMPILE_DATE
#define PLUGIN_COMPILE_DATE __DATE__ " " __TIME__
#endif

#ifdef __cplusplus
extern "C" {
#endif

// x64dbg 插件导出宏
// PLUG_EXPORT 用于声明插件导出函数（pluginit/plugstop/plugsetup）
// 使用 extern "C" 确保 C 链接，避免 C++ 名称修饰导致 x64dbg 找不到导出函数
#ifndef PLUG_EXPORT
#define PLUG_EXPORT extern "C" __declspec(dllexport)
#endif

#ifdef __cplusplus
}
#endif

#endif // _PLUGINMAIN_H

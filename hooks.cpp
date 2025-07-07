#include "hooks.h" 
#include "Minhook.h"
#include <stdio.h>
#include <Luau/lcommon.h>
#include <Luau/lgc.h>
#include <Luau/luacode.h>
#include <iostream>
#include <cassert>
#include <vector>
#include <thread>
struct HookEntry {
    uintptr_t address;
    LPVOID detour;
    LPVOID* original;
};
bool hook(uintptr_t targetAddress, LPVOID detour, LPVOID original)
{
    printf("hooking address: 0x%p\n", (void*)targetAddress);

    MH_STATUS status = MH_CreateHook(
        reinterpret_cast<LPVOID>(targetAddress),
        reinterpret_cast<LPVOID>(detour),
        reinterpret_cast<LPVOID*>(original)
    );

    if (status != MH_OK)
    {
        printf("could not create hook at 0x%p (MH_STATUS: %d)\n", (void*)targetAddress, status);
        MessageBoxA(nullptr, "failed to create hook", "Error", MB_ICONERROR);
        return false;
    }

    status = MH_EnableHook(reinterpret_cast<LPVOID>(targetAddress));
    if (status != MH_OK)
    {
        printf("failed to enable hook at 0x%p (MH_STATUS: %d)\n", (void*)targetAddress, status);
        MessageBoxA(nullptr, "failed to enable hook", "Error", MB_ICONERROR);
        return false;
    }

    printf("hooked address: 0x%p\n", (void*)targetAddress);
    return true;
}

lua_State* __cdecl LuaNewStateDetour(lua_Alloc f, void* ud)
{
    return lua_newstate(f, ud);
}

void __cdecl LuaOpenLibsDetour(lua_State* L)
{
    luaL_openlibs(L);
}

void __cdecl lua51L_newmetatable(lua_State* L, const char* arg2)
{
    luaL_newmetatable(L, arg2);
}

void __cdecl lua51_pushValue(lua_State* L, int arg2)
{
    lua_pushvalue(L, arg2);
}

void __cdecl lua51_setField(lua_State* L, int idx, const char* thing)
{
    lua_setfield(L, idx, thing);
}

void __cdecl lua51L_register(lua_State* L, const char* libName, luaL_Reg* methods)
{
    luaL_register(L, libName, methods);
}

void __cdecl lua51_pushcclosure(lua_State* L, lua_CFunction f, int n)
{
    lua_pushcclosure(L, f, "LuauLayer", n);
}

void __cdecl lua51_pushstring(lua_State* L, const char* st)
{
    lua_pushstring(L, st);
}

void __cdecl lua51_pushboolean(lua_State* L, int b)
{
    lua_pushboolean(L, b);
}

const char* __cdecl lua51L_checklstring(lua_State* L, int num, size_t* t) {
    return luaL_checklstring(L, num, t);
}
void __cdecl lua51L_checkany(lua_State* l, int narg) {
    luaL_checkany(l, narg);
}

int __cdecl lua51L_loadstring(lua_State* L, const char* buff, size_t size, const char* name) {
    std::string source(buff, size);
    size_t bytecodeSize = 0;
    char* bytecode = luau_compile(source.data(), source.length(), nullptr, &bytecodeSize);
    int result = luau_load(L, name, bytecode, bytecodeSize, 0);
    return result;
}

int __cdecl lua51_pcall(lua_State* L, int nargs, int nresults, int errfunc) {
    return lua_pcall(L, nargs, nresults, errfunc);
}

void* __cdecl lua51_newuserdata(lua_State* L, size_t size) {
    return lua_newuserdata(L, size);
}

void __cdecl lua51_pushinteger(lua_State* L, lua_Integer n) {
    lua_pushinteger(L, n);
}

void __cdecl lua51_pushnil(lua_State* L) {
    lua_pushnil(L);
}

void *__cdecl lua51L_checkudata(lua_State* L, int ud, const char* name) {
    return luaL_checkudata(L, ud, name);
}

int __cdecl lua51_setmetatable(lua_State* L, int obj) {
    return lua_setmetatable(L, obj);
}

lua_Integer __cdecl lua51L_checkinteger(lua_State* L, int na) {
    return luaL_checkinteger(L, na);
}

lua_Integer __cdecl lua51L_optinteger(lua_State* L, int n, int def) {
    return luaL_optinteger(L, n, def);
}

void __cdecl lua51_getfield(lua_State* l, int i, const char* k) {
    lua_getfield(l, i, k);
}

void __cdecl lua51_close(lua_State* l) {
    lua_close(l);
}
int __cdecl lua51_rawequal(lua_State* L, int index1, int index2) {
    return lua_rawequal(L, index1, index2);
}

int __cdecl lua51_resume(lua_State* L, int nargs) {
    return lua_resume(L, NULL, nargs);
}

void __cdecl lua51_settable(lua_State* L, int idx) {
    return lua_settable(L, idx);
}

int __fastcall getthreadcount(void* _this) {
    unsigned int count = std::thread::hardware_concurrency();
    return count > 1 ? static_cast<int>(count) : 1;
}
int __cdecl lua51_gc(lua_State* L, int wh, int data) {
    return lua_gc(L, wh, data);
}

void __cdecl lua51c_step(lua_State* L) {
    luaC_step(L, true);
}

lua_State* __cdecl lua51_newthread(lua_State* L) {
    return lua_newthread(L);
}

void __cdecl lua51_gettable(lua_State* L, int idx) {
    lua_gettable(L, idx);
}

bool __cdecl lua51_pushthread(lua_State* L) {
    return lua_pushthread(L);
}

int __cdecl lua51_gettop(lua_State* L) {
    return lua_gettop(L);
}

void __cdecl lua51_settop(lua_State* L, int th) {
    lua_settop(L, th);
}

const char* __cdecl lua51_tolstring(lua_State* l, int idx, size_t* le) {
    return lua_tolstring(l, idx, le);
}

void __cdecl lua51_pushlightuserdata(lua_State* l, void* p) {
    lua_pushlightuserdata(l, p);
}

int __cdecl lua51_rawget(lua_State* L, int index)
{
    return lua_rawget(L, index);
}

int __cdecl lua51_rawgeti(lua_State* L, int idx, int n)
{
    return lua_rawgeti(L, idx, n);
}

int __cdecl lua51_getmetatable(lua_State* L, int objindex) {
    return lua_getmetatable(L, objindex);
}

void __cdecl lua51_insert(lua_State* L, int idx) {
    lua_insert(L, idx);
}
bool __cdecl lua51_toboolean(lua_State* L, int idx) {
    return lua_toboolean(L, idx);
}
const char* __cdecl lua51_typename(lua_State* L, int t) {
    return lua_typename(L, t);
}
const void* __cdecl lua51_topointer(lua_State* L, int idx) {
    return lua_topointer(L, idx);
}

// is this the right way to implem it? i think?
const char* lua51_pushfstring(lua_State* L, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const char* result = lua_pushfstringL(L, fmt, args);
    va_end(args);
    return result;
}

void __cdecl lua51_replace(lua_State* L, int idx) {
    lua_replace(L, idx);
}

const char* __cdecl lua51_getupvalue(lua_State* L, int funcindex, int n_upvalue) {
    return lua_getupvalue(L, funcindex, n_upvalue);
}

const char* __cdecl lua51_setupvalue(lua_State* L, int funcindex, int n_upvalue) {
    return lua_setupvalue(L, funcindex, n_upvalue);
}

void __cdecl lua51_remove(lua_State* L, int index)
{
    lua_remove(L, index);
}

void __cdecl lua51_rawset(lua_State* L, int index)
{
    lua_rawset(L, index);
}

int __cdecl lua51_isnumber(lua_State* L, int index)
{
    return lua_isnumber(L, index);
}

lua_Integer __cdecl lua51_tointeger(lua_State* L, int index)
{
    return lua_tointeger(L, index);
}

lua_CFunction __cdecl lua51_atpanic(lua_State* L, lua_CFunction panicf)
{
    return NULL;
}

int __cdecl lua51_type(lua_State* L, int index)
{
    int type = lua_type(L, index);

    switch (type)
    {
    case LUA_TNIL:            return 0;
    case LUA_TBOOLEAN:        return 1;
    case LUA_TLIGHTUSERDATA:  return 2;
    case LUA_TNUMBER:         return 3;
    case LUA_TVECTOR:
    case LUA_TBUFFER:
        return 0;
    case LUA_TSTRING:         return 4;
    case LUA_TTABLE:          return 5;
    case LUA_TFUNCTION:       return 6;
    case LUA_TUSERDATA:       return 7;
    case LUA_TTHREAD:         return 8;

    default:
        return 0;
    }
}

void __cdecl lua51_call(lua_State* L, int nargs, int nresults)
{
    lua_call(L, nargs, nresults);
}

int __cdecl lua51_open_base(lua_State* L)
{
    int v = luaopen_base(L);
    if (v == 1) {
        lua_pushcclosure(L, luaopen_bit32, "LuauLayer", 0);
        lua_pushstring(L, "bit32");
        lua_call(L, 1, 1);
        lua_pop(L, 1);

        lua_pushcclosure(L, luaopen_utf8, "LuauLayer", 0);
        lua_pushstring(L, "utf8");
        lua_call(L, 1, 0);

        lua_pushcclosure(L, luaopen_buffer, "LuauLayer", 0);
        lua_pushstring(L, "buffer");
        lua_call(L, 1, 0);

        lua_pushcclosure(L, luaopen_debug, "LuauLayer", 0);
        lua_pushstring(L, "debug");
        lua_call(L, 1, 0);
    }
    return v;
}

int lua51L_ref(lua_State* L, int idx)
{
    assert(idx == LUA_REGISTRYINDEX);
    int r = lua_ref(L, -1);
    lua_pop(L, 1);
    return r;
}

void __cdecl lua51L_argerror(lua_State* L, int narg, const char* extramsg) {
    luaL_argerror(L, narg, extramsg);
}

void lua51L_unref(lua_State* L, unsigned int t, int ref)
{
    lua_unref(L, ref);
}

void __cdecl lua51_createtable(lua_State* L, int narray, int nrec) {
    return lua_createtable(L, narray, nrec);
}

void __cdecl lua51_xmove(lua_State* from, lua_State* to, int n)
{
    lua_xmove(from, to, n);
}

void __cdecl lua51_pushlstring(lua_State* L, const char* s, unsigned int len) {
    return lua_pushlstring(L, s, len);
}

void __cdecl lua51_rawseti(lua_State* L, int idx, int n) {
    return lua_rawseti(L, idx, n);
}

void lua51_pushnumber(lua_State* L, long double n)
{
    lua_pushnumber(L, static_cast<double>(n));
}

double lua51_tonumber(lua_State* L, int idx)
{
    return lua_tonumber(L, idx);
}

bool lua51_isstring(lua_State* L, int idx)
{
    return lua_isstring(L, idx);
}

int lua51_touserdata(lua_State* L, int idx)
{
    return reinterpret_cast<int>(lua_touserdata(L, idx));
}

int lua51_lessthan(lua_State* L, int index1, int index2)
{
    return lua_lessthan(L, index1, index2);
}

int lua51_next(lua_State* L, int idx)
{
    return lua_next(L, idx);
}

void lua51_concat(lua_State* L, int n)
{
    lua_concat(L, n);
}

int lua51_objlen(lua_State* L, int idx)
{
    return lua_objlen(L, idx);
}

void __cdecl lua51_getfenv(lua_State* L, int idx)
{
    lua_getfenv(L, idx);
}

int __cdecl lua51_setfenv(lua_State* L, int idx)
{
    return lua_setfenv(L, idx);
}

int __cdecl lua51_yield(lua_State* L, int nresults) {
    return lua_yield(L, nresults);
}

int __cdecl lua51L_getmetafield(lua_State* L, int obj, const char* event)
{
    return luaL_getmetafield(L, obj, event);
}

void __cdecl lua51_error(lua_State* L, int idx)
{
    (void)lua_error(L);
}

int __cdecl lua51open_string(lua_State* L)
{
    return luaopen_string(L);
}

int __cdecl lua51open_table(lua_State* L)
{
    return luaopen_table(L);
}

int __cdecl lua51open_math(lua_State* L)
{
    return luaopen_math(L);
}

int __cdecl lua51open_base(lua_State* L)
{
    return luaopen_base(L);
}

int __cdecl lua51_getinfo(lua_State* L, const char* what, lua_Debug* ar) {
    return lua_getinfo(L, 1, what, ar);
}

int __cdecl lua51_getstack(lua_State* L, int level, lua_Debug* ar51)
{
    return lua_getinfo(L, level, "n", ar51);
}

void __cdecl reportError(lua_State* L)
{
    char handle_buf[16];
    int handle;
    const char* msg = lua_tostring(L, -1);
    if (msg == NULL) {
        msg = "(error object is not a string)";
    }
    handle = *sub_572120(handle_buf);
    sub_571E10(handle, 3, "%s", msg);

    if (!(*(sub_409CD0() + 232))) {
        lua_pop(L, 1);
        return;
    }

    lua_Debug ar;
    int level = 0;
    while (lua_getinfo(L, level, "sln", &ar))
    {
        const char* source = ar.source ? ar.source : "Unknown";
        const char* name = ar.name ? ar.name : "(null)";

        if (level != 0) {
            sub_571E10(handle, 1, "stack %s, line %d: %s", source, ar.currentline, name);
        }

        level++;
    }

    sub_571E10(handle, 1, "stack end");
    lua_pop(L, 1);
}
bool InstallLuaHook()
{
    if (MH_Initialize() != MH_OK) return false;
    AllocConsole();
    FILE* f; freopen_s(&f, "CONIN$", "r", stdin);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONOUT$", "w", stdout);

    static HookEntry hooks[] = {
        {0x5D45F0, (LPVOID)&LuaNewStateDetour,     (LPVOID*)&original_newstate},
        {0x5CA370, (LPVOID)&lua51L_newmetatable,   (LPVOID*)&original_newmetatable},
        {0x5C91A0, (LPVOID)&lua51_pushValue,       (LPVOID*)&original_pushvalue},
        {0x5C9A80, (LPVOID)&lua51_setField,        (LPVOID*)&original_setfield},
        {0x5CB160, (LPVOID)&lua51L_register,       (LPVOID*)&original_register},
        {0x5C9720, (LPVOID)&lua51_pushcclosure,    (LPVOID*)&original_pushcclosure},
        {0x5C9650, (LPVOID)&lua51_pushstring,      (LPVOID*)&original_pushstring},
        {0x5C97C0, (LPVOID)&lua51_pushboolean,     (LPVOID*)&original_pushboolean},
        {0x5CADB0, (LPVOID)&lua51L_checklstring,   (LPVOID*)&original_checklstring},
        {0x5CABB0, (LPVOID)&lua51L_loadstring,     (LPVOID*)&original_loadstring},
        {0x5CA010, (LPVOID)&lua51_newuserdata,     (LPVOID*)&original_newuserdata},
        {0x5C9860, (LPVOID)&lua51_getfield,        (LPVOID*)&original_getfield},
        {0x5CACA0, (LPVOID)&lua51L_checkudata,     (LPVOID*)&original_checkudata},
        {0x5C9BC0, (LPVOID)&lua51_setmetatable,    (LPVOID*)&original_setmetatable},
        {0x5C95F0, (LPVOID)&lua51_pushinteger,     (LPVOID*)&original_pushinteger},
        {0x5C9D50, (LPVOID)&lua51_pcall,           (LPVOID*)&original_pcall},
        {0x5D20D0, (LPVOID)&lua51_resume,          (LPVOID*)&original_resume},
        {0x5C9A50, (LPVOID)&lua51_settable,        (LPVOID*)&original_settable},
        {0x539650, (LPVOID)&getthreadcount,        (LPVOID*)&original_getthreadcount},
        {0x5C9E50, (LPVOID)&lua51_gc,              (LPVOID*)&original_gc},
        {0x6216E0, (LPVOID)&lua51c_step,           (LPVOID*)&originalc_step},
        {0x5CA280, (LPVOID)&lua51_newthread,       (LPVOID*)&original_newthread},
        {0x5C9830, (LPVOID)&lua51_gettable,        (LPVOID*)&original_gettable},
        {0x5C9800, (LPVOID)&lua51_pushthread,      (LPVOID*)&original_pushthread},
        {0x5C8FE0, (LPVOID)&lua51_gettop,          (LPVOID*)&original_gettop},
        {0x5C8FF0, (LPVOID)&lua51_settop,          (LPVOID*)&original_settop},
        {0x5C93E0, (LPVOID)&lua51_tolstring,       (LPVOID*)&original_tolstring},
        {0x5C97E0, (LPVOID)&lua51_pushlightuserdata,(LPVOID*)&original_plud},
        {0x5C98C0, (LPVOID)&lua51_rawget,          (LPVOID*)&original_rawget},
        {0x5C9040, (LPVOID)&lua51_remove,          (LPVOID*)&original_remove},
        {0x5C9AE0, (LPVOID)&lua51_rawset,          (LPVOID*)&original_rawset},
        {0x5C9240, (LPVOID)&lua51_isnumber,        (LPVOID*)&original_isnumber},
        {0x5C9370, (LPVOID)&lua51_tointeger,       (LPVOID*)&original_tointeger},
        {0x5C8FC0, (LPVOID)&lua51_atpanic,         (LPVOID*)&original_atpanic},
        {0x5C91D0, (LPVOID)&lua51_type,            (LPVOID*)&original_type},
        {0x5C9CF0, (LPVOID)&lua51_call,            (LPVOID*)&original_call},
        {0x5D8530, (LPVOID)&lua51_open_base,       (LPVOID*)&original_open_base},
        {0x5C8F70, (LPVOID)&lua51_xmove,           (LPVOID*)&original_xmove},
        {0x5C9900, (LPVOID)&lua51_rawgeti,         (LPVOID*)&original_rawgeti},
        {0x5C9940, (LPVOID)&lua51_createtable,     (LPVOID*)&original_createtable},
        {0x5C9610, (LPVOID)&lua51_pushlstring,     (LPVOID*)&original_pushlstring},
        {0x5C9B50, (LPVOID)&lua51_rawseti,         (LPVOID*)&original_rawseti},
        {0x5C9980, (LPVOID)&lua51_getmetatable,    (LPVOID*)&original_getmetatable},
        {0x5C9090, (LPVOID)&lua51_insert,          (LPVOID*)&original_insert},
        {0x5C90E0, (LPVOID)&lua51_replace,         (LPVOID*)&original_replace},
        {0x5CA7C0, (LPVOID)&lua51L_ref,            (LPVOID*)&originalL_ref},
        {0x5CA870, (LPVOID)&lua51L_unref,          (LPVOID*)&originalL_unref},
        {0x5C95D0, (LPVOID)&lua51_pushnumber,      (LPVOID*)&original_pushnumber},
        {0x5C9330, (LPVOID)&lua51_tonumber,        (LPVOID*)&original_tonumber},
        {0x5C9280, (LPVOID)&lua51_isstring,        (LPVOID*)&original_isstring},
        {0x5C94F0, (LPVOID)&lua51_touserdata,      (LPVOID*)&original_touserdata},
        {0x5C92F0, (LPVOID)&lua51_lessthan,        (LPVOID*)&original_lessthan},
        {0x5C9F50, (LPVOID)&lua51_next,            (LPVOID*)&original_next},
        {0x5C9F90, (LPVOID)&lua51_concat,          (LPVOID*)&original_concat},
        {0x5C9450, (LPVOID)&lua51_objlen,          (LPVOID*)&original_objlen},
        {0x5C99E0, (LPVOID)&lua51_getfenv,         (LPVOID*)&original_getfenv},
        {0x5C9C70, (LPVOID)&lua51_setfenv,         (LPVOID*)&original_setfenv},
        {0x5CA400, (LPVOID)&lua51L_getmetafield,   (LPVOID*)&originalL_getmetafield},
        {0x5C9F40, (LPVOID)&lua51_error,           (LPVOID*)&original_error},
        {0x5D1B90, (LPVOID)&lua51_yield,           (LPVOID*)&original_yield},
        {0x5D73C0, (LPVOID)&lua51open_string,      (LPVOID*)&original_open_string},
        {0x5D57C0, (LPVOID)&lua51open_math,        (LPVOID*)&original_open_math},
        {0x5D5050, (LPVOID)&lua51open_table,       (LPVOID*)&original_open_table},
        {0x5D2E80, (LPVOID)&lua51_getinfo,         (LPVOID*)&original_getinfo},
        {0x5D2310, (LPVOID)&lua51_getstack,        (LPVOID*)&original_getstack},
        {0x53D080, (LPVOID)&reportError,           (LPVOID*)&original_scriptcontextreport},
        {0x5D4560, (LPVOID)&lua51_close,           (LPVOID*)&original_close},
        {0x5C92B0, (LPVOID)&lua51_rawequal,        (LPVOID*)&original_rawequal},
        {0x5C93B0, (LPVOID)&lua51_toboolean,       (LPVOID*)&original_toboolean},
        {0x5C91F0, (LPVOID)&lua51_typename,        (LPVOID*)&original_typename},
        {0x5C96F0, (LPVOID)&lua51_pushfstring,     (LPVOID*)&original_pushfstring},
        {0x5C9540, (LPVOID)&lua51_topointer,       (LPVOID*)&original_topointer},
        {0x5CAD80, (LPVOID)&lua51L_checkany,       (LPVOID*)&originalL_checkany},
        {0x5CABE0, (LPVOID)&lua51L_argerror,       (LPVOID*)&originalL_argerror},
        {0x5C95B0, (LPVOID)&lua51_pushnil,         (LPVOID*)&original_pushnil}
    };

    for (auto& h : hooks)
        hook(h.address, h.detour, h.original);

    return true;
}


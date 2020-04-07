#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>
#include "rc4.h"

#if LUA_VERSION_NUM < 502
# ifndef luaL_newlib
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
# endif
#endif

#define RC4_CLS_NAME "cls{rc4state}"

#define CHECK_RC4OBJ(L, n) (rc4_state_t *)luaL_checkudata(L, n, RC4_CLS_NAME)

static int lua_rc4_new(lua_State *L)
{
    size_t sz;
    const char *key = luaL_checklstring(L, 1, &sz);
    rc4_state_t *s = lua_newuserdata(L, sizeof(*s));
    rc4_init(s, (uint8_t *)key, (int)sz);
    luaL_getmetatable(L, RC4_CLS_NAME);
    lua_setmetatable(L, -2);
    return 1;
}

static int lua_rc4_gc(lua_State *L)
{
    return 0;
}

static int lua_rc4_reset(lua_State *L)
{
    size_t sz;
    rc4_state_t *s = CHECK_RC4OBJ(L, 1);
    const char *key = luaL_checklstring(L, 2, &sz);
    rc4_init(s, (uint8_t *)key, (int)sz);
    return 0;
}

static int lua_rc4_crypt(lua_State *L)
{
    size_t sz;
    rc4_state_t *s = CHECK_RC4OBJ(L, 1);
    const char *data = luaL_checklstring(L, 2, &sz);
    uint8_t *out = (uint8_t *)malloc(sz);
    if (out == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "nomem");
        return 2;
    }
    rc4_crypt(s, (uint8_t *)data, (uint8_t *)out, (int)sz);
    lua_pushlstring(L, (const char *)out, sz);
    free(out);
    return 1;
}

const uint32_t MOD_ADLER = 65521;
uint32_t adler32(uint8_t *data, size_t len) 
{
    uint32_t a = 1, b = 0;
    size_t index;

    for (index = 0; index < len; ++index)
    {
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}

static int lua_rc4_pack(lua_State *L)
{
    size_t sz, out_sz;
    uint32_t sum, sum_high, sum_low;
    uint8_t *ptr, *out;
    rc4_state_t *s = CHECK_RC4OBJ(L, 1);
    const char *data = luaL_checklstring(L, 2, &sz);
    uint16_t idx = luaL_optinteger(L, 3, 0);

    ptr = malloc(sz + 8);
    if (ptr == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "lack of memory");
        return 2;
    }

    out_sz = sz + 6;
    ptr[0] = out_sz / 256;
    ptr[1] = out_sz % 256;

    out = ptr + 2;
    /*msg(N) + sum(4) + idx(2) */
    rc4_crypt(s, (uint8_t *)data, out, sz);
    sum = adler32(out, sz);
    sum_high = sum / 65536;
    sum_low = sum % 65536;

    out[sz + 0] = sum_high / 256;
    out[sz + 1] = sum_high % 256;
    out[sz + 2] = sum_low / 256;
    out[sz + 3] = sum_low % 256;
    out[sz + 4] = idx / 256;
    out[sz + 5] = idx % 256;

    lua_pushlstring(L, (const char *)ptr, sz + 8);
    free(ptr);

    return 1;
}

static int index_check(uint8_t *data, size_t sz, uint16_t check_idx)
{
    uint16_t idx;
    idx = ((uint16_t)data[sz - 2]) << 8 | ((uint16_t)data[sz - 1]);
    if (check_idx > 0 && check_idx != idx) {
        return 0;
    }
    return 1;
}

static int adler32_check(uint8_t *data, size_t sz)
{
    uint32_t sum, ori_sum;
    sum = adler32(data, sz - 6);
    ori_sum = ((uint32_t)data[sz - 6]) << 24 | ((uint32_t)data[sz - 5]) << 16 | ((uint32_t)data[sz - 4]) << 8 | ((uint32_t)data[sz - 3]);
    return sum == ori_sum ? 1 : 0;
}

static int lua_rc4_unpack(lua_State *L)
{
    size_t sz, out_len;
    rc4_state_t *s = CHECK_RC4OBJ(L, 1);
    uint8_t *data = (uint8_t *)luaL_checklstring(L, 2, &sz);
    uint16_t check_idx = (uint16_t)luaL_optinteger(L, 3, 0);

    if (!index_check(data, sz, check_idx)) {
        lua_pushnil(L);
        lua_pushstring(L, "idx not match");
        return  2;
    }

    out_len = sz - 6;
    if (!adler32_check(data, sz)) {
        lua_pushnil(L);
        lua_pushstring(L, "sum not match");
        return  2;
    }

    uint8_t *out = (uint8_t *)malloc(out_len);

    rc4_crypt(s, data, out, out_len);

    lua_pushlstring(L, (const char*) out, out_len);
    free(out);

    return 1;
}

static int lua_xor_pack(lua_State *L)
{
    size_t sz;
    uint8_t *ptr, *out;
    const char *data = luaL_checklstring(L, 1, &sz);
    uint8_t key = (uint8_t)luaL_checkinteger(L, 2);

    if (sz > 65534) {
        lua_pushnil(L);
        lua_pushstring(L, "data size is bigger than 64K");
        return 2;
    }
    ptr = (uint8_t *)malloc(sz + 2);
    if (!ptr) {
        lua_pushnil(L) ;
        lua_pushstring(L, "lack of memory");
        return 2;
    }

    ptr[0] = sz / 256;
    ptr[1] = sz % 256;

    out = ptr + 2;
    for (int i = 0; i < sz; i++) {
        out[i] = data[i] ^ key;
    }

    lua_pushlstring(L, (const char *)ptr, sz + 2);
    free(ptr);

    return 1;
}

static int lua_xor_unpack(lua_State *L)
{
    size_t sz, out_sz;
    uint8_t *out;
    uint8_t *data = (uint8_t *)luaL_checklstring(L, 1, &sz);
    uint8_t key = (uint8_t)luaL_checkinteger(L, 2);
    int start_idx = luaL_optinteger(L, 3, 0);

    if (start_idx < 0 || start_idx + 2 >= sz) {
        lua_pushnil(L);
        lua_pushstring(L, "start index error");
        return 2;
    }

    data += start_idx;

    out_sz = ((uint8_t)data[0]) << 8 | (uint8_t)data[1];
    out = (uint8_t *)malloc(out_sz);

    data += 2;

    for (int i = 0; i < out_sz; i++) {
        out[i] = data[i] ^ key;
    }

    lua_pushlstring(L, (const char *)out, out_sz);
    free(out);

    return 1;
}

LUAMOD_API int
luaopen_lrc4(lua_State* L)
{
    luaL_Reg lmethods[] = {
        {"reset",             lua_rc4_reset},
        {"crypt",             lua_rc4_crypt},
        {"pack",              lua_rc4_pack},
        {"unpack",            lua_rc4_unpack},
        {NULL, NULL},
    };
    luaL_newmetatable(L, RC4_CLS_NAME);
    luaL_newlib(L, lmethods);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, lua_rc4_gc);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);

    luaL_Reg lfuncs[] = {
        {"new",      lua_rc4_new},
        {"xor_pack", lua_xor_pack},
        {"xor_unpack", lua_xor_unpack},
        {NULL, NULL},
    };
    luaL_newlib(L, lfuncs);
    return 1;
}

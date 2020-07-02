#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <ctype.h>
#include <sys/time.h>
#include <stdint.h>
#include <assert.h>
#include "bresenham.h"

#if LUA_VERSION_NUM < 502 && (!defined(luaL_newlib))
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#endif

struct bh_udata {
        lua_State *L; 
        int idx;
        int ref;
        size_t max;
};

static void init_bh_udata(struct bh_udata *udata,
                          lua_State *L, 
                          int max, int ref)
{
        udata->L = L;
        udata->max = max;
        udata->ref = ref;
        udata->idx = -1; 
}

static int pushpos2lua(void *data, int x, int y)
{
        struct bh_udata *udata = (struct bh_udata *)data;
        lua_State *L = udata->L;
        if (udata->max > 0 && udata->idx + 1 > udata->max) {
                return BH_STOP;
        }   
        if (udata->ref != LUA_NOREF) {
                int top = lua_gettop(L);
                lua_rawgeti(L, LUA_REGISTRYINDEX, udata->ref);
                lua_pushnumber(L, x);
                lua_pushnumber(L, y);
                if (lua_pcall(L, 2, 1, 0) == 0) {
                        if (!lua_toboolean(L, -1)) {
                                lua_settop(L, top);
                                return BH_STOP;
                        }
                } else {
                        return BH_STOP;
                }
                lua_settop(L, top);
        }
        udata->idx++;

        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)x);
        lua_rawseti(L, -2, 1);
        lua_pushinteger(L, (lua_Integer)y);
        lua_rawseti(L, -2, 2);
        lua_rawseti(L, -2, udata->idx + 1);

        return BH_CONTINUE;
}

static int lua__bresenham(lua_State *L)
{
        int ret;
        struct bh_udata udata;
        int ref = LUA_NOREF;
        int sx = luaL_checkinteger(L, 1);
        int sy = luaL_checkinteger(L, 2);
        int ex = luaL_checkinteger(L, 3);
        int ey = luaL_checkinteger(L, 4);
        int max = luaL_optinteger(L, 5, -1);
        if (lua_type(L, 6) == LUA_TFUNCTION) {
                ref = luaL_ref(L, LUA_REGISTRYINDEX);
        }
        init_bh_udata(&udata, L, max, ref);
        lua_newtable(L);
        ret = bresenham_line(sx, sy, ex, ey, pushpos2lua, &udata);
        lua_pushboolean(L, ret == 0);
        if (ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, ref);
        }
        return 2;
}



static inline void itimeofday(long *sec, long *usec)
{
#if defined(WIN32) || defined(_WIN32)
# define IINT64 __int64;
	static long mode = 0, addsec = 0;
	BOOL retval;
	static IINT64 freq = 1;
	IINT64 qpc;
	if (mode == 0) {
		retval = QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
		freq = (freq == 0)? 1 : freq;
		retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
		addsec = (long)time(NULL);
		addsec = addsec - (long)((qpc / freq) & 0x7fffffff);
		mode = 1;
	}   
	retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
	retval = retval * 2;
	if (sec) *sec = (long)(qpc / freq) + addsec;
	if (usec) *usec = (long)((qpc % freq) * 1000000 / freq);
#else
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
#endif
}

static int lua__gettimeofday(lua_State *L)
{
	long sec;
	long usec;
	itimeofday(&sec, &usec);
	lua_pushnumber(L, (lua_Number)sec);
	lua_pushnumber(L, (lua_Number)usec);
	return 2;
}

static unsigned short checksum(const char *str, int count)
{
	/**
	 * Compute Internet Checksum for "count" bytes
	 * beginning at location "addr".
	 */
	register long sum = 0;
	char *addr = (char *)str;

	while( count > 1 )  {
		/*  This is the inner loop */
		sum += * (unsigned short *) addr++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if( count > 0 )
		sum += * (unsigned char *) addr;

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static int lua__checksum(lua_State *L)
{
	size_t sz;
	const char *str = luaL_checklstring(L, 1, &sz);
	unsigned short csum = checksum(str, sz);
	lua_pushinteger(L, (lua_Integer)csum);
	return 1;
}

static int lua__assertf(lua_State *L)
{
	int top = lua_gettop(L);
	if (lua_toboolean(L, 1))  /* condition is true? */
		return lua_gettop(L);
	luaL_checkany(L, 1);  /* there must be a condition */
	lua_remove(L, 1);  /* remove it */
	if (top <= 2) {
		lua_pushliteral(L, "assertion failed!");  /* default message */
		lua_settop(L, 1);  /* leave only message (default if no other one) */
		return lua_error(L);  /* call 'error' */
	}
	luaL_checkstring(L, 1);
	lua_getglobal(L, "string");
	lua_getfield(L, -1, "format");
	lua_insert(L, 1);
	lua_settop(L, top);
        if (lua_pcall(L, top - 1, 1, 0) == 0)
		return lua_error(L);
	return luaL_error(L, "assertion failed!");
}

/*************************************************************************/
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *misc_base64_encode(const char *data, size_t input_length, size_t *output_length) {

	char *encoded_data = 0;
	int i, j;

	uint32_t octet_a;
	uint32_t octet_b;
	uint32_t octet_c;
	uint32_t triple;

	*output_length = 4 * ((input_length + 2) / 3);

	encoded_data = malloc(*output_length);
	if (encoded_data == NULL) return NULL;

	for (i = 0, j = 0; i < input_length;) {

		octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	return encoded_data;
}


void build_decoding_table() {
	int i;
	decoding_table = malloc(256);
	for (i = 0; i < 64; i++)
		decoding_table[(unsigned char) encoding_table[i]] = i;
}


unsigned char *misc_base64_decode(const char *data, size_t input_length, size_t *output_length) {

	int i , j;
	unsigned char *decoded_data = 0;
	uint32_t sextet_a;
	uint32_t sextet_b;
	uint32_t sextet_c;
	uint32_t sextet_d;
	uint32_t triple;

	if (decoding_table == NULL) build_decoding_table();

	if (input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (*output_length)--;
	if (data[input_length - 2] == '=') (*output_length)--;

	decoded_data = malloc(*output_length);
	if (decoded_data == NULL) return NULL;

	for (i = 0, j = 0; i < input_length;) {

		sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
		sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
		sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
		sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];

		triple = (sextet_a << 3 * 6)
		+ (sextet_b << 2 * 6)
		+ (sextet_c << 1 * 6)
		+ (sextet_d << 0 * 6);

		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}

static int lua__base64_encode(lua_State *L)
{
	size_t in_len =  0;
	size_t out_len = 0;
	const char * inStr = (const char * ) luaL_checklstring(L, 1, &in_len);
	char * out = misc_base64_encode(inStr, in_len, &out_len);
	if(0 == out)
	{
		return 0;
	}
	lua_pushlstring(L, (char*)out, out_len);
	free(out);
	return 1;
}

static int lua__base64_decode(lua_State *L)
{
	size_t in_len =  0;
	size_t i = 0;
	size_t out_len = 0;
	char c;
	const char *  inStr =  (const char * )luaL_checklstring(L, 1, &in_len);
	unsigned char * out;
	if(in_len == 0)
	{
		return luaL_argerror(L, 1, "bad input string,len=0");
	}

	for(i = 0; i < in_len; ++i)
	{
		c = inStr[i];
		if( !  (isalnum(c) || (c == '+') || (c == '/') || (c == '=')) )
			return luaL_argerror(L, 1, "non base64 str");
	}

	out = misc_base64_decode(inStr, in_len, &out_len);
	if(0 == out)
	{
		return 0;
	}
	lua_pushlstring(L, (char*)out, out_len);
	free(out);
	return 1;
}

int luaopen_misc(lua_State* L)
{
	luaL_Reg lfuncs[] = {
		{"assertf", lua__assertf},
		{"checksum", lua__checksum},
		{"gettimeofday", lua__gettimeofday},
		{"bresenham", lua__bresenham},
		{"base64_encode", lua__base64_encode},
		{"base64_decode", lua__base64_decode},
		{NULL, NULL},
	};
	lua_pop(L, 1);
	luaL_newlib(L, lfuncs);
	return 1;
}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>

#if (LUA_VERSION_NUM < 502 && !defined(luaL_newlib))
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#endif


#define LCS_HEAP "lheap{C11F59FA-D8F8-455E-8786-7734A288D2B2}"

typedef lua_Integer KeyT;
typedef lua_Number ValueT;

static int heap_minPriorComapre(ValueT a, ValueT b)
{
	return a < b ? 1 : 0;
}

static int heap_maxPriorComapre(ValueT a, ValueT b)
{
	return a > b ? 1 : 0;
}

typedef int (*PriorComapreFuncT)(ValueT a, ValueT b);

typedef struct SHeap
{
	int Len;
	int MaxLen;
	ValueT * pValueArray;
	KeyT * pKeyArray;
	PriorComapreFuncT pPriorFunc;
}SHeap;

static void heap_swapHeapNode(SHeap * pHeap, int pos1, int pos2)
{
	ValueT v;
	KeyT k;
	v = pHeap->pValueArray[pos1];
	pHeap->pValueArray[pos1] = pHeap->pValueArray[pos2];
	pHeap->pValueArray[pos2] = v;
	
	k = pHeap->pKeyArray[pos1];
	pHeap->pKeyArray[pos1] = pHeap->pKeyArray[pos2];
	pHeap->pKeyArray[pos2] = k;
}

static void heap_Swim(SHeap * pHeap,int pos)
{
	int parent = pos / 2;
	ValueT * arr = pHeap->pValueArray;
	while(parent != 0)
	{
		if( pHeap->pPriorFunc(arr[pos], arr[parent]) )
		{
			heap_swapHeapNode(pHeap, pos, parent);
			pos = parent;
			parent = pos / 2;
		}
		else
		{
			break;
		}
	}
}

static void heap_Sink(SHeap * pHeap,int pos)
{
	int prior_child = pos * 2;
	ValueT * arr = pHeap->pValueArray;
	while (prior_child <= pHeap->Len) {
		if (prior_child + 1 <= pHeap->Len && pHeap->pPriorFunc(arr[prior_child + 1], arr[prior_child]))
		{
			prior_child += 1;
		}
		
		if (pHeap->pPriorFunc(arr[prior_child], arr[pos])) {
			heap_swapHeapNode(pHeap, prior_child, pos);
			pos = prior_child;
			prior_child = pos * 2;
		}
		else {
			break;
		}
	}
}


#define CHECK_HEAP(L, idx) (*(SHeap **)luaL_checkudata(L, idx, LCS_HEAP))

static int lua__lheap_new(lua_State *L)
{
	SHeap **p;

	int maxLen = (int)luaL_optnumber(L, 1, 2048);
	int isMaxPrior = (int)luaL_optnumber(L, 2, 0);

	SHeap * pRet = (SHeap *)malloc(sizeof(SHeap));
	if (pRet == NULL) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, "alloc heap failed");
		return 2;
	}
	pRet->Len = 0;
	pRet->MaxLen = maxLen;
	pRet->pPriorFunc = isMaxPrior != 0 ? heap_maxPriorComapre : heap_minPriorComapre;
	pRet->pValueArray = (ValueT *) malloc( (1+maxLen) * sizeof(ValueT));
	pRet->pKeyArray = (KeyT *) malloc( (1+maxLen) * sizeof(KeyT));

	if (!pRet->pValueArray || !pRet->pKeyArray) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, "alloc heap valArray or keyArray Failed");
		return 2;
	}

	p = lua_newuserdata(L, sizeof(void *));
	*p = pRet;
	luaL_getmetatable(L, LCS_HEAP);
	lua_setmetatable(L, -2);
	return 1;
}

static int lua__lheap_push(lua_State *L)
{
	SHeap * pHeap = CHECK_HEAP(L, 1);

	#if LUA_VERSION_NUM >= 503 /* Lua 5.3 */
		KeyT key = (KeyT)luaL_checknumber(L, 2);
	#else
		KeyT key = (KeyT)luaL_checkinteger(L, 2);
	#endif
	ValueT value = (ValueT)luaL_checknumber(L, 3);
	int idx;
	
	if(pHeap->Len >= pHeap->MaxLen)
	{
		pHeap->MaxLen= pHeap->MaxLen * 2;
		pHeap->pValueArray = (ValueT*) realloc(pHeap->pValueArray, (pHeap->MaxLen + 1) * sizeof(ValueT));
		pHeap->pKeyArray = (KeyT*) realloc(pHeap->pKeyArray, (pHeap->MaxLen + 1) * sizeof(KeyT));
	}
	pHeap->Len++;
	idx = pHeap->Len;
	pHeap->pValueArray[idx] = value;
	pHeap->pKeyArray[idx] = key;
	heap_Swim(pHeap, idx);
	return 0;
}

static int lua__lheap_top(lua_State *L)
{
	SHeap * pHeap = CHECK_HEAP(L, 1);
	if(pHeap->Len <= 0)
	{
		return 0;
	}

	lua_pushinteger(L, pHeap->pKeyArray[1]);
	lua_pushnumber(L, pHeap->pValueArray[1]);
	return 2;
}

static int lua__lheap_len(lua_State *L)
{
	SHeap * pHeap = CHECK_HEAP(L, 1);
	lua_pushinteger(L, pHeap->Len);
	return 1;
}

static void heap_pop(SHeap *pHeap, int idx)
{
	heap_swapHeapNode(pHeap, idx, pHeap->Len);
	pHeap->Len --;
	heap_Sink(pHeap, idx);
}

static int lua__lheap_pop(lua_State *L)
{
	SHeap * pHeap = CHECK_HEAP(L, 1);
	if(pHeap->Len <= 0)
	{
		return luaL_error(L, "try pop from empty heap");
	}

	heap_pop(pHeap, 1);
	return 0;
}

static int lua__lheap_popbykey(lua_State *L)
{
	int idx = 0;
	int i;
	ValueT value;
	SHeap * pHeap = CHECK_HEAP(L, 1);
	#if LUA_VERSION_NUM >= 503 /* Lua 5.3 */
		KeyT key = (KeyT)luaL_checknumber(L, 2);
	#else
		KeyT key = (KeyT)luaL_checkinteger(L, 2);
	#endif
	if(pHeap->Len < 0)
	{
		return luaL_error(L, "try pop from empty heap");
	}

	for(i = 1;i<=pHeap->Len;++i)
	{
		if(pHeap->pKeyArray[i] == key)
		{
			value = pHeap->pValueArray[i];
			idx = i;
			break;
		}
	}
	if(idx == 0)
	{
		return 0;
	}

	heap_pop(pHeap, idx);
	lua_pushnumber(L, value);
	return 1;
}

static int lua__lheap_gc(lua_State *L)
{
	SHeap * pHeap = CHECK_HEAP(L, 1);
	if (pHeap != NULL)
	{
		if(pHeap->pKeyArray)
			free(pHeap->pKeyArray);
		if(pHeap->pValueArray)
			free(pHeap->pValueArray);
		free(pHeap);
	}
	return 0;
}

static int opencls__heap(lua_State *L)
{
	luaL_Reg lmethods[] = {
		{"push", lua__lheap_push},
		{"top", lua__lheap_top},
		{"len", lua__lheap_len },
		{"pop", lua__lheap_pop},
		{"popbykey", lua__lheap_popbykey},
		{NULL, NULL},
	};
	luaL_newmetatable(L, LCS_HEAP);
	luaL_newlib(L, lmethods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction (L, lua__lheap_gc);
	lua_setfield (L, -2, "__gc");

	return 1;
}

int luaopen_lheap(lua_State* L)
{
	luaL_Reg lfuncs[] = {
		{"new", lua__lheap_new},
		{NULL, NULL},
	};

	opencls__heap(L);
	luaL_newlib(L, lfuncs);
	return 1;
}


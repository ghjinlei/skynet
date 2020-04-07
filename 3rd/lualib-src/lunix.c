#include <unistd.h>
#include <signal.h>
#include <sys/utsname.h>  /* uname(2) */
#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysctl.h>

#include <lua.h>
#include <lauxlib.h>

#if (defined(WIN32) || defined(_WIN32))
#elif (defined(__linux__) || defined(__linux) || defined(linux) || defined(__gnu_linux__))
# define PLATFORM_LINUX
# include <sys/prctl.h>
#elif (defined(__APPLE__) || defined(__apple__))
# define PLATFORM_APPLE
#elif (defined(__FreeBSD__))
# define PLATFORM_FREE_BSD
#endif /* endif for platform  */

#if LUA_VERSION_NUM < 502 && (!defined(luaL_newlib))
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#endif

#define UNIX_CONST(x) { #x, x }

struct unix_const {
        const char *name;
        int value;
};

static struct unix_const const_signal[] = {
        UNIX_CONST(SIGABRT), UNIX_CONST(SIGALRM), UNIX_CONST(SIGBUS),
        UNIX_CONST(SIGCHLD), UNIX_CONST(SIGCONT), UNIX_CONST(SIGFPE),
        UNIX_CONST(SIGHUP), UNIX_CONST(SIGILL), UNIX_CONST(SIGINT),
        UNIX_CONST(SIGKILL), UNIX_CONST(SIGPIPE), UNIX_CONST(SIGQUIT),
        UNIX_CONST(SIGSEGV), UNIX_CONST(SIGSTOP), UNIX_CONST(SIGTERM),
        UNIX_CONST(SIGTSTP), UNIX_CONST(SIGTTIN), UNIX_CONST(SIGTTOU),
        UNIX_CONST(SIGUSR1), UNIX_CONST(SIGUSR2), UNIX_CONST(SIGTRAP),
        UNIX_CONST(SIGURG), UNIX_CONST(SIGXCPU), UNIX_CONST(SIGXFSZ),

#if 0
        UNIX_CONST(NSIG),

        UNIX_CONST(SIG_BLOCK), UNIX_CONST(SIG_UNBLOCK), UNIX_CONST(SIG_SETMASK),

        UNIX_CONST(SA_NOCLDSTOP), UNIX_CONST(SA_ONSTACK), UNIX_CONST(SA_RESETHAND),
        UNIX_CONST(SA_RESTART), UNIX_CONST(SA_NOCLDWAIT), UNIX_CONST(SA_NODEFER),
#if defined SA_SIGINFO
        UNIX_CONST(SA_SIGINFO),
#endif
#endif
}; /* const_signal[] */

static int lua_uname(lua_State *L)
{
        struct utsname name;

        if (-1 == uname(&name))
                return luaL_error(L, "cannot use uname");

        if (lua_isnoneornil(L, 1)) {
                lua_createtable(L, 0, 5);

                lua_pushstring(L, name.sysname);
                lua_setfield(L, -2, "sysname");

                lua_pushstring(L, name.nodename);
                lua_setfield(L, -2, "nodename");

                lua_pushstring(L, name.release);
                lua_setfield(L, -2, "release");

                lua_pushstring(L, name.version);
                lua_setfield(L, -2, "version");

                lua_pushstring(L, name.machine);
                lua_setfield(L, -2, "machine");

                return 1;
        } else {
                static const char *opts[] = {
                        "sysname", "nodename", "release", "version", "machine", NULL
                };
                int i, n = 0, top = lua_gettop(L);

                for (i = 1; i <= top; i++) {
                        switch (luaL_checkoption(L, i, NULL, opts)) {
                        case 0:
                                lua_pushstring(L, name.sysname);
                                ++n;

                                break;
                        case 1:
                                lua_pushstring(L, name.nodename);
                                ++n;

                                break;
                        case 2:
                                lua_pushstring(L, name.release);
                                ++n;

                                break;
                        case 3:
                                lua_pushstring(L, name.version);
                                ++n;

                                break;
                        case 4:
                                lua_pushstring(L, name.machine);
                                ++n;

                                break;
                        }
                }

                return n;
        }
}

static int register_const(lua_State *L, int idx, const char *name, struct unix_const *array, size_t size)
{
    int i;
    lua_pushvalue(L, idx);
    lua_newtable(L);
    for (i = 0; i < size; i++) {
            lua_pushstring(L, array[i].name);
            lua_pushinteger(L, array[i].value);
            lua_settable(L, -3);
            /* code */
    }
    lua_setfield(L, -2, name);
    lua_pop(L, 1);
    return 0;
}

static int lua_getpid(lua_State *L)
{
	lua_pushinteger(L, (lua_Integer)getpid());
	return 1;
}

static int lua_getppid(lua_State *L)
{
	lua_pushinteger(L, (lua_Integer)getppid());
	return 1;
}

static int lua_set_process_title(lua_State *L)
{
	const char *title = luaL_checkstring(L, 1);
	int ret = 0;
	(void)title;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_APPLE))
# if defined(PR_SET_NAME)
	ret = prctl(PR_SET_NAME, title);  /* Only copies first 16 characters. */
	if (ret != 0) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, strerror(errno));
		return 2;
	}
# endif
#elif (defined(PLATFORM_FREE_BSD))
	int oid[4];
	static char process_title[64];
	snprintf(process_title, sizeof(process_title), "%s", title);

	oid[0] = CTL_KERN;
	oid[1] = KERN_PROC;
	oid[2] = KERN_PROC_ARGS;
	oid[3] = getpid();

	ret = sysctl(oid, sizeof(oid)/sizeof(oid[0]), NULL, NULL, process_title, strlen(process_title) + 1);
#endif
	lua_pushboolean(L, ret == 0);
	return 1;
}

static int lua_sleep(lua_State *L)
{
	double t = luaL_checknumber(L, 1);
	usleep(t * 1e6);
	return 0;
}

int luaopen_lunix(lua_State* L)
{
    luaL_Reg lfuncs[] = {
        {"sleep", lua_sleep},
        {"uname", lua_uname},
        {"getpid", lua_getpid},
        {"getppid", lua_getppid},
        {"set_process_title", lua_set_process_title},
        {NULL, NULL},
    };
    luaL_newlib(L, lfuncs);
    register_const(L,
       -1,
       "SIGNALS",
       const_signal,
       sizeof(const_signal)/sizeof(const_signal[0]));

    return 1;
}

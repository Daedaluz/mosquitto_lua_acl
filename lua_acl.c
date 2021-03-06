#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <stdlib.h>

#include "lua_acl.h"
#if USE_SHIPPED_LUA
#warning "USING SHIPPED LUA"
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"
#else
#warning "USING SYSTEM LUA"
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#endif
static struct lua_State* lstate = NULL;

static char* get_auth_opt(const char* name, struct mosquitto_auth_opt* opts, int nopts) {
	int i = 0;
	for(i = 0; i < nopts; i++) {
		struct mosquitto_auth_opt* tmp = opts+i;
		if (strcmp(tmp->key, name) == 0) {
			return tmp->value;
		}
	}
	return NULL;
}

int mosquitto_auth_plugin_version() {
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void** udataptr, struct mosquitto_auth_opt* opts, int nopts) {
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void* udata, struct mosquitto_auth_opt* opts, int nopts) {
	return MOSQ_ERR_SUCCESS;
}

int mosq_match(const char* sub, const char* topic) {
	bool res = 0;
	mosquitto_topic_matches_sub(sub, topic, &res);
	return res;
}

int lua_mosq_match(lua_State* l) {
	int res = 0;
	const char* topic = lua_tostring(l, -1);
	const char* subscription = lua_tostring(l, -2);
	res = mosq_match(subscription, topic);
	lua_pop(l, 2);
	lua_pushboolean(l, res);
	return 1;
}

int lua_mosq_log(lua_State* l) {
	const char* msg = lua_tostring(l, -1);
//	printf("%s\n", msg);
	mosquitto_log_printf(MOSQ_LOG_INFO, msg);
	return 0;
}

int mosquitto_auth_security_init(void* udata, struct mosquitto_auth_opt* opts, int nopts, bool reload) {
	const char* script_file = get_auth_opt("scriptfile", opts, nopts);
	if (script_file == NULL) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "%s", "this module need a target script to run, try set the auth_opt_scriptfile to a LUA-script");
		//printf("%s\n", "this module need a target script to run, try set the auth_opt_scriptfile to a LUA-script");
		return MOSQ_ERR_UNKNOWN;
	}
	
	lstate = luaL_newstate();
	if(lstate == NULL) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "luaL_newstate() failed\n");
		//printf("%s\n", "luaL_newstate() failed");
		return MOSQ_ERR_UNKNOWN;
	}
	luaL_openlibs(lstate);
	
	lua_pushcfunction(lstate, lua_mosq_match);
	lua_setglobal(lstate, "match");
	lua_pushcfunction(lstate, lua_mosq_log);
	lua_setglobal(lstate, "log");

	lua_pushinteger(lstate, MOSQ_ACL_WRITE);
	lua_setglobal(lstate, "acl_write");
	lua_pushinteger(lstate, MOSQ_ACL_READ);
	lua_setglobal(lstate, "acl_read");

	lua_newtable(lstate);
	int top = lua_gettop(lstate);
	int i = 0;
	for(i = 0; i < nopts; i++) {
		struct mosquitto_auth_opt* tmp = opts+i;
		lua_pushstring(lstate, tmp->key);
		lua_pushstring(lstate, tmp->value);
		lua_settable(lstate, top);
	}
	lua_setglobal(lstate, "opt");


	if(luaL_loadfile(lstate, script_file) != 0) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Lua couldn't load file %s", lua_tostring(lstate, -1));
		//printf("Lua couldn't load file %s\n", lua_tostring(lstate, -1));
		return MOSQ_ERR_UNKNOWN;
	}
	if(lua_pcall(lstate, 0, LUA_MULTRET, 0) != 0) {
		const char* emsg = lua_tostring(lstate, -1);
		mosquitto_log_printf(MOSQ_LOG_ERR, "error doing file: %s", emsg);
		//printf("error doing file: %s\n", emsg);
		lua_pop(lstate, 1);
		return MOSQ_ERR_UNKNOWN;
	}

	lua_getglobal(lstate, "security_init");
	if(!lua_isfunction(lstate, -1)) {
		lua_pop(lstate, 1);
	} else {
		lua_pushboolean(lstate, reload);
		if(lua_pcall(lstate, 1, 0, 0) != 0) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "security_init failed: %s", lua_tostring(lstate, -1));
			//printf("security_init failed: %s\n", lua_tostring(lstate, -1));
			lua_pop(lstate, 1);
			return MOSQ_ERR_UNKNOWN;
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void* udata, struct mosquitto_auth_opt* opts, int nopts, bool reload) {
	lua_getglobal(lstate, "security_cleanup");
	if(lua_isfunction(lstate, -1)) {
		lua_pushboolean(lstate, reload);
		if(lua_pcall(lstate, 1, 0, 0) != 0) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "security_cleanup failed: %s", lua_tostring(lstate, -1));
			//printf("security_cleanup failed: %s\n", lua_tostring(lstate, -1));
			lua_pop(lstate, 1);
			//what to do?!
		}
	} else {
		lua_pop(lstate, 1);
	}
	if(lstate){
		lua_close(lstate);
		lstate = 0;
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void* udata, const char* id, const char* username, const char* topic, int access) {
	lua_getglobal(lstate, "acl_check");
	if(!lua_isfunction(lstate, -1)) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "acl_check not defined!");
		//printf("acl_check not defined!\n");
		lua_pop(lstate, 1);
		return MOSQ_ERR_ACL_DENIED;
	}
	lua_pushstring(lstate, id);
	if(username){
		lua_pushstring(lstate, username);
	} else {
		lua_pushnil(lstate);
	}
	lua_pushstring(lstate, topic);
	lua_pushinteger(lstate, access);
	if(lua_pcall(lstate, 4, 1, 0) != 0) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "acl_check failed: %s", lua_tostring(lstate, -1));
		//printf("acl_check failed: %s\n", lua_tostring(lstate, -1));
		lua_pop(lstate, 1);
		return MOSQ_ERR_ACL_DENIED;
	}
	int test = lua_toboolean(lstate, -1);
	lua_pop(lstate, 1);
	if(test) {
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_ACL_DENIED;
}

int mosquitto_auth_unpwd_check(void* udata, const char* uname, const char* pwd) {
	lua_getglobal(lstate, "unpwd_check");
	if(!lua_isfunction(lstate, -1)) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "unpwd_check not defined!");
		//printf("unpwd_check not defined!\n");
		lua_pop(lstate, 1);
		return MOSQ_ERR_AUTH;
	}
	if(uname){
		lua_pushstring(lstate, uname);
	} else {
		lua_pushnil(lstate);
	}
	if(pwd) {
		lua_pushstring(lstate, pwd);
	} else {
		lua_pushnil(lstate); 
	}

	if(lua_pcall(lstate, 2, 1, 0) != 0) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "unpwd_check failed: %s", lua_tostring(lstate, -1));
		//printf("unpwd_check failed: %s\n", lua_tostring(lstate, -1));
		lua_pop(lstate, 1);
		return MOSQ_ERR_AUTH;
	}

	int test = lua_toboolean(lstate, -1);
	lua_pop(lstate, 1);
	if(test) {
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_AUTH;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len){
	return MOSQ_ERR_SUCCESS;
}



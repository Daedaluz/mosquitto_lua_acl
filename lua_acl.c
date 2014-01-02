#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

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
	return 2;
}

int mosquitto_auth_plugin_init(void** udataptr, struct mosquitto_auth_opt* opts, int nopts) {
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void* udata, struct mosquitto_auth_opt* opts, int nopts) {
	printf("plugin_cleanup: nopts=%d\n", nopts);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void* udata, struct mosquitto_auth_opt* opts, int nopts, bool reload) {
	printf("plugin_security_init: nopts=%d, reload=%d\n", nopts, reload);
	const char* script_file = get_auth_opt("scriptfile", opts, nopts);
	if (script_file == NULL) {
		printf("this module need a target script to run, try set the auth_opt_scriptfile to a LUA-script\n");
		return MOSQ_ERR_UNKNOWN;
	}
	
	lstate = luaL_newstate();
	if(lstate == NULL) {
		printf("lua_open failed\n");
		return MOSQ_ERR_UNKNOWN;
	}
	luaL_openlibs(lstate);
	
	lua_pushinteger(lstate, MOSQ_ERR_SUCCESS);
	lua_setglobal(lstate, "mosq_err_success");
	lua_pushinteger(lstate, MOSQ_ERR_AUTH);
	lua_setglobal(lstate, "mosq_err_auth");
	
	lua_pushinteger(lstate, MOSQ_ACL_WRITE);
	lua_setglobal(lstate, "mosq_acl_write");
	lua_pushinteger(lstate, MOSQ_ACL_READ);
	lua_setglobal(lstate, "mosq_acl_read");
	lua_pushinteger(lstate, MOSQ_ERR_ACL_DENIED);
	lua_setglobal(lstate, "mosq_err_acl_denied");

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
		printf("Lua couldn't do file ...\n%s\n\n", lua_tostring(lstate, -1));
		return MOSQ_ERR_UNKNOWN;
	}
	lua_pcall(lstate, 0, LUA_MULTRET, 0);

	lua_getglobal(lstate, "security_init");
	if(!lua_isfunction(lstate, -1)) {
		lua_pop(lstate, 1);
	} else {
		lua_pushboolean(lstate, reload);
		lua_call(lstate, 1, 0);
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void* udata, struct mosquitto_auth_opt* opts, int nopts, bool reload) {
	printf("plugin_security_cleanup: nopts=%d, reload=%d\n", nopts, reload);
	lua_getglobal(lstate, "security_cleanup");
	if(lua_isfunction(lstate, -1)) {
		lua_pushboolean(lstate, reload);
		lua_call(lstate, 1, 0);
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
	printf("plugin_acl_check: %s:%s:%s (%i)\n", id, username, topic, access);
	lua_getglobal(lstate, "acl_check");
	if(!lua_isfunction(lstate, -1)) {
		printf("acl_check not defined!\n");
		lua_pop(lstate, 1);
		return MOSQ_ERR_ACL_DENIED;
	}
	lua_pushstring(lstate, id);
	lua_pushstring(lstate, username);
	lua_pushstring(lstate, topic);
	lua_pushinteger(lstate, access);
	lua_call(lstate, 4, 1);
	int res = lua_tonumber(lstate, -1);
	lua_pop(lstate, 1);
	return res;
}

int mosquitto_auth_unpwd_check(void* udata, const char* uname, const char* pwd) {
	printf("plugin_unpwd_check: %s:%s\n", uname, pwd);
	lua_getglobal(lstate, "unpwd_check");
	if(!lua_isfunction(lstate, -1)) {
		printf("unpwd_check not defined!\n");
		lua_pop(lstate, 1);
		return MOSQ_ERR_AUTH;
	}
	lua_pushstring(lstate, uname);
	lua_pushstring(lstate, pwd);
	lua_call(lstate, 2, 1);
	int res = lua_tonumber(lstate, -1);
	lua_pop(lstate, 1);
	return res;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len){
	printf("plugin_psk_get_key: hint:%s, id=%s, key=%s, max_key_len=%d\n", hint, identity, key, max_key_len);
	return MOSQ_ERR_SUCCESS;
}



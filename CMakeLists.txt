cmake_minimum_required(VERSION 2.8)

option(USE_SHIPPED_LUA "use the shipped lua instead of the pre-installed on the system" on)

add_library(lua_acl SHARED lua_acl.c)

if (USE_SHIPPED_LUA)
	add_subdirectory(lua)
	include_directories(BEFORE lua)
	set(LINK_LIBS lua523)
	add_dependencies(lua_acl lua523)
else (USE_SHIPPED_LUA)
	set(LINK_LIBS lua)
endif(USE_SHIPPED_LUA)

target_link_libraries(lua_acl ${LINK_LIBS} mosquitto)

install(TARGETS lua_acl DESTINATION lib)


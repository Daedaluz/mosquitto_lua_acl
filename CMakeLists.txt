cmake_minimum_required(VERSION 2.8)

option(USE_SHIPPED_LUA "use the shipped lua instead of the pre-installed on the system" on)

add_library(lua_acl SHARED lua_acl.c)

if (USE_SHIPPED_LUA)
	add_subdirectory(lua)
	include_directories(BEFORE lua)
	set(LINK_LIBS lua523)
	add_dependencies(lua_acl lua523)
else (USE_SHIPPED_LUA)
	find_package(Lua51 REQUIRED) 
	include_directories(${CMAKE_SOURCE_DIR} ${LUA_INCLUDE_DIR})
	set(LINK_LIBS lua5.1)
endif(USE_SHIPPED_LUA)

configure_file(${CMAKE_SOURCE_DIR}/lua_acl.h.in ${CMAKE_SOURCE_DIR}/lua_acl.h)

target_link_libraries(lua_acl ${LINK_LIBS} mosquitto)
install(TARGETS lua_acl DESTINATION lib)


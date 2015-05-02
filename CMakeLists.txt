cmake_minimum_required(VERSION 2.8)

option(USE_SHIPPED_LUA "use the shipped lua instead of the pre-installed on the system" off)

add_library(lua_acl SHARED lua_acl.c)
set_target_properties(lua_acl PROPERTIES PREFIX "")

if (USE_SHIPPED_LUA)
	add_subdirectory(lua)
	include_directories(BEFORE lua)
	set(LINK_LIBS lua523)
	add_dependencies(lua_acl lua523)
else (USE_SHIPPED_LUA)
	find_library(LUA_FOUND NAMES lua51 lua52 lua)

	if(LUA_FOUND)
		message("found and using system lua. ${LUA_FOUND}")
		include_directories(${CMAKE_SOURCE_DIR})
		set(LINK_LIBS ${LUA_FOUND})
	else(LUA_FOUND)
		message("no system lua found. using shipped lua.")
		add_subdirectory(lua)
		include_directories(BEFORE lua)
		set(LINK_LIBS lua523)
		add_dependencies(lua_acl lua523)
	endif(LUA_FOUND)

endif(USE_SHIPPED_LUA)

configure_file(${CMAKE_SOURCE_DIR}/lua_acl.h.in ${CMAKE_SOURCE_DIR}/lua_acl.h)

target_link_libraries(lua_acl ${LINK_LIBS} mosquitto)
install(TARGETS lua_acl DESTINATION lib)


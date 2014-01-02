
lua_acl.so: lua_acl.o
	gcc -shared lua_acl.o -llua -o lua_acl.so

lua_acl.o: lua_acl.c
	gcc -c -fPIC lua_acl.c -o lua_acl.o

.PHONY: clean
clean:
	rm *.o *.so



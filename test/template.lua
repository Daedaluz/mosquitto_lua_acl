
for k, v in pairs(opt) do
	print("opt", k, "", v)
end

print("url:", opt.url)
print("test1:", opt.test1)

function acl_check(id, username, topic, access)
	print(id, username, topic, access)
	if match("hello/#", topic) then
		return true
	else
		return false
	end
end

function unpwd_check(username, pwd)
	print(username, pwd)
	return true
end

function security_init(reload)
	print("SECURITY INIT, RELOAD=", reload)
end

function security_cleanup(reload)
	print("SECURITY CLEANUP, RELOAD=", reload)
end

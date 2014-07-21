
for k, v in pairs(opt) do
	print("opt", k, "", v)
end

print("url:", opt.url)
print("test1:", opt.test1)

function acl_check(id, username, topic, access)
	if mosq_match("#", topic) then
		return mosq_err_success
	else
		return mosq_err_acl_denied
	end
end

function unpwd_check(username, pwd)
	return mosq_err_success
end

function security_init(reload)
	print("SECURITY INIT, RELOAD=", reload)
end

function security_cleanup(reload)
	print("SECURITY CLEANUP, RELOAD=", reload)
end

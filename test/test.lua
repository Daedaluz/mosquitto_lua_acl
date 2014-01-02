for k, v in pairs(opt) do
	print(k, "=", v)
end

print("------------------------------------------------------------")
print(opt.test2)

function acl_check(id, username, topic, access)
	print("---------------------",id, username, topic, access)
	return(mosq_err_success)
end

function unpwd_check(username, pwd)
	if username == "tobias" then 
		print(username, "has access")
		return(mosq_err_success)
	end
	print(username, "NO ACCESS!!!!")
	return(mosq_err_auth)
end

function security_init(reload)
	print("SECURITY_INIT> RELOAD =", reload)
end

function security_cleanup(reload)
	print("SECURITY_CLEANUP> RELOAD =", reload)
end

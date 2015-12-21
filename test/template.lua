log("url:" .. opt.url)
log("test1:" .. opt.test1)

fmt = string.format

function acl_check(id, username, topic, payload, access)
	log(fmt("%s %s %s %d", id, username, topic, access))
	if match("hello/#", topic) then
		log(fmt("Payload: %s", payload))
		return true
	else
		return false
	end
end

function unpwd_check(username, pwd)
	log(fmt("checking %s:%s", username, pwd))
	return true
end

function security_init(reload)
	log(fmt("SECURITY INIT, RELOAD=%s", tostring(reload)))
end

function security_cleanup(reload)
	log(fmt("SECURITY CLEANUP, READLOAD=%s", tostring(reload)))
end


function acl_check(id, username, topic, access)
	if mosq_match("#", topic) then
		return mosq_err_success
	else
		return mosq_acl_denind
	end
end

function unpwd_check(username, pwd)
	return mosq_err_success
end

function security_init(reload)
end

function security_cleanup(reload)
end

curl = require 'cURL'
json = require 'json'

print("HELLO")

USERAGENT = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

print("------------------------------------------------------------")
print(opt.test2)

function acl_check(id, username, topic, access)
	print("---------------------",id, username, topic, access)
	return(mosq_err_success)
end

function unpwd_check(username, pwd)
	c = curl.easy_init()
	authorized = false
	function test_authorized(response)
		print(response)
		js = json.decode(response)
		if js.error ~= nil then
			print("User not valid")
			authorized = false
		else
			print("User", js.name, "connected")
			authorized = true
		end
	end
	c:setopt_url("https://www.googleapis.com/oauth2/v1/userinfo?access_token=" .. pwd .. "&token_type=Bearer")
	c:setopt_useragent(USERAGENT)
	c:perform({writefunction = test_authorized})
	if authorized then
		return(mosq_err_success)
	else
		return(mosq_err_auth)
	end
end

function security_init(reload)
	print("SECURITY_INIT> RELOAD =", reload)
end

function security_cleanup(reload)
	print("SECURITY_CLEANUP> RELOAD =", reload)
end

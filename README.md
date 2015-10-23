lua-resty-hawk
==============

[Hawk](https://github.com/hueniverse/hawk) authentication on Nginx with Lua and [OpenResty](http://openresty.org)

[Hawk](https://github.com/hueniverse/hawk) is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

Usage example
-------------

First, create a Lua script for fetching credentials, for exemple 'credentials.lua':

```lua
local ngx = ngx
local artifacts = ngx.ctx.artifacts

-- At this point, artifacts has the following keys : 
-- id, method, host, port, resource, ts, nonce, hash, ext, app, dlg, mac
-- Use what you want in order to find the key needed to check the MAC

if not artifacts.id then
	ngx.ctx.err = "Incorrect id"
else
  -- account found? (do a database lookup here, instead)
  if artifacts.id == 'bertrand' then
  	ngx.ctx.credentials = {key = "my_key", algorithm = "sha1", id = artifacts.id}
	ngx.ctx.err = nil
  else 
    ngx.ctx.err = "Account not found"
  end
end
```

The purpose of this script is to lookup the set of Hawk credentials based on the provided credentials id.
The credentials include the MAC key, MAC algorithm, and other attributes (such as username) needed by the application.
This function is the equivalent of verifying the username and password in Basic authentication.
It is the equivalent of the ```credentialsFunc``` callback in the Hawk javascript implementation.

In order to have nginx use this script, create an internal location in your nginx configuration, for example:

```
location /hawk/credentials {
  internal;
  content_by_lua_file credentials.lua;
}
```
This location will be called with a ```location.capture``` in the module, as shown below.
Then create the location you want to protect with Hawk authentication:

```
location = /my/protected/stuff {
  # if you need the body, add : lua_need_request_body on;
  access_by_lua_file    access.lua;
  # do something here, for example:
  content_by_lua_file   stuff.lua;
}
```

The authentication happens in the 'access.lua' file, it could look like this:

```lua
local hawk = require 'resty.hawk'
local options = { timestamp_skew_sec = 10 }
-- you could add payload validation in options too, for example:
--if ngx.var.request_body and string.len(ngx.var.request_body) > 0 then
--	options.payload = ngx.var.request_body
--end
hawk.authenticate('/hawk/credentials', options)
```

Now, you are ready to accept HTTP requests authenticated by Hawk.

Replay Protection / Nonce Checking
----------------------------------

To prevent replay attacks you can add nonce checking.  For example change access.lua:

```lua
local hawk = require 'resty.hawk'
local nonce_ttl_sec = 60
local options = { 
	timestamp_skew_sec = 10,
	nonce_func = function(nonce)
		local success, err = ngx.shared.hawk_nonces:add(nonce, true, ngx.time() + nonce_ttl_sec)
		return success or (err ~= 'exists')
	end
}

hawk.authenticate('/hawk/credentials', options)
```

And configure the size of `hawk_nonces` in the `http` block in your nginx.conf:

```
http {
    # Hawk nonce memory
    lua_shared_dict hawk_nonces 100k;
    
    ...
}
```

Limitations
-----------

Only sha1 is supported, but other algorithm could be implemented easily because they are available in Openresty.
Bewit and Message authentication are not yet implemented as I haven't had a use for them.

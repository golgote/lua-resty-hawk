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
-- validate the id any way you want
if not artifacts.id then
	ngx.ctx.err = "Incorrect id"
else
  -- account found? (do a database lookup here, instead)
  if artifacts.id == 'bertrand' then
  	ngx.ctx.credentials = {key = "my_app_key", algorithm = "sha1", id = artifacts.id}
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

Then create the location you want to protect with Hawk authentication:

```
location = /my/stuff {
  access_by_lua_file    access.lua;
  # serve something here, for example:
  content_by_lua_file   stuff.lua;
}
```

The authentication happens in the access.lua file, it could look like this:

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

Limitations
-----------

Only sha1 is supported, but other algorithm could be implemented easily because they are available in Openresty.
Bewit and Message authentication are not yet implemented as I haven't had a use for them.

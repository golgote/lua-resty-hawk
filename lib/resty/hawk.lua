-- Hawk server-side HTTP authentication for Nginx and Lua
-- Copyright (C) 2014 Bertrand Mansion (golgote), Mamasam
-- License MIT

local M = {
	_VERSION = '0.1',
	_HEADER_VERSION = 1
}

local function escape_header(header)
	return string.gsub(string.gsub(tostring(header), '\\', '\\\\'), '"', '\\"')
end

local function exit(status, message, attributes)
	local attributes = attributes or {}
	if message and message ~= "" then
		attributes['error'] = tostring(message)
		ngx.log(ngx.NOTICE, message)
	end
	if status == ngx.HTTP_UNAUTHORIZED then
		local wwwa = {}
		if attributes then
			for k,v in pairs(attributes) do
				wwwa[#wwwa+1] = k .. '="' .. escape_header(v) .. '"'
			end
		end
		ngx.header['WWW-Authenticate'] = 'Hawk ' .. table.concat(wwwa, ', ')
	end
	ngx.header.content_type = 'text/plain'
	return ngx.exit(status)
end

local function calculate_payload_hash(payload, algorithm, content_type)
	local normalized = 'hawk.' .. M._HEADER_VERSION .. '.payload'
	if content_type then
		normalized = normalized .. "\n" .. string.lower(content_type)
	end
	if payload then
		normalized = normalized .. "\n" .. payload
	end
	normalized = normalized .. "\n"
	if algorithm == 'sha1' then
		return ngx.encode_base64(ngx.sha1_bin(normalized))
	else
		return exit(ngx.HTTP_INTERNAL_SERVER_ERROR, "Algorithm not implemented")
	end
end

local function generate_normalized_string(mac_type, options)
	local normalized = {
		'hawk.' .. M._HEADER_VERSION .. '.' .. mac_type,
		tostring(options['ts']),
		options['nonce'],
		string.upper(options['method']),
		options['resource'],
		string.lower(options['host']),
		tostring(options['port'])
	}
	if options['hash'] then
		table.insert(normalized, options['hash'])
	else
		table.insert(normalized, '')
	end
	if options['ext'] then
		local ext = options['ext']:gsub('\\', '\\\\'):gsub('\n', '\\n')
		table.insert(normalized, ext)
	else
		table.insert(normalized, '')
	end
	if options['app'] then
		table.insert(normalized, options['app'])
		if options['dlg'] then
			table.insert(normalized, options['dlg'])
		else
			table.insert(normalized, '')
		end
	end
	return table.concat(normalized, "\n") .. "\n"
end

local function calculate_mac(mac_type, credentials, artifacts)
	local ngx = ngx
	local digest
	local normalized = generate_normalized_string(mac_type, artifacts)
	if credentials.algorithm == 'sha1' then
		digest = ngx.hmac_sha1(credentials.key, normalized)
		return ngx.encode_base64(digest)
	else
		return exit(ngx.HTTP_INTERNAL_SERVER_ERROR, "Algorithm not implemented")
	end
end

local function parse_authorization_header(auth_header, allowable_keys)
	local ngx = ngx
	if not auth_header then
		return exit(ngx.HTTP_FORBIDDEN, "No auth header")
	end

	if not allowable_keys then
	    allowable_keys = {id = true, ts = true, nonce = true, hash = true, ext = true, mac = true, app = true, dlg = true}
	end

	local attributes = {}
	local error_message = ""
	local has_attributes = false
	local allowable_chars = [=[^[%w=!#%$%%&'%(%)%*%+,%-%./:;<>%?@%^`{|}~%[%] ]+$]=]

	string.gsub(auth_header, '^[Hh][Aa][Ww][Kk]%s+(.*)$', function(attribute_string)
		string.gsub(attribute_string, '(%w+)="([^"]*)"', function(key, value)
			if not allowable_keys[key] then
				error_message = "Unknown attribute: " .. key
				return
			end
			if not string.find(value, allowable_chars) then
				error_message = "Bad attribute value: " .. key
				return
			end
			if attributes[key] then
				error_message = "Duplicate attribute:  " .. key
				return
			end
			attributes[key] = value
			has_attributes = true
		end)
	end)

	if error_message ~= "" then
		return exit(ngx.HTTP_BAD_REQUEST, error_message)
	end

	if has_attributes == false then
		return exit(ngx.HTTP_BAD_REQUEST, 'Invalid header syntax')
	end
	return attributes
end

M.header = function(credentials, artifacts, options)

	local response_artifacts = {
		method = artifacts.method,
		host = artifacts.host,
		port = artifacts.port,
		resource = artifacts.resource,
		ts = artifacts.ts,
		nonce = artifacts.nonce,
		app = artifacts.app,
		dlg = artifacts.dlg,
	}
	if options.hash then
		response_artifacts.hash = options.hash
	end
	if options.ext then
		response_artifacts.ext = options.ext
	end
	if not response_artifacts.hash and options.payload then
		response_artifacts.hash = calculate_payload_hash(options.payload, credentials.algorithm, options.content_type)
	end
	local mac = calculate_mac('response', credentials, response_artifacts)
	local header = 'Hawk mac="' .. mac .. '"'
	if response_artifacts.hash then
		header = header .. ', hash="' .. response_artifacts.hash .. '"'
	end
	if response_artifacts.ext then
		header = header .. ', ext="' .. escape_header(response_artifacts.ext) .. '"'
	end
	return header
end


M.authenticate = function(credentials_loc, options)

	local ngx = ngx
	local timestamp_offset_sec = options.timestamp_offset_sec or 0
	local timestamp_skew_sec = options.timestamp_skew_sec or 60
	local now = ngx.time() + tonumber(timestamp_offset_sec)
	local headers = ngx.req.get_headers()
	local auth_header = headers['authorization']
	local content_type = headers['content_type']
	local attributes = parse_authorization_header(auth_header)

	if not attributes or
		not attributes.id or
		not attributes.ts or
		not attributes.nonce or
		not attributes.mac then
		return exit(ngx.HTTP_BAD_REQUEST, 'Missing attributes')
	end

	ngx.ctx.artifacts = {
		method = ngx.var.request_method,
		host = ngx.var.host,
		port = ngx.var.server_port,
		resource = ngx.var.request_uri,
		ts = attributes.ts,
		nonce = attributes.nonce,
		hash = attributes.hash,
		ext = attributes.ext,
		app = attributes.app,
		dlg = attributes.dlg,
		mac = attributes.mac,
		id = attributes.id
	}

	-- Check credentials using provided location
	local res = ngx.location.capture(credentials_loc, {ctx = ngx.ctx})

	if ngx.ctx.err then
		return exit(ngx.HTTP_INTERNAL_SERVER_ERROR, ngx.ctx.err)
	end

	if not ngx.ctx.credentials then
		return exit(ngx.HTTP_UNAUTHORIZED, "Unknown credentials")
	end

	if not ngx.ctx.credentials.key or not ngx.ctx.credentials.algorithm then
		return exit(ngx.HTTP_INTERNAL_SERVER_ERROR, "Invalid credentials")
	end

	local mac = calculate_mac('header', ngx.ctx.credentials, ngx.ctx.artifacts)
	if mac and mac ~= attributes.mac then
		return exit(ngx.HTTP_UNAUTHORIZED, "Bad mac")
	end

	if options['payload'] and options['payload'] ~= '' then
		if not attributes['hash'] then
			return exit(ngx.HTTP_UNAUTHORIZED, "Missing required payload hash")
		end
		options['content_type'] = content_type
		local hash = calculate_payload_hash(options['payload'], ngx.ctx.credentials['algorithm'], content_type)
		if hash ~= attributes['hash'] then
			return exit(ngx.HTTP_UNAUTHORIZED, "Bad payload hash")
		end
	end

	if options['nonce_func'] then
		local nonce_check = options['nonce_func'](attributes['nonce'], attributes['ts'])
		if nonce_check == false then
			return exit(ngx.HTTP_UNAUTHORIZED, "Invalid nonce")
		end
	end

	if math.abs(tonumber(attributes['ts']) - tonumber(now)) > tonumber(timestamp_skew_sec) then
		local now = ngx.time() + tonumber(timestamp_offset_sec)
		local tsm = ngx.encode_base64(ngx.hmac_sha1(ngx.ctx.credentials['key'], 'hawk.' .. M._HEADER_VERSION .. ".ts\n" .. now .. "\n"))
		return exit(ngx.HTTP_UNAUTHORIZED, 'Stale timestamp', {ts = now, tsm = tsm})
	end

	-- Server Authorization header
	ngx.header['Server-Authorization'] = M.header(ngx.ctx.credentials, ngx.ctx.artifacts, options)
	return
end

M.authenticatePayload = function(payload, credentials, artifacts, content_type)
	-- TODO
end

M.authenticateBewit = function(credentials_loc, options)
	-- TODO
end

M.authenticateMessage = function(host, port, message, authorization, credentials_loc, options)
	-- TODO
end


return M

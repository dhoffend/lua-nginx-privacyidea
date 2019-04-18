-- -- Copyright (C) by Daniel Hoffend (dhoffend)

-- ----------------------------------
-- extract authentication credentials
-- ----------------------------------

function extract_credentials()
    -- Test Authentication header is set and with a value
    local header = ngx.req.get_headers()['Authorization']
    if header == nil or header:find(" ") == nil then
        return false, false
    end

    local divider = header:find(' ')
    if header:sub(0, divider-1) ~= 'Basic' then
        return false, false
    end

    local auth = ngx.decode_base64(header:sub(divider+1))
    if auth == nil or auth:find(':') == nil then
        return false, false
    end

    local divider = auth:find(':')
    return auth:sub(0, divider-1), auth:sub(divider+1)
end

-- ------------------------
-- Connect to redis storage
-- ------------------------

function redis_connect(host, port)
    local redis  = require "nginx/redis"
    local red = redis:new()
    red:set_timeout(1000) -- 1 sec
    local ok, err = red:connect(host, port)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect tor redis: ", err)
        ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    return red
end

-- ------------------
-- generate redis key
-- ------------------

function generate_key(username)
    return ngx.var.server_name .. ':' .. ngx.var.server_port .. ':' .. ngx.var.document_root .. ':' .. username
end

-- --------------------------------
-- password hashing/verify function
-- --------------------------------

function password_hash(password, salt)
    -- yes this can be improved by using sha512, bcrypt, etc
    local salt2 = ngx.sha1_bin(salt .. ':' .. password)
    local digest = ngx.hmac_sha1(salt2, password)
    return ngx.encode_base64(digest)
end

function password_verify(password, hash, salt)
    return hash == password_hash(password, salt)
end

-- -----------------------------------------
-- validate user credentials with otp server
-- -----------------------------------------

function privacyidea_validate(username, password)

    -- prepare parameter
    local params = {user = username, pass = password}
    local realm = ngx.var.privacyidea_realm or nil
    if realm then
        params['realm'] = realm
    end

    -- send request
    ngx.req.set_header('Content-Type', 'application/x-www-form-urlencoded')
    local uri = ngx.var.privacyidea_uri or '/privacyidea-validate-check'
    local res = ngx.location.capture(uri, {
        method = ngx.HTTP_POST,
        body = ngx.encode_args(params)
    })

    if res.status ~= 200 then
        return false, 'privacyIDEA HTTP Status ' .. res.status
    end

    local cjson = require "cjson"
    local answer = cjson.decode(res.body)
    local ok = false
    local err = ''
    --if res.status ~= 200 and type(answer.result) == "table" then
    if type(answer.result) == "table" then
        -- authentication okay
        if answer.result.status == true then
            if answer.result.value == true then
                ok = true
                return ok, err
            end
        end

        -- check for errors
        if type(answer.detail) == "table" then
            if answer.detail.message then
                err = err .. ': ' .. answer.detail.message
            end
        end
        if answer.result.error then
            if answer.result.error.message then
                err = err .. ': ' .. answer.result.error.message
            end
        end
    end
    return ok, err
end

-- --------------------
-- authentication logic
-- --------------------

function authenticate()
    -- Test Authentication header is set and with a value
    local header = ngx.req.get_headers()['Authorization']
    if header == nil or header:find(" ") == nil then
        return false
    end

    -- extract auth credentials
    local username, password = extract_credentials()
    if username == false then
        return false
    end

    -- open redis connection
    local redis_host = ngx.var.privacyidea_redis_host or '127.0.0.1'
    local redis_port = ngx.var.privacyidea_redis_port or 6379
    local ttl = ngx.var.privacyidea_ttl or 900
    local red = redis_connect(redis_host, redis_port)

    -- lookup key and hash
    local key = generate_key(username)
    local value = red:get(key)

    -- password hash ok => extend ttl and return username if status is ok
    if value and password_verify(password, value, key) then
        red:expire(key,ttl)
        return username

    -- start remote authentication
    else
        local ok, err = privacyidea_validate(username, password)
        if ok then
            ngx.log(ngx.ERR, '[' .. username .. '] authentication ok')
            red:setex(key, ttl, password_hash(password, key))
            return username
        else
            ngx.log(ngx.ERR, '[' .. username .. '] invalid authentication' .. err)
            return false
        end
    end
end

-- -------------------------
-- start authentication flow
-- -------------------------

local user = authenticate()

if not user then
    local http_realm = ngx.var.privacyidea_http_realm or ''
    ngx.header.www_authenticate = 'Basic realm="' .. http_realm .. '"'
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
    return
end


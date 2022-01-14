LUA based NGINX Authentication plugin for privacyIDEA
=====================================================

This LUA script enables the nginx webserver to authenticate against
privacyIDEA using multiple factor authentication like OTP, Yubikey, etc and
cache the result for a defined lifetime.

Redis is providing the server side cache (for successful HTTP Basic
Authentications) similar to the privacyIDEA apache2 authentication module.

The lua script requires the basic nginx-lua, lua-cjson, lua-nginx-redis and
lua-resty-http modules to be available.

Configuration
-------------

Configuration example nginx virtual host

    location / {
        # redis host:port
        # set $privacyidea_redis_host "127.0.0.1";
        # set $privacyidea_redis_post 6379;

        # how long are accepted authentication allowed to be cached
        # if expired, the user has to reauthenticate
        # set $privacyidea_ttl 900;

        # privacyIDEA realm. leave empty == default
        # set $privacyidea_realm 'somerealm'; # (optional)

        # pointer to the internal validation proxy pass
        # set $privacyidea_uri "/privacyidea-validate-check";

        # the salt will be used as key/salt for hashing the password
        # set $privacyidea_salt "some random string as hmac salt";

        # the http realm presented to the user
        # set $privacyidea_http_realm "Secure zone (use PIN + OTP)";

        access_by_lua_file 'privacyidea.lua';
   
    }

    # internal pointer to the validation server
    # nginx lua support remote calls only via proxy_pass or
    # by using direct sockect connections
    location /privacyidea-validate-check {
        internal;
        # proxy_ssl_verify off;
        proxy_pass https://privacyidea/validate/check;
    }
    
Installation
------------

Tested with Debian Jessie 8.0

    apt-get install nginx-extras lua-nginx-redis lua-cjson redis-server

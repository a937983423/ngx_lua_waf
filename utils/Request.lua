--
-- Created by IntelliJ IDEA.
-- User: 圣烽
-- Date: 2017/12/26
-- Time: 10:02
-- To change this template use File | Settings | File Templates.
--

local Request = class("Request")

function Request.getArgs()
    local request_method = ngx.var.request_method
    local args = ngx.req.get_uri_args()
    -- 参数获取
    if "POST" == request_method then
        ngx.req.read_body()
        local postArgs = ngx.req.get_post_args()
        if postArgs then
            for k, v in pairs(postArgs) do
                args[k] = v
            end
        end
    end
    return args
end


function Request.get_cookies()
    local cookies = ngx.header["Set-Cookie"] or {}
    if type(cookies) == "string" then
        print(cookies)
        cookies = {cookies}
    end
    return cookies
end


function Request.add_cookie(cookie)
    local cookies = get_cookies()
    table.insert(cookies, cookie)
    ngx.header['Set-Cookie'] = cookies
end


return Request;
--
-- Created by IntelliJ IDEA.
-- User: egan
-- Email egzosn@gmail.com
-- Date: 2017/12/26
-- Time: 16:27
-- To change self template use File | Settings | File Templates.
--
local Cookies = class("Cookies")


function Cookies:ctor(key, value)
    self.key = key
    if value ~= nil then
        self.value = string.urlencode(value)
    end
    self.expiresTime = nil
    self.domain = nil
    self.path = "/"
    self.secure = nil
end

function Cookies:getCookies()
    local cookies = ngx.header["Set-Cookie"] or {}
    if type(cookies) == "string" then
        cookies = { cookies }
    end
    return cookies
end


function Cookies:addCookie(cookie)
    local cookies = self:getCookies()
    table.insert(cookies, cookie)
    ngx.header['Set-Cookie'] = cookies
end


function Cookies:getValue()
    return self.value
end

function Cookies:setValue(value)
    self.value = string.urlencode(value);
end

function Cookies:getExpiresTime()
    return self.expiresTime
end

function Cookies:setExpiresTime(time)
    self.expiresTime = time
end

function Cookies:getDomain()
    return self.domain
end

function Cookies:setDomain(domain)
    self.domain = domain
end

function Cookies:getPath()
    return self.path
end

function Cookies:setPath(path)
    self.path = path
end

function Cookies:write(value)
    if value ~= nil then
        self:setValue(value)
    end

    local ck = self.key .. "=" .. self.value;
    if (self.expiresTime ~= null) then
        ck = ck .. ";expires=" .. ngx.cookie_time(self.expiresTime)
    end
    if (self.domain ~= null) then
        ck = ck .. ";domain=" + self.domain
    end
    if (self.path ~= null) then
        ck = ck .. ";path=" + self.path
    end
    if (self.secure ~= nil) then
        ck = ck .. ";secure"
    end
    addCookie(ck)
end

return Cookies

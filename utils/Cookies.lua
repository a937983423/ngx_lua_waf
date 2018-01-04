--
-- Created by IntelliJ IDEA.
-- User: egan
-- Email egzosn@gmail.com
-- Date: 2017/12/26
-- Time: 16:27
-- To change self template use File | Settings | File Templates.
--
local Cookies = class("Cookies")

----------------------
-- 初始化
-- @function ctor
-- @param String key Cookies的键
-- @param String value Cookies键对应的值
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

----------------------
-- 获取所有的Cookies
-- @function getCookies
function Cookies:getCookies()
    local cookies = ngx.header["Set-Cookie"] or {}
    if type(cookies) == "string" then
        cookies = { cookies }
    end
    return cookies
end

----------------------
-- 添加一组cookie
-- @function addCookie
-- @param String cookies组的字符串
function Cookies:addCookie(cookie)
    local cookies = self:getCookies()
    table.insert(cookies, cookie)
    ngx.header['Set-Cookie'] = cookies
end
----------------------
-- 移除一组cookie
-- @function removeCookie
-- @param String key 需要删除的cookie的key
function Cookies:removeCookie(key)

    if key ~= nil then
        self.key = key;
    end
    local cookies = get_cookies()
    for k, value in ipairs(cookies) do
        local name = match(value, "(.-)=")
        ngx.log(ngx.ERR, k.."<=>", value)
        if name == self.key then
            table.remove(cookies, k)
        end
    end

    ngx.header['Set-Cookie'] = cookies or {}

end
----------------------
-- 获取当前cookie 对应的值
-- @function getValue
-- @return string#value  当前cookie 对应的值
function Cookies:getValue()
    return self.value
end

----------------------
-- 设置当前cookie 对应的值
-- @function setValue
-- @param String value 设置当前Cookies的值
function Cookies:setValue(value)
    self.value = string.urlencode(value);
end
----------------------
-- 获取当前cookie 对应的有效时间
-- @function getExpiresTime
-- @return String#expiresTime
function Cookies:getExpiresTime()
    return self.expiresTime
end

----------------------
-- 设置当前cookie 对应的有效时间
-- @function setExpiresTime
-- @param String expiresTime 时间
function Cookies:setExpiresTime(time)
    self.expiresTime = time
end
----------------------
-- 获取当前cookie 对应的域名
-- @function getDomain
-- @return String#domain
function Cookies:getDomain()
    return self.domain
end
----------------------
-- 设置当前cookie 对应的域名
-- @function setDomain
-- @param String domain
function Cookies:setDomain(domain)
    self.domain = domain
end
----------------------
-- 获取当前cookie 对应的路径
-- @function getPath
-- @return String#path
function Cookies:getPath()
    return self.path
end
----------------------
-- 设置当前cookie 对应的路径
-- @function getPath
-- @param String path
function Cookies:setPath(path)
    self.path = path
end

----------------------
-- 写入当前cookie
-- @function write
function Cookies:write()

    self:addCookie(self:toString())
end

----------------------
-- 读取当前cookie
-- @function read
function Cookies:read()

   return ngx.var["cookie_".. self.key]
end

----------------------
--
-- @function toString
function Cookies:toString()
    local ck = self.key .. "=" .. self.value;
    if self.expiresTime ~= nil then
        ck = ck .. ";expires=" .. ngx.cookie_time(self.expiresTime)
    end
    if self.domain ~= nil then
        ck = ck .. ";domain=" .. self.domain
    end
    if self.path ~= nil then
        ck = ck .. ";path=" .. self.path
    end
    if self.secure ~= nil then
        ck = ck .. ";secure"
    end

  return ck;
end



return Cookies

--
-- Created by IntelliJ IDEA.
-- User: 圣烽
-- Date: 2017/12/27
-- Time: 11:04
-- To change this template use File | Settings | File Templates.
--
local Cookies = require 'utils.Cookies';
local request = (require 'utils.Request').new();
local action = class("action")
----------------------------------
-- 重启nginx 这里好像没有效果
function action:nginxReload()
    local ret =  os.execute(NginxPath .. "/nginx -s reload");
    if ret ~= 0 then
        success("message", "重启成功")
    else
        error(-1, "重启失败")
    end
    return true
end


----------------------------------------
--
-- @function wafAuth 授权登录
function action:wafAuth()
        local cookie = Cookies.new("session")
        if not string.isEmpty(cookie:read()) and table.indexof(users, cookie:read()) then
            return false
        end

        local args = request.getArgs();
        if  string.isEmpty(args["user"]) or string.isEmpty(args["pwd"])  then
            say_json({ code = -1, message="账号或密码是否正确"})

            return true
        end

        local acc = args["user"] .. "|" .. args["pwd"]
        if table.indexof(users, acc) then
            cookie:setValue(acc)
            cookie:setExpiresTime(ngx.time() + 60 * 30)
            cookie:write()
            say_json({ code = 0, user = args["user"], pwd = args["pwd"]})
            return true
        end
end


------------------------------------------------------
-- @function getArgsrules 获取配置argsrules的所有规则
function action:getArgsrules()
    success("rules", argsrules)
    return true

end

------------------------------------------------------
-- @function delArgsrules 获取配置argsrules的所有规则
function action:delArgsrules()
    return self:del("args")
end

------------------------------------------------------
-- @function argsrules 保存argsrules的所有规则
function action:argsrules()
    return self:save("args")
end

------------------------------------------------------
-- @function getCookierules 获取配置cookie的所有规则
function action:getCookierules()
    success("rules", ckrules)
    return true

end

------------------------------------------------------
-- @function delCookierules 获取配置cookie的所有规则
function action:delCookierules()
    return self:del("cookie")

end

------------------------------------------------------
-- @function cookierules 保存cookie的所有规则
function action:cookierules()
    return self:save("cookie")
end

------------------------------------------------------
-- @function getPostrules 获取配置post的所有规则
function action:getPostrules()
    success("rules", postrules)
    return true

end

------------------------------------------------------
-- @function delCookierules 获取配置post的所有规则
function action:delCookierules()
    return self:del("post")

end

------------------------------------------------------
-- @function postrules 保存post的所有规则
function action:postrules()
    return self:save("post")
end

------------------------------------------------------
-- 获取url规则
-- @function getUrlRules 获取url规则
function action:getUrlRules()
    success("rules", urlrules)
    return true
end

------------------------------------------------------
-- @function delArgsrules 获取配置url的所有规则
function action:delUrlrules()
    return self:del("url")
end
-------------------------------------
-- @function urlrules 保存urlrules
function action:urlrules()
    return self:save("url")
end

------------------------------------------------------
-- 获取url规则
-- @function getUrlRules 获取URL规则
function action:getUsers()
    success("rules", users)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定用户
function action:delUsers()
    return self:del("user")
end
-------------------------------------
-- @function user 保存waf操作用户
function action:users()
    return self:save("user")
end

------------------------------------------------------
-- 获取设备信息规则
-- @function getUarules 获取请求者设备信息(浏览器内核)规则
function action:getUarules()
    success("rules", uarules)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定请求者设备信息(浏览器内核)规则
function action:delUarules()
    return self:del("user-agent")
end
-------------------------------------
-- @function user 保存请求者设备信息(浏览器内核)规则
function action:uarules()
    return self:save("user-agent")
end

------------------------------------------------------
-- 获取设备信息规则
-- @function getUarules 获取请求者设备信息(浏览器内核)规则
function action:getWhiteurl()
    success("rules", whiteurl)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定请求者设备信息(浏览器内核)规则
function action:delWhiteurl()
    return self:del("whiteurl")
end
-------------------------------------
-- @function user 保存请求者设备信息(浏览器内核)规则
function action:whiteurl()
    return self:save("whiteurl")
end



function action:save(var )
    local args = request.getArgs();
    local rules =  args["rules"]
    local id =  args["id"]
    if string.isEmpty(rules)   then
        error(100101, "参数规则必填")
        return true
    end
    io.save(var, rules, id)
    return true

end
------------------------------------------------------
-- @function delArgsrules 获取配置argsrules的所有规则
function action:del(var)
    local id =  request.getArgs()["id"]
    io.delete(var, id)
    return true

end


return action
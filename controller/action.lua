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


function action:ctor()
end

----------------------------------
-- 重启nginx 这里好像没有效果
function action:nginxReload()
    local ret = os.execute(NginxPath .. "/nginx -s reload");
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
    if string.isEmpty(args["user"]) or string.isEmpty(args["pwd"]) then
        say_json({ code = -1, message = "账号或密码是否正确" })

        return true
    end

    local acc = args["user"] .. "|" .. args["pwd"]
    if table.indexof(users, acc) then
        cookie:setValue(acc)
        cookie:setExpiresTime(ngx.time() + 60 * 30)
        cookie:write()
        say_json({ code = 0, user = args["user"], pwd = args["pwd"] })
        return true
    end
end

function action:getRules()
    success("data", rules)
    return true
end


------------------------------------------------------
-- @function getArgsrules 获取配置argsrules的所有规则
function action:get_args_rules()
    success("data", argsrules)
    return true
end

------------------------------------------------------
-- @function delArgsrules 获取配置argsrules的所有规则
function action:del_args_rules()
    return action:del("args")
end

------------------------------------------------------
-- @function argsrules 保存argsrules的所有规则
function action:args_rules()
    return action:save("args")
end

------------------------------------------------------
-- @function getCookierules 获取配置cookie的所有规则
function action:get_cookie_rules()
    success("data", ckrules)
    return true
end

------------------------------------------------------
-- @function delCookierules 获取配置cookie的所有规则
function action:del_cookie_rules()
    return action:del("cookie")
end

------------------------------------------------------
-- @function cookierules 保存cookie的所有规则
function action:cookie_rules()
    return action:save("cookie")
end

------------------------------------------------------
-- @function getPostrules 获取配置post的所有规则
function action:get_post_rules()
    success("data", postrules)
    return true
end

------------------------------------------------------
-- @function delCookierules 获取配置post的所有规则
function action:del_post_rules()
    return action:del("post")
end

------------------------------------------------------
-- @function postrules 保存post的所有规则
function action:post_rules()
    return action:save("post")
end

------------------------------------------------------
-- 获取url规则
-- @function getUrlRules 获取url规则
function action:get_url_rules()
    success("data", urlrules)
    return true
end

------------------------------------------------------
-- @function delArgsrules 获取配置url的所有规则
function action:del_url_rules()

    return action:del("url")
end

-------------------------------------
-- @function urlrules 保存urlrules
function action:url_rules()
    return action:save("url")
end

------------------------------------------------------
-- 获取url规则
-- @function getUsers 获取用户
function action:get_users_rules()
    success("data", users)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定用户
function action:del_users_rules()
    return action:del("user")
end

-------------------------------------
-- @function user 保存waf操作用户
function action:users_rules()
    return action:save("user")
end

------------------------------------------------------
-- 获取设备信息规则
-- @function getUarules 获取请求者设备信息(浏览器内核)规则
function action:get_user_agent_rules()
    success("data", uarules)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定请求者设备信息(浏览器内核)规则
function action:del_user_agent_rules()
    return action:del("user_agent")
end

-------------------------------------
-- @function user 保存请求者设备信息(浏览器内核)规则
function action:user_agent_rules()
    return action:save("user_agent")
end

------------------------------------------------------
-- 获取设备信息规则
-- @function getUarules 获取请求者设备信息(浏览器内核)规则
function action:get_whiteurl_rules()
    success("data", wturlrules)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定请求者设备信息(浏览器内核)规则
function action:del_whiteurl_rules()
    return action:del("whiteurl")
end

-------------------------------------
-- @function user 保存请求者设备信息(浏览器内核)规则
function action:whiteurl_rules()
    return action:save("whiteurl")
end



function action:save(var)
    local args = request.getArgs();
    local value = args["value"]
    local id = args["id"]
    if string.isEmpty(value) then
        error(100101, "参数规则必填")
        return true
    end
    if string.isEmpty(id) then
        if io.add(var, value) then
            success("message", "添加成功")
            table.insert(rules[var .. "_rules"], rules)
            return true;
        end
        error(100102, "添加失败")
    else
        local i = tonumber(id)
        if type(i) == "number" and io.update(var, value, id) then
            rules[var .. "_rules"][i] = value
            success("message", "更新成功")

            return true;
        end
        error(100103, "更新失败")
    end
    return true
end

------------------------------------------------------
-- @function delArgsrules 获取配置argsrules的所有规则
function action:del(var)
    local id = request.getArgs()["id"]
    if not string.isEmpty(id) and type(tonumber(id)) == "number" then
        io.delete(var, id)
        table.remove(rules[var .. "_rules"], id)
        success("message", "删除成功")
    else
        error(-1, "删除失败")
    end

    return true
end


return action
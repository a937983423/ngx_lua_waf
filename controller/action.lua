--
-- Created by IntelliJ IDEA.
-- User: egan
-- Date: 2017/12/27
-- Time: 11:04
-- To change this template use File | Settings | File Templates.
--
local Cookies = require 'utils.Cookies';
local request = (require 'utils.Request').new();
local action = class("action")

----------------------
-- 初始化
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
function action:getIpList()
    success("data", ips)
    return true
end


------------------------------------------------------
-- @function getArgsrules 获取配置argsrules的所有规则
function action:get_args_rules()
    success("data", rules.args_rules)
    return true
end

------------------------------------------------------
-- @function delArgsrules 获取配置argsrules的所有规则
function action:del_args_rules()
    return action:delRule("args")
end

------------------------------------------------------
-- @function argsrules 保存argsrules的所有规则
function action:args_rules()
    return action:saveRule("args")
end

------------------------------------------------------
-- @function getArgsrules 获取配置不允许上传文件后缀类型规则
function action:get_black_fileExt_rules()
    success("data", rules.black_fileExt_rules)
    return true
end

------------------------------------------------------
-- @function delArgsrules 获取配置argsrules的所有规则
function action:del_black_fileExt_rules()
    return action:delRule("black_fileExt")
end

------------------------------------------------------
-- @function argsrules 保存argsrules的所有规则
function action:black_fileExt_rules()
    return action:saveRule("black_fileExt")
end

------------------------------------------------------
-- @function getCookierules 获取配置cookie的所有规则
function action:get_cookie_rules()
    success("data", rules.cookie_rules)
    return true
end

------------------------------------------------------
-- @function delCookierules 获取配置cookie的所有规则
function action:del_cookie_rules()
    return action:delRule("cookie")
end

------------------------------------------------------
-- @function cookierules 保存cookie的所有规则
function action:cookie_rules()
    return action:saveRule("cookie")
end

------------------------------------------------------
-- @function get_ipBlocklist 获取配置所以ip黑名单项
function action:get_ipBlocklist()
    success("data", ips.ipBlocklist)
    return true
end

------------------------------------------------------
-- @function del_ipBlocklist 删除对应的ip黑名单项
function action:del_ipBlocklist()
    return action:delIP("ipBlocklist")
end

------------------------------------------------------
-- @function ipBlocklist 保存ip黑名单
function action:ipBlocklist()
    return action:saveIP("ipBlocklist")
end

------------------------------------------------------
-- @function get_ipWhitelist 获取配置所以ip白名单项
function action:get_ipWhitelist()
    success("data", ips.ipWhitelist)
    return true
end

------------------------------------------------------
-- @function del_ipWhitelist 删除对应的ip白名单项
function action:del_ipWhitelist()
    return action:delIP("ipWhitelist")
end

------------------------------------------------------
-- @function ipWhitelist 保存ip白名单
function action:ipWhitelist()
    return action:saveIP("ipWhitelist")
end

------------------------------------------------------
-- @function getPostrules 获取配置post的所有规则
function action:get_post_rules()
    success("data", rules.post_rules)
    return true
end

------------------------------------------------------
-- @function delCookierules 获取配置post的所有规则
function action:del_post_rules()
    return action:delRule("post")
end

------------------------------------------------------
-- @function postrules 保存post的所有规则
function action:post_rules()
    return action:saveRule("post")
end

------------------------------------------------------
-- 获取url规则
-- @function getUrlRules 获取url规则
function action:get_url_rules()
    success("data", rules.url_rules)
    return true
end

------------------------------------------------------
-- @function delArgsrules 获取配置url的所有规则
function action:del_url_rules()

    return action:delRule("url")
end

-------------------------------------
-- @function urlrules 保存urlrules
function action:url_rules()
    return action:saveRule("url")
end

------------------------------------------------------
-- 获取url规则
-- @function getUsers 获取用户
function action:get_users()
    success("data", users)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定用户 暂时只使用一个账户
function action:del_users()
    return false
--    return action:del("user")
end

-------------------------------------
-- @function user 保存waf操作用户
function action:users()
    local args = request.getArgs();
    if string.isEmpty(args["name"]) or string.isEmpty(args["pwd"]) then
        error(-1, "用户名或者密码不能为空")
        return true
    end
    local user = args["name"] .. "|" .. args["pwd"];
    io.update("user", user, 1)
    users[0] = user;
    return
end

------------------------------------------------------
-- 获取设备信息规则
-- @function getUarules 获取请求者设备信息(浏览器内核)规则
function action:get_user_agent_rules()
    success("data", rules.user_agent_rules)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定请求者设备信息(浏览器内核)规则
function action:del_user_agent_rules()
    return action:delRule("user_agent")
end

-------------------------------------
-- @function user 保存请求者设备信息(浏览器内核)规则
function action:user_agent_rules()
    return action:saveRule("user_agent")
end

------------------------------------------------------
-- 获取设备信息规则
-- @function getUarules 获取请求者设备信息(浏览器内核)规则
function action:get_whiteurl_rules()
    success("data", rules.whiteurl_rules)
    return true
end

------------------------------------------------------
-- @function delUsers 删除指定请求者设备信息(浏览器内核)规则
function action:del_whiteurl_rules()
    return action:delRule("whiteurl")
end

-------------------------------------
-- @function user 保存请求者设备信息(浏览器内核)规则
function action:whiteurl_rules()
    return action:saveRule("whiteurl")
end


-------------------------------------
-- 保存对应的规则项
-- @function saveIP
-- @param string var 需要操作项的名字
function action:saveIP(var)
    return action:save(var,ips[var], ips)
end

-------------------------------------
-- 保存对应的规则项
-- @function saveRule
-- @param string var 需要操作项的名字
function action:saveRule(var)
    return action:save(var,rules[var .. "_rules"], rules )
end
------------------------------------------
-- 保存对应的项
-- @function save
-- @param string var 需要操作项的名字
-- @param string item 需要操作项
-- @param string items 需要操作项集
function action:save(var, item, items)
    local args = request.getArgs();
    local value = args["value"]
    local id = args["id"]

    if  string.isEmpty(value) then
--        success(var, item)
        error(100101, "参数规则必填")
        return true
    end
    if string.isEmpty(id) then
        if io.add(var, value) then
            success("message", "添加成功")
            table.insert(item, items)
            return true;
        end
        error(100102, "添加失败")
    end
        local i = tonumber(id)
        if type(i) == "number" and io.update(var, value, id) then
            item[i] = value
            success("message", "更新成功")

            return true;
        end
        error(100103, "更新失败")

    return true
end

------------------------------------------------------
-- 删除对应的规则项
-- @function delRule
-- @param string var 需要删除的配置
function action:delRule(var)
    return action:del(var, rules[var .. "_rules"])
end

------------------------------------------------------
-- 删除对应的Ip项
-- @function delIP
-- @param string var 需要删除的配置
function action:delIP(var)
    return action:del(var, ips[var])
end


------------------------------------------------------
-- 删除对应的项
-- @function del
-- @param string var 需要删除的配置
-- @param table item 规则集
function action:del(var, item)
    local id = request.getArgs()["id"]
    if not string.isEmpty(id) and type(tonumber(id)) == "number" then
        io.delete(var, id)
        table.remove(item, id)
        success("message", "删除成功")
    else
        error(-1, "删除失败")
    end

    return true
end


return action
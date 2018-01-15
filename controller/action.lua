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
-- 授权登录
--
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



---------------------------
-- 获取url规则
function action:getUrlrules()
    success("rules", urlrules)
    return true

end

function action:urlrules()

    local args = request.getArgs();
    local rules =  args["rules"]
    success("rules", rules)
    return true

end

---------------------------
-- 获取url规则
function action:getArgsrules()
    success("argsrules", argsrules)
    return true

end

function action:argsrules()

    local args = request.getArgs();
    local argsrules =  args["argsrules"]
    success("argsrules", argsrules)
    return true

end



return action
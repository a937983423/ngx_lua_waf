require 'config'
require 'base.functions'
local actions = (require 'controller.action').new();

local match = string.match
local ngxmatch=ngx.re.match
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect=optionIsOn(Redirect)


function getClientIp()
        IP  = ngx.var.remote_addr
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

function log(method,url,data,ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        if ua  then
            line = realIp.." [".. type(time) .."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." [".. type(time) .."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
--    	say_html(logpath..'/'..servername.."_"..ngx.today().."_sec.log")
     end
end
------------------------------------规则读取函数-------------------------------------------------------------------

rules = {
    args_rules = read_rule('args'),
    cookie_rules = read_rule('cookie'),
    post_rules = read_rule('post'),
    url_rules = read_rule('url'),
    users_rules = read_rule('user'),
    user_agent_rules = read_rule('user_agent'),
    whiteurl_rules = read_rule('whiteurl')
}









function say_html(text)
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        if text == nil then
            ngx.say(html)
        else
            ngx.say("[["..text.."]]")
        end
        ngx.exit(ngx.status)
    end
end


--------------------------------
-- 输出json响应给客户端
-- @function say_json
-- @param String text  数值
local json = require("utils.json")
function say_json(text)

    if Redirect then
        ngx.header.content_type = "application/json;charset=UTF-8"
        ngx.status = ngx.HTTP_OK
        if nil ~= text  then
            local t = type(text);
            if t == "table" or t == "userdata" then
                log('POST',ngx.var.request_uri,"-",  json.encode(text))
                ngx.say(json.encode(text))
            else
                log('POST',ngx.var.request_uri,"-",  t)
                ngx.say(text)
            end
        end
        ngx.exit(ngx.status)
    end
end

function say_upgrade()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = 200

        local times = ngx.now() --ngx.localtime()
        local html1 = string.gsub(upgradeHtml,"{{date}}", times)
        --ngx.say( string.gsub(upgradeHtml,"{{date}}", ngx.localtime()))
        ngx.say( html1)
        --ngx.exit(ngx.status)
    end
end


function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(rules.whiteurl_rules) do
                if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true
                end
            end
        end
    end
    return false
end
function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext,rule,"isjo") then
                log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
                say_html()
            end
        end
    end
    return false
end

function args()
    for _,rule in pairs(rules.args_rules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                local t={}
                for k,v in pairs(val) do
                    if v == true then
                        v=""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(rules.url_rules) do
            local flag, err = ngxmatch(ngx.var.request_uri,rule,"isjo");
            if rule ~="" and flag then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then

        for _,rule in pairs(rules["user_agent_rules"]) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                log('UA',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end
function body(data)
    for _,rule in pairs(rules.post_rules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
            log('POST',ngx.var.request_uri,data,rule)
            say_html()
            return true
        end
    end
    return false
end
function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(rules.cookie_rules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                log('Cookie',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                ngx.exit(503)
                return true
            else
                limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
    return false
end

function blockip()
    if next(ipBlocklist) ~= nil then
        for _,ip in pairs(ipBlocklist) do
            if getClientIp()==ip then
                ngx.exit(403)
                return true
            end
        end
    end
    return false
end




function upgrade()
    --[[say_html(ngx.var.request_uri)
    return true
--]]
    if ngx.var.request_uri == "/isUpgrade=true" then
        isUpgrade = true;
    elseif ngx.var.request_uri == "/isUpgrade=false" then
        isUpgrade = false;
        say_html("Set up the success ")
        return true
    end
    local receive_headers = ngx.req.get_headers()
    local host_ = receive_headers["Host"]
    if ("zzs.huodull.com" == host_ ) and isUpgrade then
        say_upgrade()
        return true

    end
    return false

end
---
-- @function: 打印table的内容，递归
-- @param: tbl 要打印的table
-- @param: level 递归的层数，默认不用传值进来
-- @param: filteDefault 是否过滤打印构造函数，默认为是
-- @return: return
function PrintTable( tbl , level, filteDefault)
    local msg = ""
    filteDefault = filteDefault or true --默认过滤关键字（DeleteMe, _class_type）
    level = level or 1
    local indent_str = ""
    for i = 1, level do
        indent_str = indent_str.."  "
    end
    log(' ',"","-",indent_str .. "{")
    for k,v in pairs(tbl) do
        if filteDefault then
            if k ~= "_class_type" and k ~= "DeleteMe" then
                local item_str = string.format("%s%s = %s", indent_str .. " ",tostring(k), tostring(v))
                log(' ',"","-",item_str)
                if type(v) == "table" then
                    PrintTable(v, level + 1)
                end
            end
        else
            local item_str = string.format("%s%s = %s", indent_str .. " ",tostring(k), tostring(v))
            log(' ',"","-",item_str)
            if type(v) == "table" then
                PrintTable(v, level + 1)
            end
        end
    end
    log(' ',"","-",indent_str .. "}")
end
----------------------
-- 防火墙相关过滤器

function waf()
    local action = string.sub(ngx.var.document_uri, 2)
    if actions[action] then
        actions[action]()
        return true
    end
    return false
end
--------------------------------
-- @param string var 配置文件名称
function getConfFile(var)
    return RulePath .. "/"..var;
end



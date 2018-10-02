-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

--[[
# Heka Alert IDRouter Lookup Module

idrouter provides identifier specific alert routing. It is intended to be used as a
lookup module in the Heka alert module.

The configuration of this module is used to control how alerts are routed.

The subjects configuration contains any user specific alerting parameters. Each entry
within subjects should be a key, which represents the standardized user identity string, and
a table containing configuration parameters.

At the least, each subjects entry should contain a mapfrom parameter. This is used to locate
the correct subject entry using the lookup data subject string. Where the lookup data subject
string matches an entry in mapfrom, this identity configuration will be used for the alert.

email and IRC alerts are currently supported. For each type, three categories exist.

Direct notification is used to determine how to route the alert directly to the user, and will
be used if senduser is set to true in lookup data.

Global notification is used when sendglobal is set to true in the lookup data.

Error notification is used when senderror is set to true in the lookup data.

A catchall setting can be set for each category for both IRC and email alerts. If the subject
entry does not specify a given category setting, the catchall will be used for the alert.

If lookup data is specified that does not contain a subject entry or does not match any known
subject, no direct alerts can be generated for the user -- however global and error alerts
may still fire depending on the lookup data settings.

Format strings are supported in a given category notification string. If %s is present in the
string value, the users standardized identity will be used in its place in the resulting
destination. If not specified, the string is used literally.

## Sample Configuration
```lua
alert = {
    lookup = "idrouter",
    modules = {
        idrouter = {
            subjects = {
                riker =  {
                    mapfrom = { "riker", "commanderriker" },
                },
                picard =  {
                    mapfrom = { "picard", "teaearlgreyhot" },
                    email = {
                        direct = "jean-luc@uss-enterprise"
                    }
                },
            },
            email = {
                direct = "manatee-%s@moz-svc-ops.pagerduty.com",
                global = "foxsec-dump+OutOfHours@mozilla.com"
            },
            irc = {
                global = "irc.server#target"
            }
        }
    }
}
```
--]]

local string    = require "string"
local table     = require "table"
local lustache  = require "lustache"

local module_name   = ...
local module_cfg    = require "string".gsub(module_name, "%.", "_")
local cfg           = read_config(module_cfg) or error(module_cfg .. " configuration not found")

local pairs     = pairs
local ipairs    = ipairs
local error     = error
local type      = type

-- XXX
local print = print
local jenc = require "cjson".encode

local M = {}
setfenv(1, M)

if cfg.subjects then
    for k,v in pairs(cfg.subjects) do
        if not v.mapfrom then error("subjects entry missing mapfrom") end
        if v.mapfrom then
            local nm = {}
            for i,w in ipairs(v.mapfrom) do
                nm[w] = true
            end
            v.mapfrom = nm
        end
    end
end


local function alert_template()
    return {
        Type        = "alert",
        Payload     = nil,
        Severity    = 1,

        Fields = {
            {name = "id", value = nil},
            {name = "summary", value = nil}
        }
    }
end


local function vdestfmt(v, t, s)
    if not v then return nil end
    if t == "email" then v = string.format("<%s>", v) end
    if string.find(v, "%%s") then
        if not s then return nil end
        v = string.format(v, s)
    end
    return v
end


function atypes(adata, template)
    local notifytypes = {"email", "irc"}
    local subjcfg
    if adata.subject then subjcfg = cfg.subjects[adata.subject] end

    local ret = {}

    for _,v in ipairs(notifytypes) do
        ret[v] = {}
        if subjcfg and subjcfg[v] then
            if subjcfg[v].templates and subjcfg[v].templates[template] then
                ret[v].summary = subjcfg[v].templates[template].summary
                ret[v].body = subjcfg[v].templates[template].body
            end
            ret[v].direct = vdestfmt(subcfg[v].direct, v, adata.subject)
            ret[v].global = vdestfmt(subcfg[v].global, v, adata.subject)
            ret[v].error = vdestfmt(subcfg[v].error, v, adata.subject)
        end
        if cfg[v] then
            if not ret[v].summary then
                if cfg[v].templates and cfg[v].templates[template] then
                    ret[v].summary = cfg[v].templates[template].summary
                    ret[v].body = cfg[v].templates[template].body
                end
            end
            if not ret[v].direct then ret[v].direct = vdestfmt(cfg[v].direct, v, adata.subject) end
            if not ret[v].global then ret[v].global = vdestfmt(cfg[v].global, v, adata.subject) end
            if not ret[v].error then ret[v].error = vdestfmt(cfg[v].error, v, adata.subject) end
        end
    end

    return ret
end


function atypes_resolve(adata, a)
    local ret = {}
    for k,v in pairs(a) do
        local nent = {dest = {}}
        if adata.notify_global then table.insert(nent.dest, v.global) end
        if adata.notify_direct then table.insert(nent.dest, v.direct) end
        if adata.notify_error then table.insert(nent.dest, v.error) end
        nent.summary = v.summary
        nent.body = v.body
        if #nent.dest > 0 then ret[k] = nent end
    end
    return ret
end


function get_alerts(adata, template)
    local ret = {}

    for i,v in ipairs(adata) do
        local a = atypes_resolve(v, atypes(v, template))

        for k,w in pairs(a) do
            if not w.summary then return nil, "no resolved summary for alert" end
            local summary = lustache:render(w.summary, v.parameters)
            if type(summary) ~= "string" then return nil, "template rendering failed for summary" end

            if not w.body then return nil, "no resolved body for alert" end
            local body = lustache:render(w.body, v.parameters)
            if type(body) ~= "string" then return nil, "template rendering failed for body" end

            local newa = alert_template()
            if k == "email" then -- special handling for email, can support multiple destinations
                newa.Fields[1].value = summary
                newa.Fields[2].value = summary
                newa.Fields[3] = {name = "email.recipients", value = w.dest}
                newa.Payload = body
            else
            end
            table.insert(ret, newa)
        end
    end

    return ret
end

return M

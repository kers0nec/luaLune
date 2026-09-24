function wrapWithAntiTamper(source) {
  return `return (function(...)
local __ll_type,__ll_typeof,__ll_pcall,__ll_error,__ll_tostring=type,typeof,pcall,error,tostring
local __ll_game=game
local function __ll_verify()
  if type~=__ll_type or typeof~=__ll_typeof or pcall~=__ll_pcall or tostring~=__ll_tostring then return false end
  if __ll_type(__ll_type)~="function" or __ll_type(__ll_pcall)~="function" then return false end
  if __ll_game==nil or __ll_typeof(__ll_game)~="Instance" then return false end
  local marker="LL_"..__ll_tostring(math.random(100000,999999))
  local caught,message=__ll_pcall(function() __ll_error(marker,0) end)
  if caught or not message or not string.find(__ll_tostring(message),marker,1,true) then return false end
  local ok,players=__ll_pcall(function() return __ll_game:GetService("Players") end)
  if not ok or players==nil or __ll_typeof(players)~="Instance" then return false end
  return true
end
if not __ll_verify() then return end
local __ll_result=(function(...)
${source}
end)(...)
if not __ll_verify() then return end
return __ll_result
end)(...)`;
}
module.exports={wrapWithAntiTamper};
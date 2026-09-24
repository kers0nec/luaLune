const fs = require('fs');
const path = require('path');
const { LuaFactory } = require('wasmoon');
const { wrapWithAntiTamper } = require('./anti-tamper');

const ROOT = path.join(__dirname, 'vendor', 'prometheus', 'src');
let factoryPromise;
function luaFiles(dir) {
  const result=[];
  for (const name of fs.readdirSync(dir)) {
    const file=path.join(dir,name), stat=fs.statSync(file);
    if (stat.isDirectory()) result.push(...luaFiles(file));
    else if (name.endsWith('.lua')) result.push(file);
  }
  return result;
}
async function factory() {
  if (!factoryPromise) factoryPromise=(async()=>{
    if(!fs.existsSync(ROOT)) throw new Error('LuaLune Obfuscator engine is missing.');
    const instance=new LuaFactory();
    for(const file of luaFiles(ROOT)) {
      const relative=path.relative(ROOT,file).replace(/\/g,'/');
      await instance.mountFile('/prometheus/'+relative,fs.readFileSync(file));
    }
    return instance;
  })();
  return factoryPromise;
}
const PROFILE_MAP={minify:'Minify',weak:'Weak',medium:'Medium',strong:'Strong',light:'Weak',balanced:'Medium',heavy:'Strong',maximum:'Strong'};
async function obfuscate(source,{preset='medium',antiTamper=true}={}) {
  source=String(source||'');
  const profile=PROFILE_MAP[String(preset).toLowerCase()]||'Medium';
  if(!source.trim()) throw new Error('Lua source cannot be empty.');
  if(Buffer.byteLength(source)>500_000) throw new Error('Source exceeds the 500 KB local obfuscation limit.');
  if(antiTamper) source=wrapWithAntiTamper(source);
  const lua=await (await factory()).createEngine();
  try {
    lua.global.set('LUALUNE_SOURCE',source); lua.global.set('LUALUNE_PROFILE',profile); lua.global.set('LUALUNE_ANTITAMPER',!!antiTamper);
    const result=await lua.doString(`
      arg = {}; math.log10 = math.log10 or function(value) return math.log(value, 10) end
      unpack = unpack or table.unpack; loadstring = loadstring or load
      package.path = '/prometheus/?.lua;/prometheus/?/init.lua;' .. package.path
      local Prometheus = require('prometheus')
      Prometheus.Logger.logLevel = Prometheus.Logger.LogLevel.Error
      Prometheus.Logger.errorCallback = function(message) error(message, 0) end
      local config = Prometheus.Presets[LUALUNE_PROFILE]; config.LuaVersion='LuaU'; config.Seed=os.time()+math.random(1,1000000)
      if LUALUNE_ANTITAMPER then
        local found=false; for _,step in ipairs(config.Steps or {}) do if step.Name=='AntiTamper' then found=true break end end
        if not found then table.insert(config.Steps,1,{Name='AntiTamper',Settings={UseDebug=false}}) end
      else
        local filtered={}; for _,step in ipairs(config.Steps or {}) do if step.Name~='AntiTamper' then filtered[#filtered+1]=step end end; config.Steps=filtered
      end
      local pipeline=Prometheus.Pipeline:fromConfig(config); return pipeline:apply(LUALUNE_SOURCE,'LuaLune')
    `);
    if(!result||!String(result).trim()) throw new Error('engine returned empty output');
    return '-- Protected by LuaLune Obfuscator\n'+result;
  } catch(error) { throw new Error('LuaLune obfuscation failed: '+(error.message||error)); }
  finally { lua.global.close(); }
}
module.exports={obfuscate,profiles:['minify','weak','medium','strong']};
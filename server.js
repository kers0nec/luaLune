import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createClient} from "@supabase/supabase-js";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
app.use(express.json({limit:"1mb"}));

const SUPABASE_URL=process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY=process.env.SUPABASE_ANON_KEY;
if(!SUPABASE_URL||!SUPABASE_ANON_KEY) console.warn("Set SUPABASE_URL and SUPABASE_ANON_KEY in Render environment variables.");

function sb(token){
  return createClient(SUPABASE_URL||"http://localhost",SUPABASE_ANON_KEY||"missing",{
    global:{headers:token?{Authorization:"Bearer "+token}:{}},
    auth:{persistSession:false,autoRefreshToken:false}
  });
}
function emailFor(email){ return String(email||"").trim().toLowerCase(); }
async function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Authentication required"});
  const token=h.slice(7), client=sb(token);
  const {data,error}=await client.auth.getUser(token);
  if(error||!data.user) return res.status(401).json({error:"Session expired"});
  req.sb=client; req.user=data.user; next();
}

function obfuscate(source,strength="strong"){
  const k1=crypto.randomBytes(16), k2=crypto.randomBytes(16);
  const input=Buffer.from(source,"utf8"), out=Buffer.alloc(input.length);
  for(let i=0;i<input.length;i++){
    let v=input[i]^k1[i%k1.length]^((i*31)&255);
    if(strength==="strong") v=v^k2[i%k2.length]^((i*17+73)&255);
    out[i]=v;
  }
  return {key:k1.toString("hex")+":"+k2.toString("hex"),payload:out.toString("hex")};
}
function loader(payload,key){
  return `-- LuaLune protected build
local __p="${payload}"
local __keys="${key}"
local __a,__b=__keys:match("([^:]+):([^:]+)")
local __o={}
for __i=1,#__p,2 do
  local __n=(__i+1)/2
  local __v=tonumber(__p:sub(__i,__i+1),16)
  local __k1=tonumber(__a:sub(((__n-1)%16)*2+1,((__n-1)%16)*2+2),16)
  local __k2=tonumber(__b:sub(((__n-1)%16)*2+1,((__n-1)%16)*2+2),16)
  if __b then __v=bit32.bxor(__v,(__n-1)*31%256,__k1,__k2,(__n-1)*17%256,73) else __v=bit32.bxor(__v,__keys:byte((__n-1)%#__keys+1)) end
  __o[#__o+1]=string.char(__v)
end
local __fn=loadstring(table.concat(__o))
if not __fn then error("LuaLune: invalid protected build") end
return __fn()
`;
}

app.get("/healthz",(_,res)=>res.type("text").send("LuaLune API OK\n"));

app.post("/api/auth/signup",async(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  const password=String(req.body?.password||"");
  const username=String(req.body?.username||"").trim();
  if(!email.includes("@")) return res.status(400).json({error:"Enter a valid email address."});
  if(password.length<8) return res.status(400).json({error:"Password must be at least 8 characters."});
  const {data,error}=await sb().auth.signUp({email,password,options:{data:{username:username||email.split("@")[0]}}});
  if(error) return res.status(400).json({error:error.message});
  res.status(201).json({user:data.user,session:data.session,needsConfirmation:!data.session});
});

app.post("/api/auth/login",async(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  const password=String(req.body?.password||"");
  if(!email||!password) return res.status(400).json({error:"Email and password are required."});
  const {data,error}=await sb().auth.signInWithPassword({email,password});
  if(error) return res.status(401).json({error:"Invalid email or password."});
  res.json({user:data.user,session:data.session});
});

app.get("/api/auth/me",auth,(req,res)=>res.json({user:req.user}));

app.post("/api/auth/logout",auth,async(req,res)=>{
  await req.sb.auth.signOut();
  res.status(204).end();
});

app.get("/api/scripts",auth,async(req,res)=>{
  const {data,error}=await req.sb.from("scripts").select("id,name,created_at,updated_at,public").eq("owner_id",req.user.id).order("created_at",{ascending:false});
  if(error) return res.status(500).json({error:error.message});
  res.json({scripts:data||[]});
});

app.post("/api/scripts",auth,async(req,res)=>{
  const name=String(req.body?.name||"").trim();
  const source=String(req.body?.source||"");
  const strength=req.body?.strength==="light"?"light":"strong";
  if(name.length<1||name.length>80) return res.status(400).json({error:"Name must be 1-80 characters."});
  if(source.length<1||source.length>500000) return res.status(400).json({error:"Script must be 1-500,000 characters."});
  const {key,payload}=obfuscate(source,strength);
  const {data,error}=await req.sb.from("scripts").insert({owner_id:req.user.id,name,payload,secret_key:key,public:true}).select("id,name,created_at,updated_at,public").single();
  if(error) return res.status(500).json({error:error.message});
  const loaderUrl=req.protocol+"://"+req.get("host")+"/loader/"+data.id;
  res.status(201).json({script:data,loader:"loadstring(game:HttpGet("+JSON.stringify(loaderUrl)+"))()"});
});

app.delete("/api/scripts/:id",auth,async(req,res)=>{
  const {error}=await req.sb.from("scripts").delete().eq("id",req.params.id).eq("owner_id",req.user.id);
  if(error) return res.status(500).json({error:error.message});
  res.status(204).end();
});

app.get("/loader/:id",async(req,res)=>{
  const {data,error}=await sb().from("scripts").select("payload,secret_key").eq("id",req.params.id).eq("public",true).single();
  if(error||!data) return res.status(404).type("text/plain").send("-- LuaLune: script not found");
  res.type("text/plain").send(loader(data.payload,data.secret_key));
});

app.use(express.static(__dirname));
app.get(/.*/,(req,res)=>{
  if(req.path.startsWith("/api/")||req.path.startsWith("/loader/")) return res.status(404).end();
  res.sendFile(path.join(__dirname,"index.html"));
});

const port=Number(process.env.PORT||10000);
app.listen(port,()=>console.log("LuaLune listening on "+port));

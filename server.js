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

function obfuscate(source){
  const key=crypto.randomBytes(12).toString("hex");
  const input=Buffer.from(source,"utf8"), k=Buffer.from(key), out=Buffer.alloc(input.length);
  for(let i=0;i<input.length;i++) out[i]=input[i]^k[i%k.length];
  return {key,payload:out.toString("hex")};
}
function loader(payload,key){
  return `-- LuaLune protected loader
local __p="${payload}"
local __k="${key}"
local __o={}
for __i=1,#__p,2 do
  local __b=tonumber(__p:sub(__i,__i+1),16)
  local __kp=(((__i-1)/2)%#__k)+1
  __o[#__o+1]=string.char(bit32.bxor(__b,__k:byte(__kp)))
end
local __src=table.concat(__o)
local __fn=loadstring(__src)
if not __fn then error("LuaLune: payload failed to decode") end
return __fn()
`;
}

app.get("/healthz",(_,res)=>res.type("text").send("LuaLune API OK\n"));

app.post("/api/auth/signup",async(req,res)=>{
  const username=String(req.body?.username||"").trim();
  const password=String(req.body?.password||"");
  if(!/^[a-zA-Z0-9._-]{3,24}$/.test(username)) return res.status(400).json({error:"Username must be 3-24 letters, numbers, dots, underscores or hyphens."});
  if(password.length<8) return res.status(400).json({error:"Password must be at least 8 characters."});
  const {data,error}=await sb().auth.signUp({email:emailFor(username),password,options:{data:{username}}});
  if(error) return res.status(400).json({error:error.message});
  res.status(201).json({user:data.user,session:data.session,needsConfirmation:!data.session});
});

app.post("/api/auth/login",async(req,res)=>{
  const username=String(req.body?.username||"").trim();
  const password=String(req.body?.password||"");
  if(!username||!password) return res.status(400).json({error:"Username and password are required."});
  const {data,error}=await sb().auth.signInWithPassword({email:emailFor(username),password});
  if(error) return res.status(401).json({error:"Invalid username or password."});
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
  if(name.length<1||name.length>80) return res.status(400).json({error:"Name must be 1-80 characters."});
  if(source.length<1||source.length>500000) return res.status(400).json({error:"Script must be 1-500,000 characters."});
  const {key,payload}=obfuscate(source);
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

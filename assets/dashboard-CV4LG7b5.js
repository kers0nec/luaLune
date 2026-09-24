import{j as w,r as O,s as Us}from"./index-BRXufwOW.js";
function component(){
 const [user,setUser]=O.useState(null);
 O.useEffect(()=>{Us.auth.getUser().then(({data})=>setUser(data.user||null))},[]);
 const out=async()=>{await Us.auth.signOut();location.href="/login"};
 return w.jsxs("main",{className:"min-h-screen p-6 sm:p-10",children:[
  w.jsxs("header",{className:"mx-auto flex max-w-5xl items-center justify-between rounded-2xl border border-border bg-card/70 p-5 backdrop-blur",children:[
   w.jsx("h1",{className:"text-xl font-semibold text-primary",children:"LuaLune"}),
   w.jsxs("div",{className:"flex items-center gap-3",children:[
    w.jsx("span",{className:"text-sm text-muted-foreground",children:user?.user_metadata?.username||"Account"}),
    w.jsx("button",{onClick:out,className:"rounded-lg border border-border px-3 py-2 text-sm",children:"Sign out"})
   ]})
  ]}),
  w.jsxs("section",{className:"mx-auto mt-6 max-w-5xl rounded-2xl border border-border bg-card/70 p-8",children:[
   w.jsx("h2",{className:"text-3xl font-bold text-primary",children:"Dashboard"}),
   w.jsx("p",{className:"mt-2 text-muted-foreground",children:"Your LuaLune account is active."}),
   w.jsxs("div",{className:"mt-6 flex flex-wrap gap-3",children:[
    w.jsx("a",{href:"/dashboard",className:"rounded-lg border border-border px-4 py-2",children:"Dashboard"}),
    w.jsx("a",{href:"/dashboard/plans",className:"rounded-lg border border-border px-4 py-2",children:"Plans"}),
    w.jsx("a",{href:"/",className:"rounded-lg border border-border px-4 py-2",children:"Home"})
   ]})
  ]})
 ]});
}
export{component};
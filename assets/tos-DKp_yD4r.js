import{j as e,r as R,m as auth}from"./index-BRXufwOW.js";
function component(){
  const[path,setPath]=R.useState(window.location.pathname);
  const[user,setUser]=R.useState(null);
  R.useEffect(()=>{auth.auth.getUser().then(({data})=>setUser(data.user||null));},[]);
  const signOut=async()=>{await auth.auth.signOut();window.location.href="/login"};
  if(path==="/tos")return e.jsxs("main",{className:"min-h-screen p-8",children:[e.jsx("h1",{className:"text-3xl font-bold text-primary",children:"LuaLune Terms of Service"}),e.jsx("p",{className:"mt-4 max-w-2xl text-muted-foreground",children:"Use LuaLune responsibly and only with scripts and content you are authorized to use."})]});
  if(path==="/bot")return e.jsxs("main",{className:"min-h-screen p-8",children:[e.jsx("h1",{className:"text-3xl font-bold text-primary",children:"LuaLune"}),e.jsx("p",{className:"mt-4 text-muted-foreground",children:"This feature is currently unavailable."})]});
  return e.jsxs("main",{className:"min-h-screen p-6 sm:p-10",children:[
    e.jsxs("header",{className:"mx-auto flex max-w-5xl items-center justify-between rounded-2xl border border-border bg-card/70 p-5 backdrop-blur",children:[
      e.jsx("div",{children:e.jsx("h1",{className:"text-xl font-semibold text-primary",children:"LuaLune Dashboard"})}),
      e.jsxs("div",{className:"flex items-center gap-3",children:[
        e.jsx("span",{className:"text-sm text-muted-foreground",children:user?.user_metadata?.username||user?.email||"Account"}),
        e.jsx("button",{onClick:signOut,className:"rounded-lg border border-border px-3 py-2 text-sm hover:bg-muted",children:"Sign out"})
      ]})
    ]}),
    e.jsxs("section",{className:"mx-auto mt-6 max-w-5xl rounded-2xl border border-border bg-card/70 p-6 shadow-card backdrop-blur",children:[
      e.jsx("h2",{className:"text-2xl font-semibold",children:"Your workspace"}),
      e.jsx("p",{className:"mt-2 text-sm text-muted-foreground",children:"Your authenticated LuaLune session is active. The dashboard assets have been restored so deployments no longer fail on missing Vite chunks."}),
      e.jsxs("div",{className:"mt-6 grid gap-4 sm:grid-cols-3",children:[
        e.jsx("a",{href:"/dashboard",className:"rounded-xl border border-border p-5 hover:border-primary",children:e.jsx("b",{children:"Dashboard"})}),
        e.jsx("a",{href:"/dashboard/plans",className:"rounded-xl border border-border p-5 hover:border-primary",children:e.jsx("b",{children:"Plans"})}),
        e.jsx("a",{href:"/",className:"rounded-xl border border-border p-5 hover:border-primary",children:e.jsx("b",{children:"Home"})})
      ]})
    ]})
  ]});
}
export{component};

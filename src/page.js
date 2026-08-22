export const LOGIN_HTML = `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0A1024">
<title>DeskSuite</title>
<style>
  :root{--bg:#0A1024;--bg2:#0e1630;--card:#111c3a;--line:#2A3A5C;--gold:#C9A961;--gold2:#e3c986;--txt:#eaf0ff;--muted:#9fb0d6;--red:#e0736b;--green:#5fb98a}
  *{box-sizing:border-box}
  body{margin:0;min-height:100dvh;background:radial-gradient(1200px 600px at 50% -10%,#16224a 0%,var(--bg) 55%);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
  .wrap{width:100%;max-width:400px}
  .brand{text-align:center;margin-bottom:26px}
  .mono{width:74px;height:74px;border-radius:18px;margin:0 auto 14px;background:linear-gradient(145deg,#0A1024,#18243F);border:1px solid var(--line);display:flex;align-items:center;justify-content:center;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  .mono b{font-family:"Bodoni 72","Didot",Georgia,serif;font-size:34px;font-weight:700;background:linear-gradient(160deg,#f2f6ff 0%,#cdd8f2 40%,var(--gold) 41%,var(--gold2) 100%);-webkit-background-clip:text;background-clip:text;color:transparent;letter-spacing:1px}
  .brand h1{font-family:"Bodoni 72","Didot",Georgia,serif;font-weight:600;font-size:26px;margin:0;letter-spacing:.5px}
  .brand p{color:var(--muted);font-size:13px;margin:6px 0 0}
  .card{background:linear-gradient(180deg,var(--card),#0f1830);border:1px solid var(--line);border-radius:20px;padding:22px;box-shadow:0 20px 50px rgba(0,0,0,.45)}
  label{display:block;font-size:12px;color:var(--muted);margin:14px 0 6px}
  input{width:100%;padding:13px 14px;border-radius:12px;border:1px solid var(--line);background:#0b1330;color:var(--txt);font-size:16px;outline:none}
  input:focus{border-color:var(--gold)}
  button{width:100%;border:none;border-radius:12px;padding:14px;font-size:15px;font-weight:600;cursor:pointer;margin-top:16px}
  .primary{background:linear-gradient(135deg,var(--gold),var(--gold2));color:#241c05}
  .ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
  .link{background:none;border:none;color:var(--muted);font-size:13px;width:auto;margin:14px auto 0;display:block;text-decoration:underline;cursor:pointer;padding:0}
  .sep{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:12px;margin:18px 0 4px}
  .sep::before,.sep::after{content:"";height:1px;background:var(--line);flex:1}
  .msg{margin-top:14px;font-size:13px;text-align:center;min-height:18px}
  .msg.err{color:var(--red)} .msg.ok{color:var(--green)}
  .hide{display:none}
  .rec{background:#0b1330;border:1px dashed var(--gold);border-radius:12px;padding:14px;margin-top:14px;text-align:center}
  .rec code{font-family:"IBM Plex Mono",ui-monospace,Menlo,monospace;font-size:15px;letter-spacing:1px;color:var(--gold2);word-break:break-all}
  .apps{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px}
  .apps a{display:block;padding:13px 12px;border:1px solid var(--line);border-radius:12px;background:#0b1330;color:var(--txt);text-decoration:none;font-size:14px;text-align:center}
  .apps a:active{border-color:var(--gold)}
  .who{color:var(--muted);font-size:13px;text-align:center;margin-top:4px}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <div class="mono"><b>DS</b></div>
    <h1>DeskSuite</h1>
    <p id="tag">Accesso unico</p>
  </div>
  <div class="card" id="card"><div class="msg" id="boot">…</div></div>
</div>
<script>
const $=id=>document.getElementById(id);
const card=$('card');
// ---- base64url <-> ArrayBuffer ----
const b64uToBuf=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const b=atob(s);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer;};
const bufToB64u=b=>{const u=new Uint8Array(b);let s='';for(let i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');};
const api=(p,body)=>fetch(p,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});

function say(el,txt,ok){el.className='msg '+(ok?'ok':'err');el.textContent=txt;}

// ---------- WebAuthn browser ----------
async function passkeyLogin(msgEl){
  try{
    const o=await (await api('/passkey/login/options')).json();
    if(o.error){say(msgEl,o.error);return;}
    o.challenge=b64uToBuf(o.challenge);
    (o.allowCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));
    const cred=await navigator.credentials.get({publicKey:o});
    const r={id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,
      response:{authenticatorData:bufToB64u(cred.response.authenticatorData),
        clientDataJSON:bufToB64u(cred.response.clientDataJSON),
        signature:bufToB64u(cred.response.signature),
        userHandle:cred.response.userHandle?bufToB64u(cred.response.userHandle):undefined},
      clientExtensionResults:cred.getClientExtensionResults()};
    const v=await (await api('/passkey/login/verify',{response:r})).json();
    if(v.ok){location.reload();}else{say(msgEl,v.error||'Accesso fallito.');}
  }catch(e){say(msgEl,'Passkey annullata o non disponibile.');}
}
async function passkeyRegister(msgEl){
  try{
    const o=await (await api('/passkey/register/options')).json();
    if(o.error){say(msgEl,o.error);return;}
    o.challenge=b64uToBuf(o.challenge);
    o.user.id=b64uToBuf(o.user.id);
    (o.excludeCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));
    const cred=await navigator.credentials.create({publicKey:o});
    const r={id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,
      response:{attestationObject:bufToB64u(cred.response.attestationObject),
        clientDataJSON:bufToB64u(cred.response.clientDataJSON),
        transports:cred.response.getTransports?cred.response.getTransports():[]},
      clientExtensionResults:cred.getClientExtensionResults()};
    const label=/iPhone|iPad/.test(navigator.userAgent)?'iPhone':(/Mac/.test(navigator.userAgent)?'Mac':'Dispositivo');
    const v=await (await api('/passkey/register/verify',{response:r,label})).json();
    if(v.ok){say(msgEl,'Passkey registrata su questo '+label+'.',true);}else{say(msgEl,v.error||'Registrazione fallita.');}
  }catch(e){say(msgEl,'Registrazione passkey annullata.');}
}

// ---------- viste ----------
function viewSetup(){
  $('tag').textContent='Primo accesso — crea il tuo account';
  card.innerHTML=\`
    <label>Email</label><input id="em" type="email" autocomplete="username" placeholder="giovanni.fasciano@me.com">
    <label>Password (min 12 caratteri)</label><input id="pw" type="password" autocomplete="new-password">
    <label>Ripeti password</label><input id="pw2" type="password" autocomplete="new-password">
    <button class="primary" id="go">Crea account</button>
    <div class="msg" id="m"></div>\`;
  $('go').onclick=async()=>{
    const email=$('em').value.trim(),pw=$('pw').value,pw2=$('pw2').value;
    if(pw!==pw2){say($('m'),'Le due password non coincidono.');return;}
    const v=await (await api('/register',{email,password:pw})).json();
    if(v.ok){viewRecovery(v.recovery);}else{say($('m'),v.error||'Errore.');}
  };
}
function viewRecovery(code){
  $('tag').textContent='Salva il codice di recupero';
  card.innerHTML=\`
    <p style="color:var(--muted);font-size:14px;margin:0 0 4px">Conservalo offline. È l'unico modo per rientrare se perdi passkey e password. Non verrà mostrato di nuovo.</p>
    <div class="rec"><code>\${code}</code></div>
    <button class="primary" id="ok">L'ho salvato, continua</button>\`;
  $('ok').onclick=()=>location.reload();
}
function viewLogin(hasPasskey){
  $('tag').textContent='Accesso unico';
  card.innerHTML=\`
    \${hasPasskey?'<button class="primary" id="pk">Entra con FaceID / Touch ID</button><div class="sep">oppure</div>':''}
    <label>Email</label><input id="em" type="email" autocomplete="username">
    <label>Password</label><input id="pw" type="password" autocomplete="current-password">
    <button class="\${hasPasskey?'ghost':'primary'}" id="go">Entra</button>
    <button class="link" id="rl">Ho un codice di recupero</button>
    <div class="msg" id="m"></div>\`;
  if(hasPasskey)$('pk').onclick=()=>passkeyLogin($('m'));
  $('go').onclick=async()=>{
    const v=await (await api('/login',{email:$('em').value.trim(),password:$('pw').value})).json();
    if(v.ok){location.reload();}else{say($('m'),v.error||'Errore.');}
  };
  $('pw').onkeydown=e=>{if(e.key==='Enter')$('go').click();};
  $('rl').onclick=viewRecover;
}
function viewRecover(){
  $('tag').textContent='Recupero accesso';
  card.innerHTML=\`
    <label>Codice di recupero</label><input id="code" placeholder="ABCD-EFGH-JKMN-PQRS-TUVW-XYZ2">
    <label>Nuova password (facoltativa)</label><input id="np" type="password" autocomplete="new-password">
    <button class="primary" id="go">Rientra</button>
    <button class="link" id="bk">Torna al login</button>
    <div class="msg" id="m"></div>\`;
  $('go').onclick=async()=>{
    const v=await (await api('/recover',{code:$('code').value.trim(),newPassword:$('np').value||undefined})).json();
    if(v.ok){location.reload();}else{say($('m'),v.error||'Errore.');}
  };
  $('bk').onclick=()=>location.reload();
}
function viewHome(email){
  $('tag').textContent='Sei dentro';
  card.innerHTML=\`
    <p class="who">Connesso come \${email}</p>
    <div class="apps">
      <a href="https://watchdesk.desksuite.cloud">WatchDesk</a>
      <a href="https://financedesk.desksuite.cloud">FinanceDesk</a>
      <a href="https://incomingorders.desksuite.cloud">Ordini in arrivo</a>
      <a href="https://ppcatalogue.desksuite.cloud">Patek</a>
      <a href="https://apcatalogue.desksuite.cloud">Audemars Piguet</a>
      <a href="https://owcatalogue.desksuite.cloud">OW Scanner</a>
    </div>
    <button class="ghost" id="addpk">Aggiungi passkey su questo dispositivo</button>
    <button class="link" id="out">Esci</button>
    <div class="msg" id="m"></div>\`;
  $('addpk').onclick=()=>passkeyRegister($('m'));
  $('out').onclick=async()=>{await api('/logout');location.reload();};
}

// ---------- avvio ----------
(async()=>{
  try{
    const s=await (await fetch('/me',{credentials:'include'})).json();
    if(s.authenticated){viewHome(s.email);}
    else if(!s.hasAccount){viewSetup();}
    else{viewLogin(s.hasPasskey);}
  }catch(e){card.innerHTML='<div class="msg err">Servizio non raggiungibile.</div>';}
})();
</script>
</body>
</html>`;

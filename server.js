// ALANGAR – storefront + secure admin backend (Node 18+, Express 4)
require('dotenv').config();
const express = require('express'), session = require('express-session'), bcrypt = require('bcryptjs'), multer = require('multer');
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const prod = process.env.NODE_ENV === 'production';

// ---------- storage (JSON files; swap for a real DB later) ----------
const DATA = path.join(__dirname, 'data'); fs.mkdirSync(DATA, { recursive: true });
const UPLOADS = path.join(__dirname, 'public', 'uploads'); fs.mkdirSync(UPLOADS, { recursive: true });
const rd = (n, d) => { try { return JSON.parse(fs.readFileSync(path.join(DATA, n + '.json'))); } catch { return d; } };
const wr = (n, v) => fs.writeFileSync(path.join(DATA, n + '.json'), JSON.stringify(v, null, 1));
const COLS = ['products', 'categories', 'sections', 'banners', 'offers', 'coupons', 'orders', 'customers', 'wholesale', 'reviews', 'settings'];
const db = rd('db', {}); COLS.forEach(c => db[c] = db[c] || []);
const logs = rd('log', []);
const save = () => wr('db', db);

// ---------- secrets: only ever read on the server ----------
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET (32+ chars) required');
let A = rd('admin', null); // persisted admin account (hash only)
if (!A) {
  const hash = process.env.ADMIN_PASSWORD_HASH || (process.env.ADMIN_PASSWORD && bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12));
  if (!process.env.ADMIN_USER_ID || !hash) throw new Error('Set ADMIN_USER_ID and ADMIN_PASSWORD or ADMIN_PASSWORD_HASH');
  A = { id: process.env.ADMIN_USER_ID, hash, ver: 1, created: new Date().toISOString(), last: null }; wr('admin', A);
}
// Recovery secret lives only in server env; it is never persisted or changeable from the dashboard.
const RH = process.env.ADMIN_RECOVERY_PASSWORD_HASH || (process.env.ADMIN_RECOVERY_PASSWORD && bcrypt.hashSync(process.env.ADMIN_RECOVERY_PASSWORD, 12));
if (!RH) throw new Error('Set ADMIN_RECOVERY_PASSWORD or ADMIN_RECOVERY_PASSWORD_HASH');

// ---------- helpers ----------
const hits = new Map();
const limit = (key, max, win) => (req, res, next) => {
  const k = key + req.ip, n = Date.now(), h = (hits.get(k) || []).filter(t => n - t < win);
  if (h.length >= max) return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
  h.push(n); hits.set(k, h); next();
};
const pwOk = p => typeof p === 'string' && p.length >= 12 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
const PWMSG = 'Password needs 12+ characters with uppercase, lowercase, a number and a special character.';
const isAdmin = r => !!(r.session && r.session.admin === true && r.session.ver === A.ver);
const log = (req, action) => { logs.unshift({ at: new Date().toISOString(), action, admin: A.id, ip: req.ip }); logs.length = Math.min(logs.length, 500); wr('log', logs); };
const noStore = (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); };
const clean = b => { const o = {}; for (const [k, v] of Object.entries(b || {})) if (/^[a-zA-Z]{1,30}$/.test(k) && k !== 'id' && ['string', 'number', 'boolean'].includes(typeof v)) o[k] = typeof v === 'string' ? v.slice(0, 5000) : v; return o; };

// ---------- app ----------
const app = express();
if (prod) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => { res.set({ 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'Content-Security-Policy': "default-src 'self' 'unsafe-inline' data: https:" }); next(); });
app.use(express.json({ limit: '100kb' }));
app.use(session({ name: 'alg.sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, rolling: true,
  cookie: { httpOnly: true, sameSite: 'strict', secure: prod, maxAge: 30 * 60 * 1000 } })); // 30 min inactivity; use a persistent store (Redis/SQLite) in production

// Public API: published, non-archived products only
app.get('/api/products', (q, s) => s.json(db.products.filter(p => p.status === 'published' && !p.archived)));
app.post('/api/orders', limit('order', 12, 15 * 60e3), (req, res) => {
  const b = req.body || {}, text = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.trim().length <= max;
  if (!text(b.customer, 100) || !text(b.mobile, 20) || !text(b.address, 300) || !text(b.city, 100) || !text(b.district, 100) || !text(b.state, 100) || !/^\d{6}$/.test(b.pin || '')) return res.status(400).json({ error: 'Complete the required delivery details.' });
  if (b.email && (!text(b.email, 254) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email))) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (!/^[0-9+() -]{10,20}$/.test(b.mobile) || !['UPI', 'Credit / Debit Card', 'Net Banking', 'Wallet', 'Cash on Delivery', 'Store Pickup (Sulur)'].includes(b.paymentMethod)) return res.status(400).json({ error: 'Check the mobile number and payment method.' });
  if (b.instructions && !text(b.instructions, 1000)) return res.status(400).json({ error: 'Delivery instructions are too long.' });
  if (!Array.isArray(b.items) || !b.items.length || b.items.length > 30) return res.status(400).json({ error: 'Your cart is empty or too large.' });
  const items = [];
  for (const item of b.items) {
    const p = db.products.find(x => String(x.id) === String(item?.id) && x.status === 'published' && !x.archived);
    const quantity = Number(item?.quantity), price = Number(p?.price);
    if (!p || !Number.isInteger(quantity) || quantity < 1 || quantity > 99 || !Number.isFinite(price) || price <= 0) return res.status(400).json({ error: 'A cart item is invalid or no longer available.' });
    if (!Number.isFinite(Number(p.stock)) || Number(p.stock) < quantity) return res.status(409).json({ error: p.name + ' does not have enough stock.' });
    const choices = (v, fallback) => { const values = (Array.isArray(v) ? v : String(v || '').split(',')).map(x => String(x).trim()).filter(Boolean); return values.length ? values : fallback; };
    const sizes = choices(p.sizes, ['One Size']), colors = choices(p.colors, ['Ivory']);
    const size = String(item.size || ''), color = String(item.color || '');
    if (!sizes.includes(size) || !colors.includes(color)) return res.status(400).json({ error: 'A selected size or colour is no longer available.' });
    items.push({ productId: p.id, name: String(p.name || '').slice(0, 200), sku: String(p.sku || '').slice(0, 60), size, color, quantity, price, lineTotal: price * quantity });
  }
  const subtotal = items.reduce((sum, item) => sum + item.lineTotal, 0), shipping = subtotal > 999 ? 0 : 60;
  const orderCode = 'ALG-' + crypto.randomUUID().slice(0, 8).toUpperCase();
  const order = { id: crypto.randomUUID(), orderCode, createdAt: new Date().toISOString(), customer: b.customer.trim(), mobile: b.mobile.trim(), email: (b.email || '').trim(), address: b.address.trim(), city: b.city.trim(), district: b.district.trim(), state: b.state.trim(), pin: b.pin, instructions: (b.instructions || '').trim(), paymentMethod: b.paymentMethod, payment: b.paymentMethod === 'Cash on Delivery' ? 'COD' : 'Pending', status: 'Pending', items: items.map(x => `${x.name} x${x.quantity} (${x.size}, ${x.color})`).join('; '), itemDetails: items, subtotal, shipping, amount: subtotal + shipping };
  db.orders.unshift(order); save();
  res.status(201).json({ orderCode, amount: order.amount });
});

// ---------- admin pages ----------
const CSS = '*{box-sizing:border-box}body{margin:0;font:15px system-ui,sans-serif;background:#fffdf9;color:#222}.c{max-width:380px;margin:8vh auto;padding:26px;border:1px solid #e6dcc6;border-radius:14px;background:#fff}h1{font:400 22px Georgia;letter-spacing:3px;color:#b8975a;margin:0 0 4px}input,select,textarea,button{width:100%;padding:11px;margin:6px 0;border:1px solid #e6dcc6;border-radius:8px;font:inherit;color:#222;background:#fff}button{background:#222;color:#f3e6c4;cursor:pointer;border-color:#222}button.o{background:#fff;color:#222;border-color:#b8975a}a{color:#b8975a}.m{color:#a33;min-height:20px;font-size:13px}.ok{color:#2f6f4a}@media(prefers-color-scheme:dark){body{background:#17150f;color:#f3ecdc}.c,input,select,textarea,button.o{background:#1d1a12;color:#f3ecdc;border-color:#3a3524}}';
const H = "{'Content-Type':'application/json','X-Requested-With':'alangar'}";
const page = (t, body, js) => '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' + t + '</title><style>' + CSS + '</style></head><body>' + body + '<script>const H=' + H + ';const $=s=>document.getElementById(s);async function post(u,b){const r=await fetch(u,{method:"POST",headers:H,body:JSON.stringify(b||{})});return[r,await r.json().catch(()=>({}))]}' + js + '</script></body></html>';

const LOGIN = page('Admin Login', '<div class="c"><h1>ALANGAR</h1><p>Administrator Login</p><input id="u" placeholder="Admin User ID" autocomplete="username"><input id="p" type="password" placeholder="Admin Password" autocomplete="current-password"><label><input type="checkbox" style="width:auto" onclick="p.type=this.checked?\'text\':\'password\'"> Show password</label><div class="m" id="m"></div><button id="b">Login</button><p><a href="/admin/forgot-password">Forgot Password?</a></p></div>',
  '$("b").onclick=async()=>{const[r,d]=await post("/admin/api/login",{id:$("u").value,password:$("p").value});r.ok?location.href="/admin":$("m").textContent=d.error||"Login failed."};$("p").onkeydown=e=>{if(e.key=="Enter")$("b").click()}');

const FORGOT = page('Admin Password Recovery', '<div class="c"><h1>ALANGAR</h1><p><b>Admin Password Recovery</b></p><div id="s1"><input id="r" type="password" placeholder="Primary Recovery Password" autocomplete="off"><button id="v">Verify Primary Password</button></div><div id="s2" style="display:none"><input id="n" type="password" placeholder="New Admin Password" autocomplete="new-password"><input id="c" type="password" placeholder="Confirm New Password" autocomplete="new-password"><label><input type="checkbox" style="width:auto" onclick="n.type=c.type=this.checked?\'text\':\'password\'"> Show passwords</label><button id="x">Change Password</button></div><div class="m" id="m"></div><p><a href="/admin/login">Back to login</a></p></div>',
  '$("v").onclick=async()=>{const[r,d]=await post("/admin/api/recovery/verify",{recovery:$("r").value});if(r.ok){$("s1").style.display="none";$("s2").style.display="block";$("m").textContent=""}else $("m").textContent=d.error||"Invalid recovery password."};$("x").onclick=async()=>{const[r,d]=await post("/admin/api/recovery/reset",{password:$("n").value,confirm:$("c").value});if(r.ok){$("m").className="m ok";$("m").textContent="Admin password changed successfully.";setTimeout(()=>location.href="/admin/login",1500)}else $("m").textContent=d.error}');

const FIELDS = {
  products: ['name', 'sku', 'category', 'gender:Men|Women|Kids', 'mrp#', 'price#', 'stock#', 'sizes', 'colors', 'image', 'description', 'featured?', 'newArrival?', 'bestSeller?', 'status:draft|published'],
  categories: ['name', 'description', 'image', 'order#', 'visible?'],
  sections: ['name', 'type:hero|productGrid|categoryGrid|banner|imageText|offer|testimonials|gallery|wholesaleCta|text', 'heading', 'description', 'image', 'buttonText', 'buttonLink', 'order#', 'visible?'],
  banners: ['heading', 'description', 'image', 'buttonText', 'link', 'startDate', 'endDate', 'status:draft|published|scheduled|expired'],
  offers: ['name', 'description', 'discountPercent#', 'startDate', 'endDate', 'active?'],
  coupons: ['code', 'discountType:percent|flat', 'value#', 'minOrder#', 'maxDiscount#', 'startDate', 'endDate', 'usageLimit#', 'active?'],
  orders: ['customer', 'mobile', 'amount#', 'payment:Paid|Pending|COD', 'status:Pending|Confirmed|Processing|Packed|Shipped|Out for Delivery|Delivered|Cancelled|Returned|Refunded', 'orderCode', 'paymentMethod', 'items', 'email', 'address', 'city', 'district', 'state', 'pin', 'instructions'],
  customers: ['name', 'email', 'phone', 'accountStatus:active|blocked'],
  wholesale: ['name', 'businessName', 'phone', 'email', 'city', 'productsRequired', 'quantity', 'status:New|Contacted|In Discussion|Converted|Closed'],
  reviews: ['product', 'customer', 'rating#', 'comment', 'status:pending|approved|hidden'],
  settings: ['name', 'value', 'description']
};
const NAV = ['dashboard', 'products', 'categories', 'inventory', 'orders', 'customers', 'sections', 'banners', 'offers', 'coupons', 'wholesale', 'reviews', 'settings', 'security', 'activity'];
const DASH = page('ALANGAR Admin Panel', '<style>#w{display:flex;min-height:100vh}#sb{width:200px;background:#222;padding:12px;flex-shrink:0}#sb a{display:block;color:#e9d9b4;padding:9px;border-radius:6px;cursor:pointer;text-transform:capitalize}#sb a.on,#sb a:hover{background:#3a3524}#mn{flex:1;padding:16px;min-width:0}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:8px;border-bottom:1px solid #e6dcc6;text-align:left}.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}.k div{border:1px solid #e6dcc6;border-radius:10px;padding:12px}.k b{display:block;font-size:22px;color:#b8975a}.sc{overflow-x:auto}button.s{width:auto;padding:5px 10px;margin:2px}#md{position:fixed;inset:0;background:#0008;display:none;overflow:auto;padding:14px}#md form{max-width:480px;margin:auto;background:#fff;color:#222;padding:18px;border-radius:12px}#md label{font-size:12px;display:block;margin-top:6px}@media(max-width:700px){#w{display:block}#sb{width:auto;display:flex;overflow-x:auto}#sb a{white-space:nowrap}}</style><div id="w"><div id="sb"><h1 style="padding:6px">ALANGAR<br><small style="font:11px system-ui;color:#e9d9b4">ADMIN PANEL</small></h1></div><div id="mn"></div></div><div id="md"></div>',
  'const NAV=' + JSON.stringify(NAV) + ',F=' + JSON.stringify(FIELDS) + ';let cur="dashboard";const api=async(m,u,b)=>{const r=await fetch("/admin/api"+u,{method:m,headers:H,body:m=="GET"?undefined:JSON.stringify(b||{})});if(r.status==401){location.href="/admin/login";return null}return r.json().then(d=>({ok:r.ok,d}))};' +
  'const sb=$("sb");NAV.forEach(n=>{const a=document.createElement("a");a.textContent=n;a.dataset.n=n;a.onclick=()=>show(n);sb.appendChild(a)});const hm=document.createElement("a");hm.textContent="Storefront Home";hm.href="/";sb.appendChild(hm);const lo=document.createElement("a");lo.textContent="Logout";lo.onclick=async()=>{await post("/admin/api/logout");location.href="/admin/login"};sb.appendChild(lo);' +
  'const el=(t,x)=>{const e=document.createElement(t);if(x!==undefined)e.textContent=x;return e};' +
  'async function show(n){cur=n;[...sb.children].forEach(a=>a.classList&&a.classList.toggle("on",a.dataset.n==n));const m=$("mn");m.innerHTML="";const h=el("h2",n[0].toUpperCase()+n.slice(1));m.appendChild(h);' +
  'if(n=="dashboard"){const r=await api("GET","/dashboard");if(!r)return;const k=el("div");k.className="k";Object.entries(r.d).forEach(([a,b])=>{const d=el("div",a);d.appendChild(el("b",b));k.appendChild(d)});m.appendChild(k);return}' +
  'if(n=="security"){const f=el("div");f.style.maxWidth="360px";f.innerHTML="<input id=cp type=password placeholder=\\"Current Admin Password\\"><input id=np type=password placeholder=\\"New Admin Password\\"><input id=nc type=password placeholder=\\"Confirm New Password\\"><button id=cb>Change Password</button><div class=m id=cm></div><p>Changing the password signs out all sessions.</p>";m.appendChild(f);$("cb").onclick=async()=>{const r=await api("POST","/password",{current:$("cp").value,password:$("np").value,confirm:$("nc").value});if(r.ok)location.href="/admin/login";else $("cm").textContent=r.d.error};return}' +
  'if(n=="activity"){const r=await api("GET","/activity");const t=el("table");t.innerHTML="<tr><th>Time</th><th>Action</th><th>Admin</th><th>IP</th></tr>";r.d.forEach(l=>{const tr=el("tr");[new Date(l.at).toLocaleString(),l.action,l.admin,l.ip].forEach(v=>tr.appendChild(el("td",v)));t.appendChild(tr)});const s=el("div");s.className="sc";s.appendChild(t);m.appendChild(s);return}' +
  'const col=n=="inventory"?"products":n;' +
  'const r=await api("GET","/c/"+col);const list=r.d,fs=F[col];const b=el("button","+ Add New");b.style.width="auto";b.onclick=()=>edit(col,{});m.appendChild(b);const t=el("table"),hr=el("tr");fs.slice(0,5).concat(["state",""]).forEach(f=>hr.appendChild(el("th",f.split(/[#?:]/)[0])));t.appendChild(hr);' +
  'list.forEach(o=>{const tr=el("tr");fs.slice(0,5).forEach(f=>tr.appendChild(el("td",o[f.split(/[#?:]/)[0]]===undefined?"":o[f.split(/[#?:]/)[0]])));tr.appendChild(el("td",o.archived?"Archived":"Active"));const td=el("td"),e=el("button","Edit");e.className="s o";e.onclick=()=>edit(col,o);const d=el("button",o.archived?"Restore":"Remove");d.className="s";d.onclick=async()=>{if(o.archived){await api("POST","/c/"+col+"/"+o.id+"/restore")}else{if(!confirm("Are you sure you want to remove this item? It will be archived and can be restored."))return;await api("DELETE","/c/"+col+"/"+o.id)}show(cur)};td.append(e,d);tr.appendChild(td);t.appendChild(tr)});const s=el("div");s.className="sc";s.appendChild(t);m.appendChild(s)}' +
  'function edit(col,o){const md=$("md");md.innerHTML="";md.style.display="block";const f=el("form");F[col].forEach(x=>{const k=x.split(/[#?:]/)[0],l=el("label",k);let i;if(col=="products"&&k=="image"){i=el("input");i.type="text";i.placeholder="Image URL (optional)";i.value=o[k]??"";i.name=k;const pick=el("input");pick.type="file";pick.accept="image/png,image/jpeg,image/webp,image/gif";pick.name="imageUpload";const up=el("label","Upload from this device");const preview=el("img");preview.alt="Product image preview";preview.style.cssText="display:none;max-width:180px;max-height:180px;object-fit:contain";const showPreview=src=>{preview.src=src;preview.style.display="block"};if(o[k])showPreview(o[k]);pick.onchange=()=>{if(pick.files[0])showPreview(URL.createObjectURL(pick.files[0]))};f.append(l,i,up,pick,preview);return}if(x.includes(":")){i=el("select");x.split(":")[1].split("|").forEach(v=>{const p=el("option",v);i.appendChild(p)})}else i=el("input");if(x.endsWith("?")){i.type="checkbox";i.style.width="auto";i.checked=!!o[k]}else if(x.endsWith("#")){i.type="number";i.value=o[k]??""}else i.value=o[k]??(col=="products"&&k=="status"?"published":"");i.name=k;f.append(l,i)});' +
  'const sv=el("button","Save"),cn=el("button","Cancel");cn.className="o";cn.type="button";cn.onclick=()=>md.style.display="none";const em=el("div");em.className="m";f.append(sv,cn,em);f.onsubmit=async e=>{e.preventDefault();const b={};F[col].forEach(x=>{const k=x.split(/[#?:]/)[0],i=f.elements[k];b[k]=x.endsWith("?")?i.checked:x.endsWith("#")?(i.value===""?undefined:+i.value):i.value});const file=f.elements.imageUpload?.files[0];if(file){const fd=new FormData();fd.append("image",file);const ur=await fetch("/admin/api/upload",{method:"POST",headers:{"X-Requested-With":"alangar"},body:fd});if(ur.status==401){location.href="/admin/login";return}const ud=await ur.json().catch(()=>({}));if(!ur.ok){em.textContent=ud.error||"Image upload failed.";return}b.image=ud.url}const r=o.id?await api("PUT","/c/"+col+"/"+o.id,b):await api("POST","/c/"+col,b);if(r.ok){md.style.display="none";show(cur)}else em.textContent=r.d.error};md.appendChild(f)}show("dashboard")');

app.get('/admin/login', noStore, (q, s) => isAdmin(q) ? s.redirect('/admin') : s.type('html').send(LOGIN));
app.get('/admin/forgot-password', noStore, (q, s) => s.type('html').send(FORGOT));
// ---------- admin API ----------
const api = express.Router();
api.use(noStore, (req, res, next) => (req.method === 'GET' || (req.get('x-requested-with') === 'alangar' && (/json/.test(req.get('content-type') || '') || req.is('multipart/form-data')))) ? next() : res.status(403).json({ error: 'Forbidden' }));

api.post('/login', limit('login', 8, 15 * 60e3), async (req, res) => {
  const { id, password } = req.body || {};
  const idOk = typeof id === 'string' && id === A.id;
  const pwGood = await bcrypt.compare(typeof password === 'string' ? password : '', A.hash); // always compared: no user-ID enumeration
  if (!(idOk && pwGood)) return res.status(401).json({ error: 'Invalid credentials.' });
  hits.delete('login' + req.ip);
  req.session.regenerate(() => { req.session.admin = true; req.session.ver = A.ver; A.last = new Date().toISOString(); wr('admin', A); log(req, 'Admin Login'); res.json({ ok: true }); });
});
api.post('/logout', (req, res) => { if (isAdmin(req)) log(req, 'Admin Logout'); req.session.destroy(() => { res.clearCookie('alg.sid'); res.json({ ok: true }); }); });

// Recovery: the primary recovery password ONLY unlocks the "set new password" step. It never sets session.admin.
api.post('/recovery/verify', limit('rec', 5, 15 * 60e3), async (req, res) => {
  const ok = await bcrypt.compare(typeof req.body?.recovery === 'string' ? req.body.recovery : '', RH);
  if (!ok) return res.status(401).json({ error: 'Invalid recovery password.' });
  req.session.regenerate(() => { req.session.recoveryAt = Date.now(); res.json({ ok: true }); });
});
api.post('/recovery/reset', limit('recreset', 10, 15 * 60e3), (req, res) => {
  if (!req.session.recoveryAt || Date.now() - req.session.recoveryAt > 10 * 60e3) return res.status(403).json({ error: 'Recovery session expired. Start again.' });
  const { password, confirm } = req.body || {};
  if (password !== confirm) return res.status(400).json({ error: 'Passwords do not match.' });
  if (!pwOk(password)) return res.status(400).json({ error: PWMSG });
  A.hash = bcrypt.hashSync(password, 12); A.ver++; wr('admin', A); log(req, 'Password Reset via Recovery');
  req.session.destroy(() => { res.clearCookie('alg.sid'); res.json({ ok: true }); }); // all old sessions invalid (ver bumped)
});

// Everything below requires an authenticated ADMIN session, verified server-side on every call.
api.use((req, res, next) => isAdmin(req) ? next() : res.status(401).json({ error: 'Access Denied — Administrator permission required.' }));
const imageUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } });
api.post('/upload', (req, res, next) => imageUpload.single('image')(req, res, err => {
  if (!err) return next();
  res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Image must be 5 MB or smaller.' : 'Invalid image upload.' });
}), (req, res) => {
  const b = req.file?.buffer, mime = req.file?.mimetype;
  const ext = b && mime === 'image/png' && b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) ? 'png'
    : b && mime === 'image/jpeg' && b[0] === 255 && b[1] === 216 && b[2] === 255 ? 'jpg'
      : b && mime === 'image/gif' && ['GIF87a', 'GIF89a'].includes(b.toString('ascii', 0, 6)) ? 'gif'
        : b && mime === 'image/webp' && b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP' ? 'webp' : '';
  if (!ext) return res.status(400).json({ error: 'Choose a valid PNG, JPEG, GIF, or WebP image.' });
  const name = crypto.randomUUID() + '.' + ext;
  fs.writeFileSync(path.join(UPLOADS, name), b, { flag: 'wx' });
  log(req, 'Uploaded product image');
  res.status(201).json({ url: '/uploads/' + name });
});
api.post('/password', limit('chg', 10, 15 * 60e3), async (req, res) => {
  const { current, password, confirm } = req.body || {};
  if (!(await bcrypt.compare(typeof current === 'string' ? current : '', A.hash))) return res.status(400).json({ error: 'Current password is incorrect.' });
  if (password !== confirm) return res.status(400).json({ error: 'Passwords do not match.' });
  if (!pwOk(password)) return res.status(400).json({ error: PWMSG });
  A.hash = await bcrypt.hash(password, 12); A.ver++; wr('admin', A); log(req, 'Password Changed');
  req.session.destroy(() => { res.clearCookie('alg.sid'); res.json({ ok: true }); });
});
api.get('/dashboard', (q, s) => {
  const p = db.products.filter(x => !x.archived), o = db.orders.filter(x => !x.archived);
  s.json({ 'Total Products': p.length, 'Active Products': p.filter(x => x.status === 'published').length, 'Out of Stock': p.filter(x => +x.stock === 0).length, 'Low Stock': p.filter(x => +x.stock > 0 && +x.stock <= 5).length,
    'Total Orders': o.length, 'Pending Orders': o.filter(x => x.status === 'Pending').length, 'Completed Orders': o.filter(x => x.status === 'Delivered').length, Customers: db.customers.length, 'Wholesale Enquiries': db.wholesale.length,
    Revenue: '₹' + o.filter(x => x.status === 'Delivered').reduce((a, b) => a + (+b.amount || 0), 0).toLocaleString('en-IN') });
});
api.get('/activity', (q, s) => s.json(logs.slice(0, 200)));
const col = (q, s, next) => COLS.includes(q.params.col) ? next() : s.status(404).json({ error: 'Not found' });
api.get('/c/:col', col, (q, s) => s.json(db[q.params.col]));
api.post('/c/:col', col, (q, s) => { const o = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), ...clean(q.body) }; db[q.params.col].unshift(o); save(); log(q, 'Added ' + q.params.col + ' item'); s.json(o); });
api.put('/c/:col/:id', col, (q, s) => { const o = db[q.params.col].find(x => x.id === q.params.id); if (!o) return s.status(404).json({ error: 'Not found' }); Object.assign(o, clean(q.body)); save(); log(q, 'Edited ' + q.params.col + ' item'); s.json(o); });
api.delete('/c/:col/:id', col, (q, s) => { const o = db[q.params.col].find(x => x.id === q.params.id); if (!o) return s.status(404).json({ error: 'Not found' }); o.archived = true; save(); log(q, 'Removed (archived) ' + q.params.col + ' item'); s.json({ ok: true }); }); // soft delete
api.post('/c/:col/:id/restore', col, (q, s) => { const o = db[q.params.col].find(x => x.id === q.params.id); if (!o) return s.status(404).json({ error: 'Not found' }); o.archived = false; save(); log(q, 'Restored ' + q.params.col + ' item'); s.json({ ok: true }); });
app.use('/admin/api', api);

app.get('/admin', noStore, (q, s) => isAdmin(q) ? s.type('html').send(DASH) : s.redirect('/admin/login'));
app.use(express.static(path.join(__dirname, 'public')));
app.listen(process.env.PORT || 3000, () => console.log('ALANGAR running on port ' + (process.env.PORT || 3000)));

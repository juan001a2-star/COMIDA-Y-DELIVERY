'use strict';
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const webpush = require('web-push');

let webPushConfigured = false;
function configureWebPush() {
  const publicKey = process.env.WEB_PUSH_PUBLIC_KEY || '';
  const privateKey = process.env.WEB_PUSH_PRIVATE_KEY || '';
  const subject = process.env.WEB_PUSH_SUBJECT || 'mailto:admin@foodtrack.local';
  if (!publicKey || !privateKey) return false;
  try {
    if (!webPushConfigured) {
      webpush.setVapidDetails(subject, publicKey, privateKey);
      webPushConfigured = true;
    }
    return true;
  } catch (e) {
    console.error('No se pudo configurar Web Push:', e.message);
    return false;
  }
}
async function sendPushToUser(userId, title, body, data = {}) {
  if (!configureWebPush()) return;
  const found = await pool.query('SELECT id, subscription FROM push_subscriptions WHERE user_id=$1', [userId]);
  if (!found.rows.length) return;
  const payload = JSON.stringify({ title, body, icon: '/icon-192.png', badge: '/icon-192.png', tag: String(data.tag || 'foodtrack-update'), data });
  for (const row of found.rows) {
    try {
      await webpush.sendNotification(row.subscription, payload, { TTL: 60 * 60 * 24 });
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await pool.query('DELETE FROM push_subscriptions WHERE id=$1', [row.id]);
      } else {
        console.error('Error enviando Web Push:', e.statusCode || '', e.message);
      }
    }
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET) {
  console.error('Faltan DATABASE_URL o JWT_SECRET. Configura las variables de entorno.');
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname)));

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS app_users (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, username TEXT,
    address TEXT NOT NULL DEFAULT '', phone TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'cliente' CHECK (role IN ('cliente','dueno','repartidor','admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS username TEXT');
  await pool.query("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'active'");
  await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS blocked_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS blocked_reason TEXT');
  await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
  await pool.query("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS hidden_order_ids JSONB NOT NULL DEFAULT '[]'::jsonb");
  await pool.query("UPDATE app_users SET username=phone WHERE username IS NULL OR username=''");
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS app_users_username_unique ON app_users(LOWER(username))');
  await pool.query(`CREATE TABLE IF NOT EXISTS app_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1), payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query("INSERT INTO app_state(id,payload) VALUES(1,'{}'::jsonb) ON CONFLICT(id) DO NOTHING");
  await pool.query(`CREATE TABLE IF NOT EXISTS app_events (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL, payload JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), read_at TIMESTAMPTZ
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS app_events_user_id_id_idx ON app_events(user_id,id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS push_subscriptions (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL UNIQUE, subscription JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS push_subscriptions_user_id_idx ON push_subscriptions(user_id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS restaurant_billing (
    restaurant_id TEXT PRIMARY KEY, plan_name TEXT NOT NULL DEFAULT 'Mensual',
    fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (fee >= 0), currency TEXT NOT NULL DEFAULT 'EUR',
    started_on DATE NOT NULL DEFAULT CURRENT_DATE, due_on DATE NOT NULL, grace_days INTEGER NOT NULL DEFAULT 7 CHECK (grace_days BETWEEN 0 AND 60),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','grace','suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS restaurant_payments (
    id BIGSERIAL PRIMARY KEY, restaurant_id TEXT NOT NULL REFERENCES restaurant_billing(restaurant_id),
    amount NUMERIC(12,2) NOT NULL CHECK (amount > 0), currency TEXT NOT NULL DEFAULT 'EUR',
    paid_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), covered_until DATE NOT NULL,
    payment_method TEXT NOT NULL DEFAULT '', reference TEXT NOT NULL DEFAULT '',
    recorded_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS restaurant_payments_restaurant_idx ON restaurant_payments(restaurant_id, paid_at DESC)');
  await pool.query(`CREATE TABLE IF NOT EXISTS driver_locations (
    user_id BIGINT PRIMARY KEY REFERENCES app_users(id) ON DELETE CASCADE,
    lat DOUBLE PRECISION NOT NULL, lng DOUBLE PRECISION NOT NULL,
    accuracy INTEGER, recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  if (process.env.ADMIN_PHONE && process.env.ADMIN_PASSWORD) {
    const username = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query(`INSERT INTO app_users(name,username,address,phone,password_hash,role)
      VALUES('Administrador FoodTrack',$1,'',$2,$3,'admin')
      ON CONFLICT(phone) DO UPDATE SET username=EXCLUDED.username,password_hash=EXCLUDED.password_hash,role='admin'`, [username, process.env.ADMIN_PHONE, hash]);
    console.log('Cuenta administradora inicial configurada. Usuario: ' + username);
  }
}
function signToken(user) { return jwt.sign({ id: user.id, username: user.username, phone: user.phone, role: user.role }, JWT_SECRET, { expiresIn: '7d' }); }
async function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  try { req.auth = jwt.verify(token, JWT_SECRET); const check=await pool.query('SELECT account_status,phone,name FROM app_users WHERE id=$1',[req.auth.id]); if(!check.rows[0] || check.rows[0].account_status!=='active') return res.status(403).json({error:'Esta cuenta está bloqueada o ya no está disponible. Contacta con el administrador.'}); req.auth.phone=check.rows[0].phone;req.auth.name=check.rows[0].name;next(); }
  catch (e) { if(e.status) return res.status(e.status).json({error:e.message}); return res.status(401).json({ error: 'Sesión caducada. Inicia sesión de nuevo.' }); }
}
const safeUser = u => ({ id: u.id, name: u.name, username: u.username, addr: u.address || '', phone: u.phone, role: u.role, accountStatus: u.account_status || 'active' });
const clean = v => String(v || '').trim();
function validDateOnly(value){const s=String(value||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return false;const d=new Date(s+'T00:00:00.000Z');return !Number.isNaN(d.getTime())&&d.toISOString().slice(0,10)===s;}
const BUSINESS_TZ = process.env.BUSINESS_TIMEZONE || 'America/Cayenne';
const DAY_KEYS = ['sun','mon','tue','wed','thu','fri','sat'];
const DAY_NAMES = {Sun:'domingo',Mon:'lunes',Tue:'martes',Wed:'miércoles',Thu:'jueves',Fri:'viernes',Sat:'sábado'};
function zonedParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone: BUSINESS_TZ, weekday: 'short', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(date);
  const v = Object.fromEntries(parts.map(x => [x.type, x.value]));
  return { weekday: v.weekday, dayKey: ({Sun:'sun',Mon:'mon',Tue:'tue',Wed:'wed',Thu:'thu',Fri:'fri',Sat:'sat'})[v.weekday], year:Number(v.year), month:Number(v.month), day:Number(v.day), hour:Number(v.hour), minute:Number(v.minute) };
}
function localDateString(date = new Date()) { const p=zonedParts(date); return `${p.year}-${String(p.month).padStart(2,'0')}-${String(p.day).padStart(2,'0')}`; }
function minuteOfDay(date) { const p=zonedParts(date); return p.hour*60+p.minute; }
function parseIntervals(value) {
  if (!Array.isArray(value)) return [];
  return value.map(x => ({ open:String(x.open||''), close:String(x.close||'') })).filter(x => /^([01]\d|2[0-3]):[0-5]\d$/.test(x.open) && /^([01]\d|2[0-3]):[0-5]\d$/.test(x.close));
}
function validWeeklyHours(hours) {
  if(hours==null)return true; if(typeof hours!=='object'||Array.isArray(hours))return false;
  for(const key of Object.keys(hours)){if(!DAY_KEYS.includes(key)||!Array.isArray(hours[key])||hours[key].length>6)return false;for(const x of hours[key]){const open=String(x?.open||''),close=String(x?.close||'');if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(open)||!/^([01]\d|2[0-3]):[0-5]\d$/.test(close)||open===close)return false;}}
  return true;
}
function intervalsForDay(business, key) {
  const raw = business.hours && business.hours[key];
  if (Array.isArray(raw)) return parseIntervals(raw);
  if (business.openTime && business.closeTime) return parseIntervals([{open:business.openTime,close:business.closeTime}]);
  return [];
}
function businessOpenAt(business, date = new Date()) {
  if (!business || business.blocked || business.ownerSuspended || business.subscriptionBlocked || business.isOpen === false) return false;
  const allIntervals=DAY_KEYS.flatMap(k=>intervalsForDay(business,k));
  if(!allIntervals.length) return business.hoursConfigured ? false : true; // Compatibilidad para negocios antiguos sin horario semanal configurado.
  const now=zonedParts(date), minute=now.hour*60+now.minute;
  const current=intervalsForDay(business,now.dayKey);
  for (const i of current) { const a=Number(i.open.slice(0,2))*60+Number(i.open.slice(3)); const b=Number(i.close.slice(0,2))*60+Number(i.close.slice(3)); if (a<b ? minute>=a&&minute<b : minute>=a) return true; }
  const prevKey=DAY_KEYS[(DAY_KEYS.indexOf(now.dayKey)+6)%7];
  for (const i of intervalsForDay(business,prevKey)) { const a=Number(i.open.slice(0,2))*60+Number(i.open.slice(3)); const b=Number(i.close.slice(0,2))*60+Number(i.close.slice(3)); if (a>b && minute<b) return true; }
  return false;
}
function nextBusinessOpening(business, date = new Date()) {
  const now=zonedParts(date), currentMinute=now.hour*60+now.minute, currentIndex=DAY_KEYS.indexOf(now.dayKey);
  for(let offset=0;offset<=7;offset++){
    const key=DAY_KEYS[(currentIndex+offset)%7];
    const intervals=intervalsForDay(business,key).slice().sort((a,b)=>a.open.localeCompare(b.open));
    for(const i of intervals){const minute=Number(i.open.slice(0,2))*60+Number(i.open.slice(3));if(offset>0||minute>currentMinute)return {dayOffset:offset,day:DAY_NAMES[({sun:'Sun',mon:'Mon',tue:'Tue',wed:'Wed',thu:'Thu',fri:'Fri',sat:'Sat'})[key]],time:i.open};}
  }
  return null;
}
function formatBusinessTime(date) { return new Intl.DateTimeFormat('es', {timeZone:BUSINESS_TZ,weekday:'short',hour:'2-digit',minute:'2-digit'}).format(date); }
async function applySubscriptionEnforcement() {
  const today=localDateString();
  const q=await pool.query(`UPDATE restaurant_billing SET status=CASE WHEN due_on + grace_days < $1::date THEN 'suspended' WHEN due_on < $1::date THEN 'grace' ELSE 'active' END, updated_at=NOW() WHERE status <> CASE WHEN due_on + grace_days < $1::date THEN 'suspended' WHEN due_on < $1::date THEN 'grace' ELSE 'active' END RETURNING restaurant_id,status`,[today]);
  const suspended=(await pool.query("SELECT restaurant_id FROM restaurant_billing WHERE status='suspended'")).rows.map(x=>String(x.restaurant_id));
  if(q.rowCount || suspended.length){const c=await pool.connect();try{await c.query('BEGIN');const r=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');const state=r.rows[0]?.payload||{};let changed=false;state.restaurants=(state.restaurants||[]).map(x=>{const should=suspended.includes(String(x.id));if(Boolean(x.subscriptionBlocked)!==should){changed=true;return {...x,subscriptionBlocked:should};}return x;});if(changed)await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);await c.query('COMMIT');}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
}

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});
// Configuración pública de Web Push. La clave privada solo permanece en el servidor.
app.get('/api/push/config', (_req, res) => {
  const publicKey = process.env.WEB_PUSH_PUBLIC_KEY || '';
  res.json({ enabled: Boolean(publicKey && process.env.WEB_PUSH_PRIVATE_KEY && configureWebPush()), publicKey });
});
app.post('/api/push/subscribe', auth, async (req, res) => {
  try {
    if (!['dueno','cliente'].includes(req.auth.role)) return res.status(403).json({ error: 'Las notificaciones están disponibles para clientes y dueños.' });
    if (!configureWebPush()) return res.status(503).json({ error: 'Web Push todavía no está configurado en Render.' });
    const sub = req.body?.subscription;
    if (!sub || typeof sub.endpoint !== 'string' || !sub.endpoint.startsWith('https://') || !sub.keys?.p256dh || !sub.keys?.auth) return res.status(400).json({ error: 'Suscripción de notificaciones no válida.' });
    if (JSON.stringify(sub).length > 10000) return res.status(400).json({ error: 'Suscripción demasiado grande.' });
    await pool.query(`INSERT INTO push_subscriptions(user_id,endpoint,subscription) VALUES($1,$2,$3::jsonb)
      ON CONFLICT(endpoint) DO UPDATE SET user_id=EXCLUDED.user_id,subscription=EXCLUDED.subscription,updated_at=NOW()`, [req.auth.id, sub.endpoint, JSON.stringify(sub)]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo registrar este dispositivo.' }); }
});
app.delete('/api/push/subscribe', auth, async (req, res) => {
  try { const endpoint = String(req.body?.endpoint || '').trim(); if (endpoint) await pool.query('DELETE FROM push_subscriptions WHERE user_id=$1 AND endpoint=$2', [req.auth.id, endpoint]); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo desactivar este dispositivo.' }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, address = '', phone, password } = req.body || {};
    const username = clean(req.body?.username || phone).toLowerCase();
    if (!clean(name) || !clean(phone) || !username || !password || String(password).length < 4) return res.status(400).json({ error: 'Indica nombre, usuario, teléfono y contraseña de al menos 4 caracteres.' });
    const hash = await bcrypt.hash(String(password), 12);
    const result = await pool.query(`INSERT INTO app_users(name,username,address,phone,password_hash,role)
      VALUES($1,$2,$3,$4,$5,'cliente') RETURNING *`, [clean(name), username, String(address), clean(phone), hash]);
    const user = result.rows[0];
    res.status(201).json({ token: signToken(user), user: safeUser(user) });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese usuario o teléfono ya está registrado. Inicia sesión.' });
    console.error(e); res.status(500).json({ error: 'No se pudo crear la cuenta.' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const login = clean(req.body?.login || req.body?.username || req.body?.phone).toLowerCase();
    const result = await pool.query('SELECT * FROM app_users WHERE LOWER(username)= $1 OR phone=$1 LIMIT 1', [login]);
    const user = result.rows[0];
    if (!user || user.account_status !== 'active' || !(await bcrypt.compare(String(req.body?.password || ''), user.password_hash))) return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    res.json({ token: signToken(user), user: safeUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo iniciar sesión.' }); }
});
app.post('/api/admin/users', auth, async (req, res) => {
  try {
    if (req.auth.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede crear cuentas internas.' });
    const { name, address = '', phone, password, role } = req.body || {};
    const username = clean(req.body?.username).toLowerCase();
    if (!clean(name) || !username || !clean(phone) || !password || String(password).length < 4 || !['dueno','repartidor'].includes(role)) return res.status(400).json({ error: 'Completa nombre, usuario, teléfono y contraseña (mínimo 4 caracteres). Rol permitido: dueño o repartidor.' });
    const hash = await bcrypt.hash(String(password), 12);
    const r = await pool.query(`INSERT INTO app_users(name,username,address,phone,password_hash,role) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`, [clean(name),username,String(address),clean(phone),hash,role]);
    res.status(201).json({ user: safeUser(r.rows[0]) });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese usuario o teléfono ya está registrado.' });
    console.error(e); res.status(500).json({ error: 'No se pudo crear la cuenta interna.' });
  }
});
app.get('/api/admin/users', auth, async (req,res) => {
  if(req.auth.role!=='admin') return res.status(403).json({error:'Solo el administrador.'});
  const r=await pool.query("SELECT id,name,username,address AS addr,phone,role,account_status,blocked_at,blocked_reason,created_at FROM app_users WHERE role IN ('dueno','repartidor','cliente') ORDER BY created_at DESC");
  res.json(r.rows);
});
// Perfil propio: nunca se devuelve el hash ni la contraseña.
app.put('/api/me', auth, async (req,res)=>{
  try { const {name,address='',phone,username}=req.body||{}; if(!clean(name)||!clean(phone)||!clean(username)) return res.status(400).json({error:'Nombre, usuario y teléfono son obligatorios.'});
    const r=await pool.query('UPDATE app_users SET name=$1,address=$2,phone=$3,username=$4,updated_at=NOW() WHERE id=$5 RETURNING id,name,username,address,phone,role,account_status',[clean(name),clean(address),clean(phone),clean(username).toLowerCase(),req.auth.id]);
    res.json({user:safeUser(r.rows[0])});
  } catch(e){ if(e.code==='23505')return res.status(409).json({error:'Ese usuario o teléfono ya está utilizado.'}); console.error(e);res.status(500).json({error:'No se pudo actualizar el perfil.'}); }
});
app.put('/api/me/password', auth, async (req,res)=>{
  try { const {currentPassword,newPassword}=req.body||{}; if(String(newPassword||'').length<4)return res.status(400).json({error:'La nueva contraseña debe tener al menos 4 caracteres.'}); const q=await pool.query('SELECT password_hash FROM app_users WHERE id=$1',[req.auth.id]); if(!q.rows[0]||!(await bcrypt.compare(String(currentPassword||''),q.rows[0].password_hash)))return res.status(400).json({error:'La contraseña actual no es correcta.'}); const hash=await bcrypt.hash(String(newPassword),12); await pool.query('UPDATE app_users SET password_hash=$1,updated_at=NOW() WHERE id=$2',[hash,req.auth.id]); res.json({ok:true}); }
  catch(e){console.error(e);res.status(500).json({error:'No se pudo cambiar la contraseña.'});}
});
app.put('/api/admin/users/:id', auth, async(req,res)=>{
  if(req.auth.role!=='admin')return res.status(403).json({error:'Solo el administrador.'});
  try { const b=req.body||{}; const fields=['name','username','phone','address','role']; const vals=[clean(b.name),clean(b.username).toLowerCase(),clean(b.phone),clean(b.address),b.role]; if(!vals[0]||!vals[1]||!vals[2]||!['cliente','dueno','repartidor'].includes(vals[4]))return res.status(400).json({error:'Datos de cuenta incompletos o rol no válido.'});
    let sql='UPDATE app_users SET name=$1,username=$2,phone=$3,address=$4,role=$5,updated_at=NOW()'; if(b.newPassword){if(String(b.newPassword).length<4)return res.status(400).json({error:'La contraseña debe tener al menos 4 caracteres.'}); vals.push(await bcrypt.hash(String(b.newPassword),12));sql+=`,password_hash=$${vals.length}`;} vals.push(req.params.id); const r=await pool.query(sql+` WHERE id=$${vals.length} RETURNING id,name,username,address,phone,role,account_status,created_at,blocked_at,blocked_reason`,vals); if(!r.rows[0])return res.status(404).json({error:'Cuenta no encontrada.'});res.json({user:r.rows[0]});
  }catch(e){if(e.code==='23505')return res.status(409).json({error:'Usuario o teléfono ya registrado.'});console.error(e);res.status(500).json({error:'No se pudo modificar la cuenta.'});}
});
app.post('/api/admin/users/:id/block',auth,async(req,res)=>{if(req.auth.role!=='admin')return res.status(403).json({error:'Solo el administrador.'});try{if(String(req.params.id)===String(req.auth.id))return res.status(400).json({error:'No puedes bloquear tu propia cuenta administradora.'});const r=await pool.query("UPDATE app_users SET account_status='blocked',blocked_at=NOW(),blocked_reason=$1,updated_at=NOW() WHERE id=$2 AND role<>'admin' RETURNING id,name,account_status,blocked_at,blocked_reason",[clean(req.body?.reason),req.params.id]);if(!r.rows[0])return res.status(404).json({error:'Cuenta no encontrada o no bloqueable.'});if((await pool.query('SELECT role FROM app_users WHERE id=$1',[req.params.id])).rows[0]?.role==='dueno')await setOwnerSuspended(req.params.id,true);res.json({user:r.rows[0]});}catch(e){console.error(e);res.status(500).json({error:'No se pudo bloquear la cuenta.'});}});
app.post('/api/admin/users/:id/unblock',auth,async(req,res)=>{if(req.auth.role!=='admin')return res.status(403).json({error:'Solo el administrador.'});try{const r=await pool.query("UPDATE app_users SET account_status='active',blocked_at=NULL,blocked_reason=NULL,updated_at=NOW() WHERE id=$1 RETURNING id,name,account_status",[req.params.id]);if(!r.rows[0])return res.status(404).json({error:'Cuenta no encontrada.'});if((await pool.query('SELECT role FROM app_users WHERE id=$1',[req.params.id])).rows[0]?.role==='dueno')await setOwnerSuspended(req.params.id,false);res.json({user:r.rows[0]});}catch(e){console.error(e);res.status(500).json({error:'No se pudo reactivar la cuenta.'});}});
app.delete('/api/admin/users/:id',auth,async(req,res)=>{if(req.auth.role!=='admin')return res.status(403).json({error:'Solo el administrador.'});const c=await pool.connect();try{if(String(req.params.id)===String(req.auth.id))return res.status(400).json({error:'No puedes eliminar tu propia cuenta administradora.'});await c.query('BEGIN');const found=await c.query("SELECT id,name,phone,role FROM app_users WHERE id=$1 AND role<>'admin' FOR UPDATE",[req.params.id]);if(!found.rows[0]){await c.query('ROLLBACK');return res.status(404).json({error:'Cuenta no encontrada o no eliminable.'});}const u=found.rows[0];const stateQ=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');const state=stateQ.rows[0]?.payload||{};if(u.role==='cliente'){state.orders=(state.orders||[]).map(o=>String(o.phone||'')===String(u.phone)?{...o,client:'Cliente eliminado',phone:'',addr:'',customerDeleted:true}:o);state.myDeliveries=(state.myDeliveries||[]).map(o=>String(o.phone||'')===String(u.phone)?{...o,client:'Cliente eliminado',phone:'',addr:'',customerDeleted:true}:o);}if(u.role==='dueno'){state.restaurants=(state.restaurants||[]).map(r=>Number(r.ownerId)===Number(u.id)?{...r,ownerId:null,ownerSuspended:true,isOpen:false}:r);}if(u.role==='repartidor'){state.myDeliveries=(state.myDeliveries||[]).map(o=>Number(o.driverId)===Number(u.id)?{...o,driverId:null,driverName:null}:o);state.orders=(state.orders||[]).map(o=>Number(o.driverId)===Number(u.id)?{...o,driverId:null,driverName:null}:o);}await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);await c.query('DELETE FROM app_users WHERE id=$1',[req.params.id]);await c.query('COMMIT');res.json({ok:true});}catch(e){await c.query('ROLLBACK');console.error(e);res.status(500).json({error:'No se pudo eliminar la cuenta.'});}finally{c.release();}});
app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id,name,username,address,phone,role FROM app_users WHERE id=$1', [req.auth.id]);
  if (!r.rows[0]) return res.status(401).json({ error: 'Cuenta no encontrada.' });
  res.json({ user: safeUser(r.rows[0]) });
});
async function setOwnerSuspended(ownerId, suspended) { const q=await pool.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE'); const state=q.rows[0]?.payload||{}; state.restaurants=(state.restaurants||[]).map(r=>Number(r.ownerId)===Number(ownerId)?{...r,ownerSuspended:suspended}:r); await pool.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]); }
function visibleState(payload, user) {
  const state = structuredClone(payload || {});
  const all = Array.isArray(state.restaurants) ? state.restaurants : [];
  if (user.role === 'dueno') state.restaurants = all.filter(r => Number(r.ownerId) === Number(user.id));
  if (user.role === 'cliente') {
    state.restaurants = all.filter(r => !r.blocked && !r.ownerSuspended && !r.subscriptionBlocked && r.isOpen !== false && Boolean(r.ownerId)).map(r => ({...r, openNow:businessOpenAt(r), nextOpen:businessOpenAt(r)?null:nextBusinessOpening(r)}));
    const hidden=new Set((user.hiddenOrderIds||[]).map(String));
    state.orders = (state.orders || []).filter(o => (Number(o.customerId)===Number(user.id) || String(o.phone) === String(user.phone)) && !hidden.has(String(o.id)));
    state.myDeliveries = [];
    state.notifications = [];
  }
  if (user.role === 'dueno') {
    const ids = new Set(state.restaurants.map(r => String(r.id)));
    state.orders = (state.orders || []).filter(o => ids.has(String(o.restId)));
    state.myDeliveries = [];
    state.notifications = [];
  }
  if (user.role === 'repartidor') {
    state.orders = (state.orders || []).filter(o => o.status === 'listo' && !o.driverId).map(o => ({id:o.id,rest:o.rest,restId:o.restId,client:o.client,phone:o.phone,addr:o.addr,total:o.total,pay:o.pay,status:o.status,items:o.items}));
    state.myDeliveries = (state.myDeliveries || []).filter(o => Number(o.driverId) === Number(user.id));
    state.notifications = [];
  }
  return state;
}
app.get('/api/state', auth, async (req, res) => {
  try {
    await applySubscriptionEnforcement();
    const [r,u]=await Promise.all([pool.query('SELECT payload FROM app_state WHERE id=1'),pool.query('SELECT hidden_order_ids FROM app_users WHERE id=$1',[req.auth.id])]);
    const state=visibleState(r.rows[0]?.payload,{...req.auth,hiddenOrderIds:u.rows[0]?.hidden_order_ids||[]});
    if(req.auth.role==='dueno'||req.auth.role==='admin'){
      const bills=await pool.query('SELECT restaurant_id,plan_name,fee,currency,started_on,due_on,grace_days,status FROM restaurant_billing');
      const map=new Map(bills.rows.map(b=>[String(b.restaurant_id),b]));
      state.restaurants=(state.restaurants||[]).map(b=>({...b,billing:map.get(String(b.id))||null}));
    }
    res.json(state);
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudieron cargar los datos.' }); }
});
app.post('/api/state/bootstrap', auth, async (req, res) => {
  try {
    if(req.auth.role!=='admin') return res.status(403).json({error:'Solo el administrador puede inicializar el catálogo.'});
    const restaurants = req.body?.restaurants;
    if (!Array.isArray(restaurants) || !restaurants.length) return res.status(400).json({ error: 'No hay restaurantes iniciales.' });
    const current = await pool.query("SELECT payload->'restaurants' AS restaurants FROM app_state WHERE id=1 FOR UPDATE");
    if (Array.isArray(current.rows[0]?.restaurants) && current.rows[0].restaurants.length) return res.json({ ok: true, alreadyInitialized: true });
    const seed=restaurants.map(r=>({...r,ownerId:null}));
    await pool.query("UPDATE app_state SET payload=jsonb_set(payload,'{restaurants}',$1::jsonb,true),updated_at=NOW() WHERE id=1", [JSON.stringify(seed)]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo inicializar el catálogo.' }); }
});
app.post('/api/restaurants', auth, async (req,res)=>{
  if(req.auth.role!=='admin') return res.status(403).json({error:'Solo el administrador puede crear negocios nuevos.'});
  const b=req.body||{};
  if(!clean(b.name)) return res.status(400).json({error:'El nombre del negocio es obligatorio.'});
  if(!validWeeklyHours(b.hours)) return res.status(400).json({error:'Los horarios semanales no tienen un formato válido.'});
  const ownerId=Number(b.ownerId)||null;
  try {
    if(ownerId){const owner=await pool.query("SELECT id FROM app_users WHERE id=$1 AND role='dueno' AND account_status='active'",[ownerId]);if(!owner.rowCount)return res.status(400).json({error:'El dueño asignado no existe o está bloqueado.'});}
    const id=Date.now()+Math.floor(Math.random()*1000);
    const item={id,name:clean(b.name),desc:clean(b.desc)||'Nuevo negocio',img:clean(b.img)||'',svc:Array.isArray(b.svc)?b.svc:['Delivery propio'],menu:[],blocked:false,phone:clean(b.phone),whatsapp:clean(b.whatsapp),address:clean(b.address),createdAt:new Date().toISOString(),openTime:'',closeTime:'',hours:b.hours||{},hoursConfigured:true,prepMinutes:Math.max(15,Math.min(240,Number(b.prepMinutes)||15)),deliveryMinutes:Math.max(0,Math.min(240,Number(b.deliveryMinutes)||30)),isOpen:b.isOpen!==false,ownerId};
    const c=await pool.connect();try{await c.query('BEGIN');const q=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');const state=q.rows[0]?.payload||{};state.restaurants=Array.isArray(state.restaurants)?state.restaurants:[];state.restaurants.push(item);await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);await c.query('COMMIT');}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
    res.status(201).json({restaurant:item});
  }catch(e){console.error(e);res.status(500).json({error:'No se pudo crear el negocio.'});}
});
app.put('/api/restaurants/:id', auth, async (req,res)=>{
  const b=req.body||{};
  if(Object.prototype.hasOwnProperty.call(b,'hours')&&!validWeeklyHours(b.hours))return res.status(400).json({error:'Los horarios semanales no tienen un formato válido.'});
  if(Object.prototype.hasOwnProperty.call(b,'prepMinutes')&&(!Number.isFinite(Number(b.prepMinutes))||Number(b.prepMinutes)<15||Number(b.prepMinutes)>240))return res.status(400).json({error:'El tiempo de preparación debe estar entre 15 y 240 minutos.'});
  if(Object.prototype.hasOwnProperty.call(b,'deliveryMinutes')&&(!Number.isFinite(Number(b.deliveryMinutes))||Number(b.deliveryMinutes)<0||Number(b.deliveryMinutes)>240))return res.status(400).json({error:'El tiempo de delivery debe estar entre 0 y 240 minutos.'});
  const c=await pool.connect();
  try {
    await c.query('BEGIN');const q=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');
    const state=q.rows[0]?.payload||{},list=state.restaurants||[],idx=list.findIndex(x=>String(x.id)===String(req.params.id));
    if(idx<0){await c.query('ROLLBACK');return res.status(404).json({error:'Negocio no encontrado.'});}
    const old=list[idx];if(req.auth.role!=='admin'&&!(req.auth.role==='dueno'&&Number(old.ownerId)===Number(req.auth.id))){await c.query('ROLLBACK');return res.status(403).json({error:'No tienes permiso para modificar este negocio.'});}
    if(req.auth.role==='admin'&&Object.prototype.hasOwnProperty.call(b,'ownerId')&&b.ownerId!==null){if(!Number.isSafeInteger(Number(b.ownerId))||Number(b.ownerId)<1){await c.query('ROLLBACK');return res.status(400).json({error:'El dueño asignado no es válido.'});}const owner=await c.query("SELECT id FROM app_users WHERE id=$1 AND role='dueno' AND account_status='active'",[Number(b.ownerId)]);if(!owner.rowCount){await c.query('ROLLBACK');return res.status(400).json({error:'El dueño asignado no existe o está bloqueado.'});}}
    const allowed=req.auth.role==='admin'?['name','desc','img','svc','menu','blocked','ownerId','phone','whatsapp','address','openTime','closeTime','hours','prepMinutes','deliveryMinutes','isOpen']:['name','desc','img','svc','menu','phone','whatsapp','address','openTime','closeTime','hours','prepMinutes','deliveryMinutes','isOpen'];
    for(const k of allowed)if(Object.prototype.hasOwnProperty.call(b,k))old[k]=b[k];if(Object.prototype.hasOwnProperty.call(b,'hours'))old.hoursConfigured=true;
    list[idx]=old;state.restaurants=list;await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);await c.query('COMMIT');res.json({restaurant:old});
  }catch(e){await c.query('ROLLBACK');console.error(e);res.status(500).json({error:'No se pudo guardar el negocio.'});}finally{c.release();}
});
app.put('/api/admin/restaurants/:id/owner', auth, async (req,res)=>{
  if(req.auth.role!=='admin') return res.status(403).json({error:'Solo el administrador puede asignar negocios.'});
  const ownerId=req.body?.ownerId===null?null:Number(req.body?.ownerId);
  try{
    if(ownerId!==null){const u=await pool.query("SELECT id FROM app_users WHERE id=$1 AND role='dueno' AND account_status='active'",[ownerId]);if(!u.rows.length)return res.status(400).json({error:'La cuenta seleccionada no es un dueño válido.'});}
    const c=await pool.connect();try{await c.query('BEGIN');const q=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');const state=q.rows[0]?.payload||{};const r=(state.restaurants||[]).find(x=>String(x.id)===String(req.params.id));if(!r){await c.query('ROLLBACK');return res.status(404).json({error:'Negocio no encontrado.'});}r.ownerId=ownerId;r.ownerSuspended=ownerId===null;await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);await c.query('COMMIT');res.json({ok:true,restaurant:r});}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
  }catch(e){console.error(e);res.status(500).json({error:'No se pudo asignar el negocio.'});}
});
app.post('/api/orders', auth, async (req, res) => {
  try {
    if (req.auth.role !== 'cliente') return res.status(403).json({ error: 'Solo los clientes pueden crear pedidos.' });
    const o = req.body || {};
    if (!o.restId || !Array.isArray(o.items) || !o.items.length || !Number.isFinite(Number(o.total))) return res.status(400).json({ error: 'Pedido incompleto.' });
    await applySubscriptionEnforcement();
    const stateQ = await pool.query('SELECT payload FROM app_state WHERE id=1');
    const state = stateQ.rows[0]?.payload || {};
    const business = (state.restaurants || []).find(r => String(r.id) === String(o.restId));
    if (!business || business.blocked || business.ownerSuspended || business.subscriptionBlocked || business.isOpen === false || !business.ownerId) return res.status(400).json({ error: 'Este negocio no está disponible para recibir pedidos.' });
    const now=new Date(); const scheduled=o.scheduledFor?new Date(o.scheduledFor):null;
    if(o.scheduledFor && (!scheduled || Number.isNaN(scheduled.getTime()) || scheduled.getTime()<now.getTime()+15*60000)) return res.status(400).json({error:'Los pedidos programados deben solicitarse con al menos 15 minutos de antelación.'});
    if(!scheduled && !businessOpenAt(business,now)) return res.status(400).json({error:'El negocio está cerrado. Programa el pedido para una hora de apertura.'});
    if(scheduled && !businessOpenAt(business,scheduled)) return res.status(400).json({error:'La hora solicitada queda fuera del horario de apertura del negocio.'});
    if(scheduled && !businessOpenAt(business,new Date(scheduled.getTime()-Math.max(15,Number(business.prepMinutes)||15)*60000))) return res.status(400).json({error:'La preparación debe comenzar dentro del horario de apertura del negocio. Elige una hora posterior.'});
    let verifiedItems=[],verifiedTotal=0;
    for(const raw of o.items){const qty=Number(raw.q);if(!Number.isInteger(qty)||qty<1||qty>99)return res.status(400).json({error:'La cantidad de un producto no es válida.'});const dish=(business.menu||[]).find(m=>m.n===raw.n);const option=dish?.opts?.find(x=>x.l===raw.l);if(!dish||!option||!dish.av)return res.status(400).json({error:'Uno de los productos ya no está disponible. Actualiza el menú.'});const price=Number(option.p);if(!Number.isFinite(price)||price<0||price>1000000)return res.status(400).json({error:'El precio de un producto no es válido. Contacta con el negocio.'});verifiedItems.push({n:String(dish.n),l:String(option.l),p:price,q:qty});verifiedTotal+=price*qty;if(!Number.isFinite(verifiedTotal)||verifiedTotal>100000000)return res.status(400).json({error:'El importe total del pedido supera el límite permitido.'});}
    const prepMinutes=Math.max(15,Math.min(240,Number(business.prepMinutes)||15)); const deliveryMinutes=Math.max(0,Math.min(240,Number(business.deliveryMinutes)||30));
    const readyAt=scheduled?scheduled.toISOString():new Date(now.getTime()+prepMinutes*60000).toISOString(); const deliveryEtaAt=new Date(new Date(readyAt).getTime()+deliveryMinutes*60000).toISOString();
    const payment=String(o.pay||'');if(!['Efectivo','Verifone (tarjeta en la entrega)'].includes(payment))return res.status(400).json({error:'Método de pago no válido.'});
    const saved = { id:Date.now()+Math.floor(Math.random()*1000), rest:business.name, restId:business.id, client:clean(req.auth.name)||'Cliente', phone:req.auth.phone, addr:clean(o.addr), pay:payment, items:verifiedItems, total:Number(verifiedTotal.toFixed(2)), customerId:Number(req.auth.id), ownerId:Number(business.ownerId), status:'recibido', scheduledFor:scheduled?scheduled.toISOString():null, prepMinutes, deliveryMinutes, readyAt, deliveryEtaAt, createdAt:now.toISOString() };
    await pool.query("UPDATE app_state SET payload=jsonb_set(payload,'{orders}',COALESCE(payload->'orders','[]'::jsonb) || $1::jsonb,true),updated_at=NOW() WHERE id=1", [JSON.stringify([saved])]);
    await pool.query('INSERT INTO app_events(user_id,event_type,payload) VALUES($1,$2,$3::jsonb)', [business.ownerId, 'new_order', JSON.stringify({orderId:saved.id,rest:business.name,total:saved.total,createdAt:saved.createdAt,scheduledFor:saved.scheduledFor,readyAt:saved.readyAt,deliveryEtaAt:saved.deliveryEtaAt})]);
    try { await sendPushToUser(business.ownerId, 'FoodTrack · Pedido nuevo', `Nuevo pedido #${saved.id} en ${business.name}. ${scheduled?'Solicitado para '+formatBusinessTime(scheduled):'Lo antes posible'}.`, { type:'new_order', orderId:saved.id, restId:saved.restId, url:'/', tag:`foodtrack-order-${saved.id}` }); }
    catch (pushError) { console.error('No se pudo enviar push al dueño:', pushError.message); }
    res.status(201).json(saved);
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo registrar el pedido.' }); }
});
// Ocultar el historial propio en la vista del cliente sin borrar pedidos ni datos financieros.
app.delete('/api/me/orders/history', auth, async (req,res)=>{
  if(req.auth.role!=='cliente') return res.status(403).json({error:'Esta acción está disponible para clientes.'});
  const c=await pool.connect();
  try{await c.query('BEGIN');const s=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');const u=await c.query('SELECT hidden_order_ids FROM app_users WHERE id=$1 FOR UPDATE',[req.auth.id]);const orders=(s.rows[0]?.payload?.orders||[]).filter(o=>Number(o.customerId)===Number(req.auth.id)||String(o.phone)===String(req.auth.phone));const ids=[...(u.rows[0]?.hidden_order_ids||[]),...orders.map(o=>String(o.id))];await c.query('UPDATE app_users SET hidden_order_ids=$1::jsonb WHERE id=$2',[JSON.stringify([...new Set(ids)]),req.auth.id]);await c.query('COMMIT');res.json({ok:true,hidden:orders.length});}
  catch(e){await c.query('ROLLBACK');console.error(e);res.status(500).json({error:'No se pudo ocultar el historial.'});}finally{c.release();}
});
// Eventos privados: cada usuario recibe únicamente sus propias notificaciones.
app.get('/api/events', auth, async (req,res)=>{
  try { const after=Math.max(0,Number(req.query.after)||0); const r=await pool.query('SELECT id,event_type,payload,created_at FROM app_events WHERE user_id=$1 AND id>$2 ORDER BY id ASC LIMIT 100',[req.auth.id,after]); res.json(r.rows); }
  catch(e){console.error(e);res.status(500).json({error:'No se pudieron consultar las notificaciones.'});}
});
app.post('/api/orders/:id/status', auth, async(req,res)=>{
  if(req.auth.role!=='dueno' && req.auth.role!=='admin') return res.status(403).json({error:'Solo el dueño del negocio puede actualizar el pedido.'});
  const next=String(req.body?.status||''); if(!['preparacion','listo','cancelado'].includes(next)) return res.status(400).json({error:'Estado no válido.'});
  const c=await pool.connect(); try { await c.query('BEGIN'); const q=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE'); const state=q.rows[0]?.payload||{}; const order=(state.orders||[]).find(o=>String(o.id)===String(req.params.id)); if(!order){await c.query('ROLLBACK');return res.status(404).json({error:'Pedido no encontrado.'});}
    const business=(state.restaurants||[]).find(r=>String(r.id)===String(order.restId)); if(req.auth.role==='dueno' && (!business || Number(business.ownerId)!==Number(req.auth.id))){await c.query('ROLLBACK');return res.status(403).json({error:'Este pedido no pertenece a tu negocio.'});}
    if(next==='preparacion' && order.status!=='recibido'){await c.query('ROLLBACK');return res.status(409).json({error:'El pedido ya fue actualizado.'});}
    order.status=next; order.updatedAt=new Date().toISOString(); await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);
    const message=next==='preparacion'?'El negocio aceptó tu pedido y comenzó a prepararlo.':next==='listo'?'Tu pedido está listo.':'El negocio canceló tu pedido.';
    if(order.customerId) await c.query('INSERT INTO app_events(user_id,event_type,payload) VALUES($1,$2,$3::jsonb)',[order.customerId,'order_status',JSON.stringify({orderId:order.id,status:next,rest:order.rest,message})]);
    await c.query('COMMIT');
    if(order.customerId) { try { await sendPushToUser(order.customerId, 'FoodTrack · Estado de tu pedido', message, { type:'order_status', orderId:order.id, status:next, url:'/', tag:`foodtrack-status-${order.id}-${next}` }); } catch (pushError) { console.error('No se pudo enviar push al cliente:', pushError.message); } }
    res.json({ok:true,order});
  }catch(e){await c.query('ROLLBACK');console.error(e);res.status(500).json({error:'No se pudo actualizar el pedido.'});}finally{c.release();}
});

// Un repartidor reclama un pedido listo. La asignación se guarda en PostgreSQL bajo bloqueo transaccional.
app.post('/api/orders/:id/claim',auth,async(req,res)=>{
  if(req.auth.role!=='repartidor')return res.status(403).json({error:'Solo un repartidor puede aceptar una entrega.'});
  const c=await pool.connect();let customerId=null,ownerId=null,orderCopy=null;
  try{
    await c.query('BEGIN');
    const q=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');
    const state=q.rows[0]?.payload||{};
    const order=(state.orders||[]).find(o=>String(o.id)===String(req.params.id));
    if(!order){await c.query('ROLLBACK');return res.status(404).json({error:'Pedido no encontrado.'});}
    if(order.status!=='listo'||order.driverId){await c.query('ROLLBACK');return res.status(409).json({error:'Este pedido ya no está disponible para aceptar.'});}
    order.driverId=Number(req.auth.id);order.driverName=req.auth.name;order.status='aceptado';order.assignedAt=new Date().toISOString();
    const business=(state.restaurants||[]).find(r=>String(r.id)===String(order.restId));
    ownerId=business?.ownerId?Number(business.ownerId):null;customerId=order.customerId?Number(order.customerId):null;
    state.myDeliveries=Array.isArray(state.myDeliveries)?state.myDeliveries:[];
    state.myDeliveries=state.myDeliveries.filter(x=>String(x.id)!==String(order.id));
    state.myDeliveries.push({...order});
    await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);
    if(ownerId)await c.query('INSERT INTO app_events(user_id,event_type,payload) VALUES($1,$2,$3::jsonb)',[ownerId,'driver_assigned',JSON.stringify({orderId:order.id,driverName:req.auth.name,rest:order.rest})]);
    if(customerId)await c.query('INSERT INTO app_events(user_id,event_type,payload) VALUES($1,$2,$3::jsonb)',[customerId,'order_status',JSON.stringify({orderId:order.id,status:'aceptado',rest:order.rest,message:'Un repartidor aceptó tu pedido y va a recogerlo.'})]);
    orderCopy={...order};
    await c.query('COMMIT');
    if(ownerId){try{await sendPushToUser(ownerId,'FoodTrack · Repartidor asignado',`${req.auth.name} aceptó la entrega del pedido #${order.id}.`,{type:'driver_assigned',orderId:order.id,url:'/',tag:`foodtrack-driver-${order.id}`});}catch(e){console.error('No se pudo avisar al dueño:',e.message);}}
    if(customerId){try{await sendPushToUser(customerId,'FoodTrack · Pedido en camino','Un repartidor aceptó tu pedido y va a recogerlo.',{type:'order_status',orderId:order.id,status:'aceptado',url:'/',tag:`foodtrack-status-${order.id}-aceptado`});}catch(e){console.error('No se pudo avisar al cliente:',e.message);}}
    res.json({ok:true,order:orderCopy});
  }catch(e){await c.query('ROLLBACK');console.error(e);res.status(500).json({error:'No se pudo aceptar la entrega.'});}finally{c.release();}
});
// El repartidor asignado confirma la entrega; se conserva el pedido en el historial operativo y financiero.
app.post('/api/orders/:id/delivered',auth,async(req,res)=>{
  if(req.auth.role!=='repartidor')return res.status(403).json({error:'Solo un repartidor puede confirmar la entrega.'});
  const c=await pool.connect();let customerId=null,ownerId=null,orderCopy=null;
  try{
    await c.query('BEGIN');
    const q=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');
    const state=q.rows[0]?.payload||{};
    const order=(state.orders||[]).find(o=>String(o.id)===String(req.params.id));
    if(!order){await c.query('ROLLBACK');return res.status(404).json({error:'Pedido no encontrado.'});}
    if(Number(order.driverId)!==Number(req.auth.id)){await c.query('ROLLBACK');return res.status(403).json({error:'Esta entrega no está asignada a tu cuenta.'});}
    if(order.status!=='aceptado'){await c.query('ROLLBACK');return res.status(409).json({error:'El pedido no está en estado de entrega.'});}
    order.status='entregado';order.deliveredAt=new Date().toISOString();
    const business=(state.restaurants||[]).find(r=>String(r.id)===String(order.restId));
    ownerId=business?.ownerId?Number(business.ownerId):null;customerId=order.customerId?Number(order.customerId):null;
    state.myDeliveries=Array.isArray(state.myDeliveries)?state.myDeliveries:[];
    state.myDeliveries=state.myDeliveries.map(x=>String(x.id)===String(order.id)?{...order}:x);
    await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);
    if(customerId)await c.query('INSERT INTO app_events(user_id,event_type,payload) VALUES($1,$2,$3::jsonb)',[customerId,'order_status',JSON.stringify({orderId:order.id,status:'entregado',rest:order.rest,message:'Tu pedido fue entregado. ¡Gracias por usar FoodTrack!'})]);
    if(ownerId)await c.query('INSERT INTO app_events(user_id,event_type,payload) VALUES($1,$2,$3::jsonb)',[ownerId,'delivery_completed',JSON.stringify({orderId:order.id,driverName:req.auth.name})]);
    orderCopy={...order};
    await c.query('COMMIT');
    if(customerId){try{await sendPushToUser(customerId,'FoodTrack · Pedido entregado','Tu pedido fue entregado. ¡Gracias por usar FoodTrack!',{type:'order_status',orderId:order.id,status:'entregado',url:'/',tag:`foodtrack-status-${order.id}-entregado`});}catch(e){console.error('No se pudo avisar al cliente:',e.message);}}
    res.json({ok:true,order:orderCopy});
  }catch(e){await c.query('ROLLBACK');console.error(e);res.status(500).json({error:'No se pudo confirmar la entrega.'});}finally{c.release();}
});

// Suscripciones y cobros: tablas independientes para no alterar pedidos ni catálogo histórico.
app.get('/api/admin/billing',auth,async(req,res)=>{
  if(req.auth.role!=='admin')return res.status(403).json({error:'Solo el administrador.'});
  try{await applySubscriptionEnforcement();const state=await pool.query("SELECT payload->'restaurants' AS restaurants FROM app_state WHERE id=1");const bills=await pool.query('SELECT * FROM restaurant_billing ORDER BY due_on ASC');const pays=await pool.query('SELECT * FROM restaurant_payments ORDER BY paid_at DESC');const byId=new Map(bills.rows.map(b=>[String(b.restaurant_id),b]));const restaurants=state.rows[0]?.restaurants||[];res.json(restaurants.map(r=>{const b=byId.get(String(r.id));return {restaurant_id:String(r.id),restaurant_name:r.name,business_created_at:r.createdAt||null,billing:b||null,payments:pays.rows.filter(p=>String(p.restaurant_id)===String(r.id)).slice(0,10)};}));}
  catch(e){console.error(e);res.status(500).json({error:'No se pudo consultar la facturación.'});}
});
app.put('/api/admin/billing/:id',auth,async(req,res)=>{
  if(req.auth.role!=='admin')return res.status(403).json({error:'Solo el administrador.'});
  try{const b=req.body||{};const fee=Number(b.fee),due=String(b.dueOn||''),started=String(b.startedOn||localDateString());if(!Number.isFinite(fee)||fee<0||!validDateOnly(due)||!validDateOnly(started)||due<started)return res.status(400).json({error:'Indica una cuota válida y una fecha de vencimiento.'});const state=await pool.query("SELECT 1 FROM app_state WHERE id=1 AND EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(payload->'restaurants','[]'::jsonb)) r WHERE r->>'id'=$1)",[String(req.params.id)]);if(!state.rowCount)return res.status(404).json({error:'Negocio no encontrado.'});const r=await pool.query(`INSERT INTO restaurant_billing(restaurant_id,plan_name,fee,currency,started_on,due_on,grace_days,status) VALUES($1,$2,$3,$4,$5::date,$6,7,'active') ON CONFLICT(restaurant_id) DO UPDATE SET plan_name=EXCLUDED.plan_name,fee=EXCLUDED.fee,currency=EXCLUDED.currency,started_on=EXCLUDED.started_on,due_on=EXCLUDED.due_on,status='active',updated_at=NOW() RETURNING *`,[String(req.params.id),clean(b.planName)||'Mensual',fee,clean(b.currency)||'EUR',started,due]);await pool.query("UPDATE app_state SET payload=jsonb_set(payload,'{restaurants}',(SELECT COALESCE(jsonb_agg(CASE WHEN r->>'id'=$1 THEN r-'subscriptionBlocked' ELSE r END),'[]'::jsonb) FROM jsonb_array_elements(COALESCE(payload->'restaurants','[]'::jsonb)) r),true),updated_at=NOW() WHERE id=1",[String(req.params.id)]);res.json({billing:r.rows[0]});}
  catch(e){console.error(e);res.status(500).json({error:'No se pudo guardar la suscripción.'});}
});
app.post('/api/admin/billing/:id/payments',auth,async(req,res)=>{
  if(req.auth.role!=='admin')return res.status(403).json({error:'Solo el administrador.'});
  try{const b=req.body||{},amount=Number(b.amount),covered=String(b.coveredUntil||'');if(!Number.isFinite(amount)||amount<=0||!validDateOnly(covered)||covered<localDateString())return res.status(400).json({error:'Indica un importe y una fecha cubierta válidos.'});const c=await pool.connect();try{await c.query('BEGIN');const bill=await c.query('SELECT currency FROM restaurant_billing WHERE restaurant_id=$1 FOR UPDATE',[String(req.params.id)]);if(!bill.rows[0]){await c.query('ROLLBACK');return res.status(404).json({error:'Primero configura la suscripción del negocio.'});}const p=await c.query('INSERT INTO restaurant_payments(restaurant_id,amount,currency,covered_until,payment_method,reference,recorded_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[String(req.params.id),amount,bill.rows[0].currency,covered,clean(b.method),clean(b.reference),req.auth.id]);await c.query("UPDATE restaurant_billing SET due_on=$1,status='active',updated_at=NOW() WHERE restaurant_id=$2",[covered,String(req.params.id)]);const state=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');const payload=state.rows[0]?.payload||{};payload.restaurants=(payload.restaurants||[]).map(r=>String(r.id)===String(req.params.id)?{...r,subscriptionBlocked:false}:r);await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(payload)]);await c.query('COMMIT');res.status(201).json({payment:p.rows[0]});}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
  catch(e){console.error(e);res.status(500).json({error:'No se pudo registrar el pago.'});}
});

app.post('/api/location', auth, async (req, res) => {
  try {
    if (req.auth.role !== 'repartidor' && req.auth.role !== 'admin') return res.status(403).json({ error: 'Solo las cuentas de repartidor pueden compartir GPS.' });
    const { lat, lng, accuracy } = req.body || {};
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat)>90 || Math.abs(lng)>180) return res.status(400).json({ error: 'Coordenadas no válidas.' });
    await pool.query(`INSERT INTO driver_locations(user_id,lat,lng,accuracy) VALUES($1,$2,$3,$4)
      ON CONFLICT(user_id) DO UPDATE SET lat=EXCLUDED.lat,lng=EXCLUDED.lng,accuracy=EXCLUDED.accuracy,recorded_at=NOW()`, [req.auth.id,lat,lng,accuracy||null]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo guardar la ubicación.' }); }
});
app.get('/api/locations', auth, async (req, res) => {
  if (req.auth.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede consultar todas las ubicaciones.' });
  try { const r=await pool.query(`SELECT u.name,l.lat,l.lng,l.accuracy,l.recorded_at FROM driver_locations l JOIN app_users u ON u.id=l.user_id ORDER BY l.recorded_at DESC`); res.json(r.rows); }
  catch(e) { console.error(e); res.status(500).json({error:'No se pudieron consultar ubicaciones.'}); }
});
app.put('/api/state', auth, async (req, res) => {
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const q=await client.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');
    const state=q.rows[0]?.payload||{}; const body=req.body||{};
    if(req.auth.role==='admin') {
      const allowed=['restaurants','orders','myDeliveries','notifications','orderSeq','nextRestId','notifCount'];
      for(const k of allowed) if(Object.prototype.hasOwnProperty.call(body,k)) state[k]=body[k];
    } else if(req.auth.role==='dueno') {
      const owned=(state.restaurants||[]).filter(r=>Number(r.ownerId)===Number(req.auth.id));
      const incoming=Array.isArray(body.restaurants)?body.restaurants:[];
      for(const item of incoming){const idx=owned.findIndex(r=>String(r.id)===String(item.id));if(idx<0)throw Object.assign(new Error('Intentaste modificar un negocio que no te pertenece.'),{status:403});owned[idx]={...owned[idx],name:item.name,desc:item.desc,img:item.img,svc:item.svc,menu:item.menu};}
      state.restaurants=(state.restaurants||[]).map(r=>{const updated=owned.find(x=>String(x.id)===String(r.id));return updated||r});
    } else if(req.auth.role==='repartidor') {
      if(Array.isArray(body.myDeliveries)) state.myDeliveries=body.myDeliveries;
    } else return res.status(403).json({error:'Tu cuenta no tiene permiso para guardar estos cambios.'});
    await client.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);
    await client.query('COMMIT'); res.json({ok:true,savedAt:new Date().toISOString()});
  } catch(e) { await client.query('ROLLBACK'); console.error(e); res.status(e.status||500).json({error:e.status?e.message:'No se pudieron guardar los datos.'}); }
  finally {client.release();}
});
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().then(() => app.listen(PORT, () => console.log(`FoodTrack Pro escuchando en ${PORT}`))).catch(e => { console.error('Error iniciando PostgreSQL:', e); process.exit(1); });

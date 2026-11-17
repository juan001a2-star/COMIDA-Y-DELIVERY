'use strict';
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

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
  await pool.query("UPDATE app_users SET username=phone WHERE username IS NULL OR username=''");
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS app_users_username_unique ON app_users(LOWER(username))');
  await pool.query(`CREATE TABLE IF NOT EXISTS app_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1), payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query("INSERT INTO app_state(id,payload) VALUES(1,'{}'::jsonb) ON CONFLICT(id) DO NOTHING");
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
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  try { req.auth = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Sesión caducada. Inicia sesión de nuevo.' }); }
}
const safeUser = u => ({ id: u.id, name: u.name, username: u.username, addr: u.address || '', phone: u.phone, role: u.role });
const clean = v => String(v || '').trim();
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, address = '', phone, password } = req.body || {};
    const username = clean(req.body?.username || phone).toLowerCase();
    if (!clean(name) || !clean(phone) || !username || !password || String(password).length < 8) return res.status(400).json({ error: 'Indica nombre, usuario, teléfono y contraseña de al menos 8 caracteres.' });
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
    if (!user || !(await bcrypt.compare(String(req.body?.password || ''), user.password_hash))) return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    res.json({ token: signToken(user), user: safeUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo iniciar sesión.' }); }
});
app.post('/api/admin/users', auth, async (req, res) => {
  try {
    if (req.auth.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede crear cuentas internas.' });
    const { name, address = '', phone, password, role } = req.body || {};
    const username = clean(req.body?.username).toLowerCase();
    if (!clean(name) || !username || !clean(phone) || !password || String(password).length < 8 || !['dueno','repartidor'].includes(role)) return res.status(400).json({ error: 'Completa nombre, usuario, teléfono y contraseña (mínimo 8 caracteres). Rol permitido: dueño o repartidor.' });
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
  const r=await pool.query("SELECT id,name,username,address AS addr,phone,role,created_at FROM app_users WHERE role IN ('dueno','repartidor','cliente') ORDER BY created_at DESC");
  res.json(r.rows);
});
app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id,name,username,address,phone,role FROM app_users WHERE id=$1', [req.auth.id]);
  if (!r.rows[0]) return res.status(401).json({ error: 'Cuenta no encontrada.' });
  res.json({ user: safeUser(r.rows[0]) });
});
function visibleState(payload, user) {
  const state = structuredClone(payload || {});
  const all = Array.isArray(state.restaurants) ? state.restaurants : [];
  if (user.role === 'dueno') state.restaurants = all.filter(r => Number(r.ownerId) === Number(user.id));
  if (user.role === 'cliente') {
    state.restaurants = all.filter(r => !r.blocked);
    state.orders = (state.orders || []).filter(o => String(o.phone) === String(user.phone));
    state.myDeliveries = [];
    state.notifications = [];
  }
  if (user.role === 'dueno') {
    const ids = new Set(state.restaurants.map(r => String(r.id)));
    state.orders = (state.orders || []).filter(o => ids.has(String(o.restId)));
    state.myDeliveries = [];
  }
  if (user.role === 'repartidor') state.myDeliveries = (state.myDeliveries || []).filter(o => Number(o.driverId) === Number(user.id));
  return state;
}
app.get('/api/state', auth, async (req, res) => {
  try { const r = await pool.query('SELECT payload FROM app_state WHERE id=1'); res.json(visibleState(r.rows[0]?.payload, req.auth)); }
  catch (e) { console.error(e); res.status(500).json({ error: 'No se pudieron cargar los datos.' }); }
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
  try {
    if(!['dueno','admin'].includes(req.auth.role)) return res.status(403).json({error:'Solo un dueño o administrador puede crear negocios.'});
    const b=req.body||{}; if(!clean(b.name)) return res.status(400).json({error:'El nombre del negocio es obligatorio.'});
    const id=Date.now()+Math.floor(Math.random()*1000);
    const item={id,name:clean(b.name),desc:clean(b.desc)||'Nuevo negocio',img:clean(b.img)||'',svc:Array.isArray(b.svc)?b.svc:['Delivery propio'],menu:[],blocked:false,ownerId:req.auth.role==='dueno'?Number(req.auth.id):(Number(b.ownerId)||null)};
    await pool.query(`UPDATE app_state SET payload=jsonb_set(payload,'{restaurants}',COALESCE(payload->'restaurants','[]'::jsonb) || $1::jsonb,true),updated_at=NOW() WHERE id=1`,[JSON.stringify([item])]);
    res.status(201).json({restaurant:item});
  }catch(e){console.error(e);res.status(500).json({error:'No se pudo crear el negocio.'});}
});
app.put('/api/restaurants/:id', auth, async (req,res)=>{
  try {
    const id=String(req.params.id), b=req.body||{};
    const q=await pool.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');
    const state=q.rows[0]?.payload||{}, list=state.restaurants||[];
    const idx=list.findIndex(x=>String(x.id)===id); if(idx<0)return res.status(404).json({error:'Negocio no encontrado.'});
    const old=list[idx]; if(req.auth.role!=='admin' && !(req.auth.role==='dueno' && Number(old.ownerId)===Number(req.auth.id)))return res.status(403).json({error:'No tienes permiso para modificar este negocio.'});
    const allowed=req.auth.role==='admin'?['name','desc','img','svc','menu','blocked','ownerId']:['name','desc','img','svc','menu'];
    for(const k of allowed) if(Object.prototype.hasOwnProperty.call(b,k)) old[k]=b[k];
    list[idx]=old; state.restaurants=list;
    await pool.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);
    res.json({restaurant:old});
  }catch(e){console.error(e);res.status(500).json({error:'No se pudo guardar el negocio.'});}
});
app.put('/api/admin/restaurants/:id/owner', auth, async (req,res)=>{
  if(req.auth.role!=='admin') return res.status(403).json({error:'Solo el administrador puede asignar negocios.'});
  const ownerId=req.body?.ownerId===null?null:Number(req.body?.ownerId);
  try{
    if(ownerId!==null){const u=await pool.query("SELECT id FROM app_users WHERE id=$1 AND role='dueno'",[ownerId]);if(!u.rows.length)return res.status(400).json({error:'La cuenta seleccionada no es un dueño válido.'});}
    const c=await pool.connect();try{await c.query('BEGIN');const q=await c.query('SELECT payload FROM app_state WHERE id=1 FOR UPDATE');const state=q.rows[0]?.payload||{};const r=(state.restaurants||[]).find(x=>String(x.id)===String(req.params.id));if(!r){await c.query('ROLLBACK');return res.status(404).json({error:'Negocio no encontrado.'});}r.ownerId=ownerId;await c.query('UPDATE app_state SET payload=$1::jsonb,updated_at=NOW() WHERE id=1',[JSON.stringify(state)]);await c.query('COMMIT');res.json({ok:true,restaurant:r});}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
  }catch(e){console.error(e);res.status(500).json({error:'No se pudo asignar el negocio.'});}
});
app.post('/api/orders', auth, async (req, res) => {
  try {
    if (req.auth.role !== 'cliente') return res.status(403).json({ error: 'Solo los clientes pueden crear pedidos.' });
    const o = req.body || {};
    if (!o.restId || !Array.isArray(o.items) || !o.items.length || !Number.isFinite(Number(o.total))) return res.status(400).json({ error: 'Pedido incompleto.' });
    const saved = { ...o, id: Date.now(), phone: req.auth.phone, status: 'recibido', createdAt: new Date().toISOString() };
    await pool.query("UPDATE app_state SET payload=jsonb_set(payload,'{orders}',COALESCE(payload->'orders','[]'::jsonb) || $1::jsonb,true),updated_at=NOW() WHERE id=1", [JSON.stringify([saved])]);
    res.status(201).json(saved);
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo registrar el pedido.' }); }
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
      if(Array.isArray(body.orders)) { const ids=new Set(owned.map(r=>String(r.id))); const old=state.orders||[]; for(const incomingOrder of body.orders){const idx=old.findIndex(o=>String(o.id)===String(incomingOrder.id)&&ids.has(String(o.restId)));if(idx>=0)old[idx]={...old[idx],status:incomingOrder.status};} state.orders=old; }
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

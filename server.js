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
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL DEFAULT '',
    phone TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'cliente' CHECK (role IN ('cliente','dueno','repartidor','admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
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
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query(`INSERT INTO app_users(name,address,phone,password_hash,role)
      VALUES('Administrador FoodTrack','', $1, $2, 'admin')
      ON CONFLICT(phone) DO UPDATE SET password_hash=EXCLUDED.password_hash, role='admin'`, [process.env.ADMIN_PHONE, hash]);
    console.log('Cuenta administradora inicial configurada.');
  }
}
function signToken(user) { return jwt.sign({ id: user.id, phone: user.phone, role: user.role }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  try { req.auth = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Sesión caducada. Inicia sesión de nuevo.' }); }
}
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, address = '', phone, password } = req.body || {};
    if (!name || !phone || !password || String(password).length < 8) return res.status(400).json({ error: 'Indica nombre, teléfono y contraseña de al menos 8 caracteres.' });
    const hash = await bcrypt.hash(String(password), 12);
    // El registro público siempre crea clientes. Los roles privilegiados se asignan fuera del registro público.
    const result = await pool.query(`INSERT INTO app_users(name,address,phone,password_hash,role)
      VALUES($1,$2,$3,$4,'cliente') RETURNING id,name,address AS addr,phone,role`, [String(name).trim(), String(address), String(phone).trim(), hash]);
    const user = result.rows[0];
    res.status(201).json({ token: signToken(user), user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese teléfono ya tiene una cuenta. Inicia sesión.' });
    console.error(e); res.status(500).json({ error: 'No se pudo crear la cuenta.' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body || {};
    const result = await pool.query('SELECT * FROM app_users WHERE phone=$1', [String(phone || '').trim()]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(String(password || ''), user.password_hash))) return res.status(401).json({ error: 'Teléfono o contraseña incorrectos.' });
    const safeUser = { id: user.id, name: user.name, addr: user.address, phone: user.phone, role: user.role };
    res.json({ token: signToken(user), user: safeUser });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo iniciar sesión.' }); }
});
app.post('/api/admin/users', auth, async (req, res) => {
  try {
    if (req.auth.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede crear cuentas internas.' });
    const { name, address = '', phone, password, role } = req.body || {};
    if (!name || !phone || !password || String(password).length < 8 || !['dueno','repartidor'].includes(role)) return res.status(400).json({ error: 'Datos incompletos. Rol permitido: dueno o repartidor; contraseña mínima: 8 caracteres.' });
    const hash = await bcrypt.hash(String(password), 12);
    const r = await pool.query(`INSERT INTO app_users(name,address,phone,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING id,name,address AS addr,phone,role`, [String(name).trim(),String(address),String(phone).trim(),hash,role]);
    res.status(201).json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese teléfono ya está registrado.' });
    console.error(e); res.status(500).json({ error: 'No se pudo crear la cuenta interna.' });
  }
});
app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id,name,address AS addr,phone,role FROM app_users WHERE id=$1', [req.auth.id]);
  if (!r.rows[0]) return res.status(401).json({ error: 'Cuenta no encontrada.' });
  res.json({ user: r.rows[0] });
});
// Estado compartido persistido en PostgreSQL. Solo usuarios autenticados pueden leer o guardar.
app.get('/api/state', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT payload FROM app_state WHERE id=1');
    const state = r.rows[0]?.payload || {};
    if (req.auth.role === 'cliente') {
      state.orders = (state.orders || []).filter(o => String(o.phone) === String(req.auth.phone));
      state.myDeliveries = [];
      state.notifications = [];
    }
    res.json(state);
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudieron cargar los datos.' }); }
});
app.post('/api/state/bootstrap', auth, async (req, res) => {
  try {
    const restaurants = req.body?.restaurants;
    if (!Array.isArray(restaurants) || !restaurants.length) return res.status(400).json({ error: 'No hay restaurantes iniciales.' });
    const current = await pool.query("SELECT payload->'restaurants' AS restaurants FROM app_state WHERE id=1");
    if (Array.isArray(current.rows[0]?.restaurants) && current.rows[0].restaurants.length) return res.json({ ok: true, alreadyInitialized: true });
    await pool.query("UPDATE app_state SET payload=jsonb_set(payload,'{restaurants}',$1::jsonb,true),updated_at=NOW() WHERE id=1", [JSON.stringify(restaurants)]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudo inicializar el catálogo.' }); }
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
  if (req.auth.role !== 'admin' && req.auth.role !== 'dueno') return res.status(403).json({ error: 'No tienes permiso para consultar ubicaciones.' });
  try { const r=await pool.query(`SELECT u.name,l.lat,l.lng,l.accuracy,l.recorded_at FROM driver_locations l JOIN app_users u ON u.id=l.user_id ORDER BY l.recorded_at DESC`); res.json(r.rows); }
  catch(e) { console.error(e); res.status(500).json({error:'No se pudieron consultar ubicaciones.'}); }
});
app.put('/api/state', auth, async (req, res) => {
  try {
    if (!['admin','dueno','repartidor'].includes(req.auth.role)) return res.status(403).json({ error: 'Tu cuenta no tiene permiso para modificar el estado general.' });
    const allowed = ['restaurants','orders','myDeliveries','notifications','orderSeq','nextRestId','notifCount'];
    const payload = {};
    for (const key of allowed) if (Object.prototype.hasOwnProperty.call(req.body || {}, key)) payload[key] = req.body[key];
    if (Object.keys(payload).length === 0) return res.status(400).json({ error: 'No hay datos válidos para guardar.' });
    await pool.query(`UPDATE app_state SET payload = payload || $1::jsonb, updated_at=NOW() WHERE id=1`, [JSON.stringify(payload)]);
    res.json({ ok: true, savedAt: new Date().toISOString() });
  } catch (e) { console.error(e); res.status(500).json({ error: 'No se pudieron guardar los datos.' }); }
});
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().then(() => app.listen(PORT, () => console.log(`FoodTrack Pro escuchando en ${PORT}`))).catch(e => { console.error('Error iniciando PostgreSQL:', e); process.exit(1); });

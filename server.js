'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');
const calc = require('./lib/calc');

const {
  SHIFTS,
  EXCEPTION_KINDS,
  localParts,
  localToUtc,
  isValidDate,
  isWorkday,
  addDays,
  haversineMeters,
  isLate,
  minutesLate,
  toMinutes,
  summarize,
} = calc;

// ---------------------------------------------------------------------------
// Configuración
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const PHOTO_DIR = path.join(DATA_DIR, 'photos');
const IS_PROD = process.env.NODE_ENV === 'production';

fs.mkdirSync(PHOTO_DIR, { recursive: true });

let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  if (IS_PROD) {
    console.error('Falta la variable de entorno ADMIN_PASSWORD. Defínela antes de iniciar en producción.');
    process.exit(1);
  }
  ADMIN_PASSWORD = 'admin123';
  console.warn('⚠  ADMIN_PASSWORD no definida: usando "admin123" (solo para pruebas locales).');
}

function loadSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const file = path.join(DATA_DIR, 'session.key');
  try {
    return fs.readFileSync(file, 'utf8').trim();
  } catch {
    const s = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(file, s, { mode: 0o600 });
    return s;
  }
}
const SECRET = loadSecret();

// ---------------------------------------------------------------------------
// Base de datos
// ---------------------------------------------------------------------------
const db = new Database(path.join(DATA_DIR, 'checador.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  shift TEXT NOT NULL,
  pin_salt TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  start_date TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  photo_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS punches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  type TEXT NOT NULL CHECK (type IN ('in','out')),
  ts TEXT NOT NULL,
  local_date TEXT NOT NULL,
  lat REAL,
  lng REAL,
  accuracy REAL,
  distance_m REAL,
  source TEXT NOT NULL DEFAULT 'app',
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_punches_emp_date ON punches (employee_id, local_date);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exceptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER REFERENCES employees(id),
  date_from TEXT NOT NULL,
  date_to TEXT NOT NULL,
  kind TEXT NOT NULL,
  note TEXT
);
`);

const DEFAULTS = {
  site_name: 'Centro de trabajo',
  site_lat: '',
  site_lng: '',
  site_radius_m: '150',
  max_accuracy_m: '80',
  late_tolerance_min: '10',
  break_min: '0',
  early_window_min: '120',
};

function getSettings() {
  const raw = { ...DEFAULTS };
  for (const r of db.prepare('SELECT key, value FROM settings').all()) raw[r.key] = r.value;
  return {
    site_name: raw.site_name,
    site_lat: raw.site_lat === '' ? null : Number(raw.site_lat),
    site_lng: raw.site_lng === '' ? null : Number(raw.site_lng),
    site_radius_m: Number(raw.site_radius_m),
    max_accuracy_m: Number(raw.max_accuracy_m),
    late_tolerance_min: Number(raw.late_tolerance_min),
    break_min: Number(raw.break_min),
    early_window_min: Number(raw.early_window_min),
  };
}

const setSetting = db.prepare(
  'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
);

// ---------------------------------------------------------------------------
// Utilidades de seguridad
// ---------------------------------------------------------------------------
function hashPin(pin, salt) {
  return crypto.scryptSync(pin, salt, 32).toString('hex');
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function verify(token) {
  if (typeof token !== 'string') return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!safeEqual(mac, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function setSession(req, res, name, payload, maxAgeMs) {
  const token = sign({ ...payload, exp: Date.now() + maxAgeMs });
  const flags = ['Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${Math.floor(maxAgeMs / 1000)}`];
  if (req.secure) flags.push('Secure');
  res.append('Set-Cookie', `${name}=${encodeURIComponent(token)}; ${flags.join('; ')}`);
}

function clearSession(res, name) {
  res.append('Set-Cookie', `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

// Limitador sencillo de intentos fallidos de acceso.
const failures = new Map();
const MAX_FAILS = 5;
const LOCK_MS = 10 * 60 * 1000;

function lockedFor(key) {
  const f = failures.get(key);
  if (f && f.until && f.until > Date.now()) return Math.ceil((f.until - Date.now()) / 60000);
  return 0;
}
function registerFail(key) {
  const f = failures.get(key) || { count: 0, until: 0 };
  if (f.until && f.until <= Date.now()) {
    f.count = 0;
    f.until = 0;
  }
  f.count += 1;
  if (f.count >= MAX_FAILS) f.until = Date.now() + LOCK_MS;
  failures.set(key, f);
}
function clearFails(key) {
  failures.delete(key);
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'geolocation=(self), camera=(self)',
    'Content-Security-Policy':
      "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
  });
  next();
});

app.use(express.json({ limit: '2mb' }));

// Las peticiones que cambian datos deben ser JSON (mitiga CSRF junto con SameSite=Lax).
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && !req.is('application/json')) {
    return res.status(415).json({ message: 'Se esperaba JSON.' });
  }
  next();
});

app.use(
  express.static(path.join(__dirname, 'public'), {
    extensions: ['html'],
    setHeaders: (res) => res.set('Cache-Control', 'no-cache'),
  })
);

app.get('/healthz', (req, res) => res.json({ ok: true }));

function fail(res, status, message, extra = {}) {
  return res.status(status).json({ message, ...extra });
}

function currentSession(req) {
  const c = parseCookies(req);
  return {
    emp: verify(c.emp),
    admin: verify(c.adm),
  };
}

function requireEmployee(req, res, next) {
  const { emp } = currentSession(req);
  if (!emp || emp.role !== 'emp') return fail(res, 401, 'Inicia sesión para continuar.');
  const row = db.prepare('SELECT * FROM employees WHERE id = ?').get(emp.id);
  if (!row || !row.active) return fail(res, 403, 'Tu usuario está inactivo. Habla con tu administrador.');
  req.employee = row;
  next();
}

function requireAdmin(req, res, next) {
  const { admin } = currentSession(req);
  if (!admin || admin.role !== 'admin') return fail(res, 401, 'Acceso de administrador requerido.');
  next();
}

function publicEmployee(e) {
  return {
    id: e.id,
    name: e.name,
    shift: e.shift,
    shift_label: SHIFTS[e.shift].label,
    shift_start: SHIFTS[e.shift].start,
    shift_end: SHIFTS[e.shift].end,
    start_date: e.start_date,
    active: !!e.active,
    photo_url: e.photo_version ? `/api/photo/${e.id}?v=${e.photo_version}` : null,
  };
}

// ---------------------------------------------------------------------------
// Fotos
// ---------------------------------------------------------------------------
// Valida la foto (JPEG reducido por el navegador) antes de tocar la base de datos.
function parsePhoto(dataUrl) {
  const prefix = 'data:image/jpeg;base64,';
  if (typeof dataUrl !== 'string' || !dataUrl.startsWith(prefix)) {
    throw new Error('La foto debe ser una imagen JPEG.');
  }
  const buf = Buffer.from(dataUrl.slice(prefix.length), 'base64');
  if (buf.length < 500 || buf.length > 900 * 1024) throw new Error('La foto es demasiado grande o está vacía.');
  if (buf[0] !== 0xff || buf[1] !== 0xd8) throw new Error('El archivo no es una imagen JPEG válida.');
  return buf;
}

function writePhoto(employeeId, buf) {
  fs.writeFileSync(path.join(PHOTO_DIR, `${employeeId}.jpg`), buf);
}

app.get('/api/photo/:id', (req, res) => {
  const id = Number(req.params.id);
  const { emp, admin } = currentSession(req);
  const allowed = (admin && admin.role === 'admin') || (emp && emp.role === 'emp' && emp.id === id);
  if (!allowed) return fail(res, 401, 'No autorizado.');
  const file = path.join(PHOTO_DIR, `${id}.jpg`);
  if (!Number.isInteger(id) || !fs.existsSync(file)) return fail(res, 404, 'Sin foto.');
  res.set('Cache-Control', 'private, max-age=86400');
  res.type('image/jpeg').sendFile(file);
});

// ---------------------------------------------------------------------------
// Público / empleado
// ---------------------------------------------------------------------------
app.get('/api/config', (req, res) => {
  const s = getSettings();
  res.json({
    site_name: s.site_name,
    configured: s.site_lat != null && s.site_lng != null,
    tz: calc.TZ,
    shifts: SHIFTS,
  });
});

app.get('/api/employees/public', (req, res) => {
  const rows = db.prepare('SELECT id, name FROM employees WHERE active = 1 ORDER BY name COLLATE NOCASE').all();
  res.json(rows);
});

app.post('/api/login', (req, res) => {
  const id = Number(req.body.employee_id);
  const pin = String(req.body.pin || '');
  const key = `emp:${req.ip}:${id}`;
  const wait = lockedFor(key);
  if (wait) return fail(res, 429, `Demasiados intentos. Intenta de nuevo en ${wait} min.`);

  const e = Number.isInteger(id) ? db.prepare('SELECT * FROM employees WHERE id = ? AND active = 1').get(id) : null;
  if (!e || !safeEqual(hashPin(pin, e.pin_salt), e.pin_hash)) {
    registerFail(key);
    return fail(res, 401, 'Nombre o PIN incorrecto.');
  }
  clearFails(key);
  setSession(req, res, 'emp', { role: 'emp', id: e.id }, 30 * 24 * 3600 * 1000);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  clearSession(res, 'emp');
  res.json({ ok: true });
});

function monthRange(month, today) {
  const m = /^(\d{4})-(\d{2})$/.test(month || '') ? month : today.slice(0, 7);
  const from = `${m}-01`;
  const [y, mo] = m.split('-').map(Number);
  const last = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  return { month: m, from, to: `${m}-${String(last).padStart(2, '0')}` };
}

function loadPunches(employeeId, from, to) {
  // Margen de un día a cada lado por el cambio de zona; summarize filtra por fecha local.
  return db
    .prepare('SELECT id, type, ts FROM punches WHERE employee_id = ? AND local_date BETWEEN ? AND ? ORDER BY ts')
    .all(employeeId, from, to);
}

function loadExceptions(from, to) {
  return db.prepare('SELECT * FROM exceptions WHERE date_to >= ? AND date_from <= ?').all(from, to);
}

function nextAction(todayPunches) {
  const hasIn = todayPunches.some((p) => p.type === 'in');
  if (!hasIn) return 'in';
  const firstIn = todayPunches.find((p) => p.type === 'in');
  const hasOut = todayPunches.some((p) => p.type === 'out' && p.ts > firstIn.ts);
  return hasOut ? 'done' : 'out';
}

app.get('/api/me/status', requireEmployee, (req, res) => {
  const e = req.employee;
  const s = getSettings();
  const now = new Date();
  const lp = localParts(now);
  const rows = db
    .prepare('SELECT type, ts, distance_m FROM punches WHERE employee_id = ? AND local_date = ? ORDER BY ts')
    .all(e.id, lp.date);
  const month = monthRange(null, lp.date);
  const report = summarize({
    employee: e,
    punches: loadPunches(e.id, month.from, month.to),
    exceptions: loadExceptions(month.from, month.to),
    from: month.from,
    to: month.to,
    now,
    settings: s,
  });
  res.json({
    employee: publicEmployee(e),
    site_name: s.site_name,
    configured: s.site_lat != null && s.site_lng != null,
    max_accuracy_m: s.max_accuracy_m,
    server_time: now.toISOString(),
    today: {
      date: lp.date,
      workday: isWorkday(lp.date),
      next: isWorkday(lp.date) ? nextAction(rows) : 'off',
      punches: rows.map((p) => ({
        type: p.type,
        time: localParts(p.ts).time,
        distance_m: p.distance_m == null ? null : Math.round(p.distance_m),
      })),
    },
    month: { month: month.month, totals: report.totals },
  });
});

app.get('/api/me/report', requireEmployee, (req, res) => {
  const e = req.employee;
  const now = new Date();
  const range = monthRange(req.query.month, localParts(now).date);
  const report = summarize({
    employee: e,
    punches: loadPunches(e.id, range.from, range.to),
    exceptions: loadExceptions(range.from, range.to),
    from: range.from,
    to: range.to,
    now,
    settings: getSettings(),
  });
  res.json({ month: range.month, ...report });
});

app.post('/api/punch', requireEmployee, (req, res) => {
  const e = req.employee;
  const s = getSettings();

  if (s.site_lat == null || s.site_lng == null) {
    return fail(res, 409, 'El administrador aún no configura la ubicación del centro de trabajo.', {
      code: 'sin_configurar',
    });
  }

  const lat = Number(req.body.lat);
  const lng = Number(req.body.lng);
  const accuracy = Number(req.body.accuracy);
  const positionTs = Number(req.body.position_ts);
  if (
    !Number.isFinite(lat) || !Number.isFinite(lng) || !Number.isFinite(accuracy) ||
    lat < -90 || lat > 90 || lng < -180 || lng > 180 || accuracy < 0 || accuracy > 100000
  ) {
    return fail(res, 400, 'No se recibió una ubicación válida.', { code: 'ubicacion_invalida' });
  }

  const now = new Date();
  if (!Number.isFinite(positionTs) || Math.abs(now.getTime() - positionTs) > 60 * 1000) {
    return fail(res, 400, 'La ubicación está desactualizada. Vuelve a intentarlo para tomar una lectura nueva.', {
      code: 'ubicacion_vieja',
    });
  }

  if (accuracy > s.max_accuracy_m) {
    return fail(
      res,
      422,
      `La precisión del GPS es de ±${Math.round(accuracy)} m y se requiere ±${s.max_accuracy_m} m o mejor. Sal a un lugar abierto o activa la ubicación de alta precisión e inténtalo de nuevo.`,
      { code: 'precision', accuracy_m: Math.round(accuracy) }
    );
  }

  const distance = haversineMeters(lat, lng, s.site_lat, s.site_lng);
  if (distance > s.site_radius_m) {
    return fail(
      res,
      403,
      `Estás a ${Math.round(distance)} m de ${s.site_name}. Debes estar dentro de ${s.site_radius_m} m para registrar tu checada.`,
      { code: 'fuera_de_zona', distance_m: Math.round(distance) }
    );
  }

  const lp = localParts(now);
  if (!isWorkday(lp.date)) {
    return fail(res, 422, 'Hoy es domingo, no es día laborable.', { code: 'domingo' });
  }

  const todayRows = db
    .prepare('SELECT type, ts FROM punches WHERE employee_id = ? AND local_date = ? ORDER BY ts')
    .all(e.id, lp.date);
  const next = nextAction(todayRows);
  if (next === 'done') {
    return fail(res, 409, 'Ya registraste tu entrada y salida de hoy.', { code: 'completo' });
  }

  const last = todayRows[todayRows.length - 1];
  if (last && now - new Date(last.ts) < 60 * 1000) {
    return fail(res, 429, 'Acabas de checar. Espera un minuto antes de volver a hacerlo.', { code: 'repetida' });
  }

  if (next === 'in') {
    const earliest = toMinutes(SHIFTS[e.shift].start) - s.early_window_min;
    if (lp.minutes < earliest) {
      const h = String(Math.floor(earliest / 60)).padStart(2, '0');
      const m = String(earliest % 60).padStart(2, '0');
      return fail(res, 422, `Aún es muy temprano para tu entrada. Puedes checar desde las ${h}:${m}.`, {
        code: 'muy_temprano',
      });
    }
  }

  const info = db
    .prepare(
      `INSERT INTO punches (employee_id, type, ts, local_date, lat, lng, accuracy, distance_m, source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'app')`
    )
    .run(e.id, next, now.toISOString(), lp.date, lat, lng, accuracy, distance);

  const result = {
    id: info.lastInsertRowid,
    type: next,
    time: lp.time,
    date: lp.date,
    distance_m: Math.round(distance),
    accuracy_m: Math.round(accuracy),
  };
  if (next === 'in') {
    result.late = isLate(lp.minutes, e.shift, s.late_tolerance_min);
    result.minutes_late = minutesLate(lp.minutes, e.shift);
  }
  res.json(result);
});

// ---------------------------------------------------------------------------
// Administrador
// ---------------------------------------------------------------------------
app.post('/api/admin/login', (req, res) => {
  const key = `adm:${req.ip}`;
  const wait = lockedFor(key);
  if (wait) return fail(res, 429, `Demasiados intentos. Intenta de nuevo en ${wait} min.`);
  if (!safeEqual(String(req.body.password || ''), ADMIN_PASSWORD)) {
    registerFail(key);
    return fail(res, 401, 'Contraseña incorrecta.');
  }
  clearFails(key);
  setSession(req, res, 'adm', { role: 'admin' }, 12 * 3600 * 1000);
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  clearSession(res, 'adm');
  res.json({ ok: true });
});

app.get('/api/admin/session', (req, res) => {
  const { admin } = currentSession(req);
  res.json({ admin: !!(admin && admin.role === 'admin') });
});

app.get('/api/admin/settings', requireAdmin, (req, res) => {
  res.json({ ...getSettings(), shifts: SHIFTS, exception_kinds: EXCEPTION_KINDS, tz: calc.TZ });
});

function numIn(v, min, max, label) {
  const n = Number(v);
  if (v === '' || v == null || !Number.isFinite(n) || n < min || n > max) {
    throw new Error(`${label} debe estar entre ${min} y ${max}.`);
  }
  return n;
}

app.put('/api/admin/settings', requireAdmin, (req, res) => {
  try {
    const b = req.body;
    const name = String(b.site_name || '').trim();
    if (!name || name.length > 80) throw new Error('El nombre del centro de trabajo es obligatorio (máx. 80 caracteres).');
    const lat = numIn(b.site_lat, -90, 90, 'La latitud');
    const lng = numIn(b.site_lng, -180, 180, 'La longitud');
    const next = {
      site_name: name,
      site_lat: String(lat),
      site_lng: String(lng),
      site_radius_m: String(numIn(b.site_radius_m, 20, 2000, 'El radio permitido (m)')),
      max_accuracy_m: String(numIn(b.max_accuracy_m, 10, 500, 'La precisión máxima (m)')),
      late_tolerance_min: String(numIn(b.late_tolerance_min, 0, 120, 'La tolerancia de retardo (min)')),
      break_min: String(numIn(b.break_min, 0, 180, 'El descanso descontado (min)')),
      early_window_min: String(numIn(b.early_window_min, 0, 480, 'La anticipación permitida (min)')),
    };
    const tx = db.transaction(() => {
      for (const [k, v] of Object.entries(next)) setSetting.run(k, v);
    });
    tx();
    res.json(getSettings());
  } catch (err) {
    fail(res, 400, err.message);
  }
});

app.get('/api/admin/employees', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM employees ORDER BY active DESC, name COLLATE NOCASE').all();
  res.json(rows.map(publicEmployee));
});

function validateEmployeeBody(b, { creating }) {
  const out = {};
  if (creating || b.name !== undefined) {
    const name = String(b.name || '').trim();
    if (!name || name.length > 80) throw new Error('El nombre es obligatorio (máx. 80 caracteres).');
    out.name = name;
  }
  if (creating || b.shift !== undefined) {
    if (!SHIFTS[b.shift]) throw new Error('Turno inválido.');
    out.shift = b.shift;
  }
  if (creating || b.start_date !== undefined) {
    if (!isValidDate(b.start_date)) throw new Error('La fecha de ingreso no es válida.');
    out.start_date = b.start_date;
  }
  if (creating || (b.pin !== undefined && b.pin !== '')) {
    if (!/^\d{4,6}$/.test(String(b.pin || ''))) throw new Error('El PIN debe tener de 4 a 6 dígitos.');
    out.pin = String(b.pin);
  }
  if (b.active !== undefined) out.active = b.active ? 1 : 0;
  return out;
}

app.post('/api/admin/employees', requireAdmin, (req, res) => {
  try {
    const v = validateEmployeeBody(req.body, { creating: true });
    const photo = req.body.photo ? parsePhoto(req.body.photo) : null;
    const salt = crypto.randomBytes(16).toString('hex');
    const info = db
      .prepare(
        `INSERT INTO employees (name, shift, pin_salt, pin_hash, start_date, photo_version, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(v.name, v.shift, salt, hashPin(v.pin, salt), v.start_date, photo ? Date.now() : 0, new Date().toISOString());
    const id = Number(info.lastInsertRowid);
    if (photo) writePhoto(id, photo);
    res.status(201).json(publicEmployee(db.prepare('SELECT * FROM employees WHERE id = ?').get(id)));
  } catch (err) {
    fail(res, 400, err.message);
  }
});

app.put('/api/admin/employees/:id', requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const cur = db.prepare('SELECT * FROM employees WHERE id = ?').get(id);
    if (!cur) return fail(res, 404, 'Empleado no encontrado.');
    const v = validateEmployeeBody(req.body, { creating: false });
    const sets = [];
    const args = [];
    for (const k of ['name', 'shift', 'start_date', 'active']) {
      if (v[k] !== undefined) {
        sets.push(`${k} = ?`);
        args.push(v[k]);
      }
    }
    if (v.pin) {
      const salt = crypto.randomBytes(16).toString('hex');
      sets.push('pin_salt = ?', 'pin_hash = ?');
      args.push(salt, hashPin(v.pin, salt));
    }
    const photo = req.body.photo ? parsePhoto(req.body.photo) : null;
    if (photo) {
      sets.push('photo_version = ?');
      args.push(Date.now());
    }
    if (sets.length) db.prepare(`UPDATE employees SET ${sets.join(', ')} WHERE id = ?`).run(...args, id);
    if (photo) writePhoto(id, photo);
    res.json(publicEmployee(db.prepare('SELECT * FROM employees WHERE id = ?').get(id)));
  } catch (err) {
    fail(res, 400, err.message);
  }
});

function parseRange(q, now) {
  const today = localParts(now).date;
  const from = q.from || `${today.slice(0, 7)}-01`;
  const to = q.to || today;
  if (!isValidDate(from) || !isValidDate(to) || from > to) throw new Error('El rango de fechas no es válido.');
  const days = (Date.parse(to) - Date.parse(from)) / 86400000;
  if (days > 366) throw new Error('El rango máximo es de un año.');
  return { from, to };
}

function buildReport(from, to, includeInactive) {
  const now = new Date();
  const s = getSettings();
  const employees = db
    .prepare(`SELECT * FROM employees ${includeInactive ? '' : 'WHERE active = 1'} ORDER BY name COLLATE NOCASE`)
    .all();
  const exceptions = loadExceptions(from, to);
  return employees
    .filter((e) => e.start_date <= to)
    .map((e) => {
      const r = summarize({
        employee: e,
        punches: loadPunches(e.id, from, to),
        exceptions,
        from,
        to,
        now,
        settings: s,
      });
      return { employee: publicEmployee(e), totals: r.totals };
    });
}

app.get('/api/admin/report', requireAdmin, (req, res) => {
  try {
    const { from, to } = parseRange(req.query, new Date());
    res.json({ from, to, rows: buildReport(from, to, req.query.inactive === '1') });
  } catch (err) {
    fail(res, 400, err.message);
  }
});

function csvCell(v) {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

app.get('/api/admin/report.csv', requireAdmin, (req, res) => {
  try {
    const { from, to } = parseRange(req.query, new Date());
    const rows = buildReport(from, to, req.query.inactive === '1');
    const header = [
      'Empleado', 'Turno', 'Días trabajados', 'Retardos', 'Minutos de retardo',
      'Faltas', 'Justificadas', 'Sin salida', 'Horas trabajadas',
    ];
    const lines = [header.map(csvCell).join(',')];
    for (const r of rows) {
      const t = r.totals;
      lines.push(
        [
          r.employee.name, r.employee.shift_label, t.dias_trabajados, t.retardos, t.minutos_retardo,
          t.faltas, t.justificadas, t.sin_salida, calc.formatHours(t.minutos_trabajados),
        ].map(csvCell).join(',')
      );
    }
    res.set({
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="asistencia_${from}_${to}.csv"`,
    });
    res.send('﻿' + lines.join('\r\n'));
  } catch (err) {
    fail(res, 400, err.message);
  }
});

app.get('/api/admin/employees/:id/detail', requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const e = db.prepare('SELECT * FROM employees WHERE id = ?').get(id);
    if (!e) return fail(res, 404, 'Empleado no encontrado.');
    const { from, to } = parseRange(req.query, new Date());
    const r = summarize({
      employee: e,
      punches: loadPunches(id, from, to),
      exceptions: loadExceptions(from, to),
      from,
      to,
      now: new Date(),
      settings: getSettings(),
    });
    const punches = db
      .prepare(
        `SELECT id, type, ts, local_date, accuracy, distance_m, source, note
         FROM punches WHERE employee_id = ? AND local_date BETWEEN ? AND ? ORDER BY ts DESC`
      )
      .all(id, from, to)
      .map((p) => ({
        id: p.id,
        type: p.type,
        date: p.local_date,
        time: localParts(p.ts).time,
        accuracy_m: p.accuracy == null ? null : Math.round(p.accuracy),
        distance_m: p.distance_m == null ? null : Math.round(p.distance_m),
        source: p.source,
        note: p.note || '',
      }));
    res.json({ employee: publicEmployee(e), from, to, ...r, punches });
  } catch (err) {
    fail(res, 400, err.message);
  }
});

// Tablero del día: quién ya llegó, quién va tarde y quién falta.
app.get('/api/admin/today', requireAdmin, (req, res) => {
  const now = new Date();
  const date = isValidDate(req.query.date) ? req.query.date : localParts(now).date;
  const s = getSettings();
  const employees = db
    .prepare('SELECT * FROM employees WHERE active = 1 AND start_date <= ? ORDER BY name COLLATE NOCASE')
    .all(date);
  const exceptions = loadExceptions(date, date);
  const rows = employees.map((e) => {
    const r = summarize({
      employee: e,
      punches: loadPunches(e.id, date, date),
      exceptions,
      from: date,
      to: date,
      now,
      settings: s,
    });
    const day = r.days[0] || { status: isWorkday(date) ? 'pendiente' : 'descanso' };
    return { employee: publicEmployee(e), day };
  });
  res.json({ date, workday: isWorkday(date), rows });
});

app.post('/api/admin/punches', requireAdmin, (req, res) => {
  try {
    const b = req.body;
    const e = db.prepare('SELECT id FROM employees WHERE id = ?').get(Number(b.employee_id));
    if (!e) throw new Error('Empleado no encontrado.');
    if (!['in', 'out'].includes(b.type)) throw new Error('Tipo de checada inválido.');
    if (!isValidDate(b.date)) throw new Error('La fecha no es válida.');
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(String(b.time || ''))) throw new Error('La hora no es válida (HH:MM).');
    const note = String(b.note || '').trim();
    if (!note) throw new Error('Escribe el motivo de la corrección.');
    const ts = localToUtc(b.date, b.time);
    db.prepare(
      `INSERT INTO punches (employee_id, type, ts, local_date, source, note)
       VALUES (?, ?, ?, ?, 'manual', ?)`
    ).run(e.id, b.type, ts.toISOString(), b.date, note.slice(0, 200));
    res.status(201).json({ ok: true });
  } catch (err) {
    fail(res, 400, err.message);
  }
});

app.delete('/api/admin/punches/:id', requireAdmin, (req, res) => {
  const info = db.prepare('DELETE FROM punches WHERE id = ?').run(Number(req.params.id));
  if (!info.changes) return fail(res, 404, 'Checada no encontrada.');
  res.json({ ok: true });
});

app.get('/api/admin/exceptions', requireAdmin, (req, res) => {
  const rows = db
    .prepare(
      `SELECT x.*, e.name AS employee_name FROM exceptions x
       LEFT JOIN employees e ON e.id = x.employee_id
       ORDER BY x.date_from DESC, x.id DESC LIMIT 300`
    )
    .all();
  res.json(rows);
});

app.post('/api/admin/exceptions', requireAdmin, (req, res) => {
  try {
    const b = req.body;
    const kind = String(b.kind || '');
    if (!EXCEPTION_KINDS.includes(kind)) throw new Error('Tipo de incidencia inválido.');
    if (!isValidDate(b.date_from) || !isValidDate(b.date_to) || b.date_from > b.date_to) {
      throw new Error('El rango de fechas no es válido.');
    }
    let employeeId = null;
    if (b.employee_id !== null && b.employee_id !== '' && b.employee_id !== undefined) {
      employeeId = Number(b.employee_id);
      if (!db.prepare('SELECT 1 FROM employees WHERE id = ?').get(employeeId)) throw new Error('Empleado no encontrado.');
    }
    if (kind !== 'festivo' && employeeId == null) {
      throw new Error('Selecciona al empleado (solo los festivos aplican a todos).');
    }
    db.prepare('INSERT INTO exceptions (employee_id, date_from, date_to, kind, note) VALUES (?, ?, ?, ?, ?)').run(
      kind === 'festivo' ? null : employeeId,
      b.date_from,
      b.date_to,
      kind,
      String(b.note || '').trim().slice(0, 200)
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    fail(res, 400, err.message);
  }
});

app.delete('/api/admin/exceptions/:id', requireAdmin, (req, res) => {
  const info = db.prepare('DELETE FROM exceptions WHERE id = ?').run(Number(req.params.id));
  if (!info.changes) return fail(res, 404, 'Incidencia no encontrada.');
  res.json({ ok: true });
});

// 404 y errores
app.use('/api', (req, res) => fail(res, 404, 'No encontrado.'));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return fail(res, 413, 'El archivo es demasiado grande.');
  if (err instanceof SyntaxError) return fail(res, 400, 'JSON inválido.');
  console.error(err);
  fail(res, 500, 'Error interno del servidor.');
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Checador escuchando en http://localhost:${PORT}  (zona horaria: ${calc.TZ})`);
  });
}

module.exports = { app, db };

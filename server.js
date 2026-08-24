const express = require('express');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = './db.json';
const PHOTO_DIR = './photos';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

fs.ensureDirSync(PHOTO_DIR);

const readDB = () => {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeJsonSync(DB_PATH, { pin_hash: null, photos: [], deleted: [], albums: [], token: null });
  }
  return fs.readJsonSync(DB_PATH);
};
const writeDB = (data) => fs.writeJsonSync(DB_PATH, data);

const hashPin = (pin) => {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pin, salt, 64).toString('hex');
  return salt + ':' + hash;
};
const verifyPin = (pin, stored) => {
  const [salt, hash] = stored.split(':');
  const computed = crypto.scryptSync(pin, salt, 64).toString('hex');
  return computed === hash;
};

let db = readDB();
if (!db.pin_hash) {
  db.pin_hash = hashPin('1234');
  writeDB(db);
  console.log('🔑 Default PIN: 1234');
}

const requireAuth = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const db2 = readDB();
  if (token !== db2.token) return res.status(403).json({ error: 'Invalid session' });
  next();
};

app.use('/photos', express.static(PHOTO_DIR));

app.post('/api/login', (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'PIN required' });
  const db2 = readDB();
  if (!db2.pin_hash) return res.status(400).json({ error: 'No PIN set' });
  if (!verifyPin(pin, db2.pin_hash)) return res.status(401).json({ error: 'Wrong PIN' });
  const token = uuidv4();
  db2.token = token;
  writeDB(db2);
  res.json({ success: true, token });
});

app.get('/api/photos', requireAuth, (req, res) => {
  const db2 = readDB();
  res.json(db2.photos.sort((a, b) => b.created - a.created));
});

app.get('/api/deleted', requireAuth, (req, res) => {
  const db2 = readDB();
  res.json(db2.deleted.sort((a, b) => b.deleted_at - a.deleted_at));
});

app.get('/api/albums', requireAuth, (req, res) => {
  const db2 = readDB();
  res.json(db2.albums.sort((a, b) => b.created - a.created));
});

app.post('/api/albums', requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const db2 = readDB();
  const album = { id: uuidv4(), name, created: Date.now() };
  db2.albums.push(album);
  writeDB(db2);
  res.json(album);
});

app.delete('/api/albums/:id', requireAuth, (req, res) => {
  const db2 = readDB();
  db2.albums = db2.albums.filter(a => a.id !== req.params.id);
  writeDB(db2);
  res.json({ success: true });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, PHOTO_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype))
});

app.post('/api/upload', requireAuth, upload.array('photos'), (req, res) => {
  const files = req.files;
  if (!files || !files.length) return res.status(400).json({ error: 'No files' });
  const db2 = readDB();
  const newPhotos = files.map(f => ({
    id: uuidv4(),
    name: f.originalname,
    file: f.filename,
    created: Date.now(),
    album_id: null
  }));
  db2.photos.push(...newPhotos);
  writeDB(db2);
  res.json({ count: files.length });
});

app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const db2 = readDB();
  const idx = db2.photos.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const photo = db2.photos.splice(idx, 1)[0];
  db2.deleted.push({
    id: photo.id,
    name: photo.name,
    file: photo.file,
    deleted_at: Date.now(),
    expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000
  });
  writeDB(db2);
  res.json({ success: true });
});

app.post('/api/photos/:id/restore', requireAuth, (req, res) => {
  const db2 = readDB();
  const idx = db2.deleted.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const del = db2.deleted.splice(idx, 1)[0];
  db2.photos.push({ id: del.id, name: del.name, file: del.file, created: Date.now(), album_id: null });
  writeDB(db2);
  res.json({ success: true });
});

app.delete('/api/photos/:id/permanent', requireAuth, (req, res) => {
  const db2 = readDB();
  const idx = db2.deleted.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const del = db2.deleted.splice(idx, 1)[0];
  const filePath = path.join(PHOTO_DIR, del.file);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  writeDB(db2);
  res.json({ success: true });
});

app.post('/api/deleted/restore-all', requireAuth, (req, res) => {
  const db2 = readDB();
  const list = [...db2.deleted];
  list.forEach(d => {
    db2.photos.push({ id: d.id, name: d.name, file: d.file, created: Date.now(), album_id: null });
  });
  db2.deleted = [];
  writeDB(db2);
  res.json({ success: true });
});

app.delete('/api/deleted/delete-all', requireAuth, (req, res) => {
  const db2 = readDB();
  db2.deleted.forEach(d => {
    const filePath = path.join(PHOTO_DIR, d.file);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  });
  db2.deleted = [];
  writeDB(db2);
  res.json({ success: true });
});

app.post('/api/change-pin', requireAuth, (req, res) => {
  const { currentPin, newPin } = req.body;
  if (!currentPin || !newPin || newPin.length !== 4) return res.status(400).json({ error: 'Invalid' });
  const db2 = readDB();
  if (!db2.pin_hash) return res.status(400).json({ error: 'No PIN' });
  if (!verifyPin(currentPin, db2.pin_hash)) return res.status(401).json({ error: 'Wrong current PIN' });
  db2.pin_hash = hashPin(newPin);
  writeDB(db2);
  res.json({ success: true });
});

app.get('/api/settings/auto-lock', requireAuth, (req, res) => {
  const db2 = readDB();
  res.json({ minutes: db2.auto_lock || 5 });
});
app.post('/api/settings/auto-lock', requireAuth, (req, res) => {
  const db2 = readDB();
  db2.auto_lock = req.body.minutes;
  writeDB(db2);
  res.json({ success: true });
});

app.get('/api/storage', requireAuth, (req, res) => {
  const db2 = readDB();
  let photoSize = 0;
  try { fs.readdirSync(PHOTO_DIR).forEach(f => photoSize += fs.statSync(path.join(PHOTO_DIR, f)).size); } catch(e) {}
  res.json({ photos: db2.photos.length, albums: db2.albums.length, photoStorage: photoSize });
});

app.get('*', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <title>Private Photo Vault</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0a0a0f;color:#fff;font-family:sans-serif;display:flex;justify-content:center;min-height:100vh}
    #app{width:100%;max-width:600px;background:#12121a;padding:20px 16px 80px;min-height:100vh}
    .screen{display:none}.screen.active{display:block}
    .glass{background:rgba(255,255,255,0.05);border-radius:24px;padding:20px;backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,0.08)}
    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:4px}
    .grid img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:8px;cursor:pointer}
    .btn{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.1);color:#fff;padding:12px 20px;border-radius:16px;cursor:pointer;font-size:16px;margin:8px 0;display:inline-block;text-align:center}
    .btn.primary{background:rgba(120,80,255,0.3);border-color:rgba(120,80,255,0.4)}
    .btn.danger{background:rgba(255,60,60,0.2);border-color:rgba(255,60,60,0.3)}
    .pin-dots{font-size:32px;letter-spacing:12px;text-align:center;margin:20px 0}
    .pin-keypad{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;max-width:300px;margin:20px auto}
    .pin-key{background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.1);border-radius:50%;aspect-ratio:1;font-size:24px;color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:0.1s}
    .pin-key:active{transform:scale(0.9)}
    .pin-key.empty{background:transparent;border:none;pointer-events:none}
    .topbar{display:flex;justify-content:space-between;align-items:center;padding:12px 0;font-size:18px;font-weight:600}
    .topbar .back{cursor:pointer;font-size:24px}
    .feature-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}
    .feature-card{background:rgba(255,255,255,0.04);border-radius:16px;padding:20px;text-align:center;cursor:pointer;transition:0.1s}
    .feature-card:active{transform:scale(0.95)}
    .feature-card .icon{font-size:32px;margin-bottom:8px}
    .feature-card .label{font-size:14px}
    .bottom-nav{position:fixed;bottom:0;left:0;right:0;max-width:600px;margin:auto;background:rgba(18,18,26,0.95);backdrop-filter:blur(16px);display:flex;justify-content:space-around;padding:8px 0 12px;border-top:1px solid rgba(255,255,255,0.06);z-index:100}
    .bottom-nav button{background:none;border:none;color:#777;font-size:11px;display:flex;flex-direction:column;align-items:center;cursor:pointer;padding:4px 8px}
    .bottom-nav button.active{color:#a88bff}
    .bottom-nav button .icon{font-size:24px;margin-bottom:2px}
    .bottom-nav button.import-btn{background:rgba(120,80,255,0.2);border-radius:50%;padding:4px 14px;margin-top:-12px;color:#c8b8ff}
    .import-zone{border:2px dashed rgba(255,255,255,0.15);padding:40px 20px;text-align:center;border-radius:24px;margin-top:16px}
    .import-zone .icon{font-size:48px;margin-bottom:12px}
    .import-zone .hint{color:#aaa;font-size:14px}
    .deleted-item{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.05);align-items:center}
    .deleted-item .thumb{width:48px;height:48px;border-radius:8px;object-fit:cover}
    .deleted-item .info{flex:1}
    .deleted-item .info .name{font-size:14px}
    .deleted-item .info .days{font-size:12px;color:#888}
    .deleted-item .actions button{background:none;border:none;color:#aaa;font-size:20px;cursor:pointer;padding:4px}
    .settings-item{display:flex;align-items:center;padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.05);cursor:pointer}
    .settings-item .icon{font-size:20px;width:32px}
    .settings-item .label{flex:1;font-size:16px}
    .settings-item .arrow{color:#555;font-size:18px}
    .viewer-container{position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:150;display:flex;flex-direction:column;align-items:center;justify-content:center}
    .viewer-container .viewer-top{position:absolute;top:20px;left:16px;right:16px;display:flex;justify-content:space-between;z-index:10}
    .viewer-container .viewer-top button{background:rgba(0,0,0,0.5);border:none;color:#fff;font-size:24px;padding:8px 16px;border-radius:30px;cursor:pointer}
    .viewer-container .viewer-image{max-width:100%;max-height:80%;object-fit:contain}
    .empty-state{text-align:center;padding:60px 20px;color:#888}
    .empty-state .icon{font-size:64px;margin-bottom:16px}
    .empty-state .title{font-size:18px;color:#ccc}
    .album-item{display:flex;padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.05);align-items:center;gap:12px;cursor:pointer}
    .album-item .thumb{font-size:24px}
    .album-item .info{flex:1}
    .album-item .info .name{font-weight:500}
    .album-item .info .count{font-size:13px;color:#888}
  </style>
</head>
<body>
<div id="app"></div>
<div id="bottomNav" class="bottom-nav" style="display:none">
  <button onclick="navigate('photos')"><span class="icon">🖼</span>Photos</button>
  <button onclick="navigate('albums')"><span class="icon">📁</span>Albums</button>
  <button onclick="navigate('import')" class="import-btn"><span class="icon" style="font-size:28px">＋</span></button>
  <button onclick="navigate('deleted')"><span class="icon">🗑</span>Deleted</button>
  <button onclick="navigate('settings')"><span class="icon">⚙</span>Settings</button>
</div>
<script>
const api = {
  get: async (url, token) => {
    const r = await fetch(url, { headers: token ? { Authorization: token } : {} });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
  post: async (url, body, token) => {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: token } : {}) },
      body: JSON.stringify(body)
    });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
  del: async (url, token) => {
    const r = await fetch(url, { method: 'DELETE', headers: token ? { Authorization: token } : {} });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
  upload: async (url, formData, token) => {
    const r = await fetch(url, { method: 'POST', body: formData, headers: token ? { Authorization: token } : {} });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  }
};

let state = {
  screen: 'pin',
  token: localStorage.getItem('token') || null,
  photos: [],
  deleted: [],
  albums: [],
  stack: [],
  viewerId: null
};

function render() {
  const app = document.getElementById('app');
  let html = '';
  const s = state.screen;

  if (s === 'pin') {
    html = \`
      <div class="screen active">
        <div class="glass" style="max-width:320px;margin:40px auto;text-align:center">
          <h2>🔒 Private Vault</h2>
          <p style="color:#aaa;margin:8px 0">Enter PIN</p>
          <div class="pin-dots" id="pinDots">●●●●</div>
          <div id="pinError" style="color:red;min-height:24px"></div>
          <div class="pin-keypad" id="keypad">
            <button class="pin-key" data-v="1">1</button>
            <button class="pin-key" data-v="2">2</button>
            <button class="pin-key" data-v="3">3</button>
            <button class="pin-key" data-v="4">4</button>
            <button class="pin-key" data-v="5">5</button>
            <button class="pin-key" data-v="6">6</button>
            <button class="pin-key" data-v="7">7</button>
            <button class="pin-key" data-v="8">8</button>
            <button class="pin-key" data-v="9">9</button>
            <button class="pin-key empty"></button>
            <button class="pin-key" data-v="0">0</button>
            <button class="pin-key" data-v="del">⌫</button>
          </div>
        </div>
      </div>
    \`;
  } else if (s === 'home') {
    const count = state.photos.length;
    const mb = (count * 0.1).toFixed(1);
    html = \`
      <div class="screen active">
        <div class="topbar"><span style="font-weight:600">☰ Private Vault</span><span>🔒</span></div>
        <div class="glass">
          <div style="color:#aaa;font-size:13px">Storage Used</div>
          <div><span>\${count} photos</span> <span style="float:right">\${mb} MB</span></div>
        </div>
        <div class="feature-grid">
          <div class="feature-card" onclick="navigate('photos')"><div class="icon">🖼</div><div class="label">Photos</div></div>
          <div class="feature-card" onclick="navigate('albums')"><div class="icon">📁</div><div class="label">Albums</div></div>
          <div class="feature-card" onclick="navigate('import')"><div class="icon">⬆</div><div class="label">Import</div></div>
          <div class="feature-card" onclick="navigate('deleted')"><div class="icon">🗑</div><div class="label">Deleted</div></div>
          <div class="feature-card" onclick="navigate('settings')"><div class="icon">⚙</div><div class="label">Settings</div></div>
        </div>
      </div>
    \`;
  } else if (s === 'photos') {
    const photos = state.photos;
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Photos</span><span>\${photos.length}</span></div>
    \`;
    if (!photos.length) {
      html += \`<div class="empty-state"><div class="icon">🖼️</div><div class="title">No Photos</div><button class="btn primary" onclick="navigate('import')">Import</button></div>\`;
    } else {
      html += \`<div class="grid">\`;
      photos.forEach(p => {
        html += \`<img src="/photos/\${p.file}" onclick="viewPhoto('\${p.id}')" loading="lazy">\`;
      });
      html += \`</div>\`;
    }
    html += \`</div>\`;
  } else if (s === 'viewer') {
    const p = state.photos.find(x => x.id === state.viewerId);
    if (p) {
      html = \`
        <div class="viewer-container">
          <div class="viewer-top">
            <button onclick="goBack()">✕</button>
            <div>
              <button onclick="deletePhoto('\${p.id}')" style="margin-right:8px">🗑</button>
            </div>
          </div>
          <img class="viewer-image" src="/photos/\${p.file}" alt="">
        </div>
      \`;
    } else { html = '<div>Not found</div>'; goBack(); }
  } else if (s === 'import') {
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Import</span></div>
        <div class="import-zone">
          <div class="icon">⬆</div>
          <div class="hint">Tap to Select Photos</div>
          <input type="file" id="fileInput" accept="image/*" multiple style="display:none">
          <button class="btn primary" onclick="document.getElementById('fileInput').click()">Select Photos</button>
          <div id="preview" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px"></div>
          <div id="status" style="margin-top:8px"></div>
        </div>
      </div>
    \`;
  } else if (s === 'deleted') {
    const del = state.deleted;
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Recently Deleted</span></div>
        <div style="color:#888;font-size:13px;margin:8px 0">Photos deleted permanently after 30 days.</div>
        <div style="display:flex;gap:12px;margin-bottom:12px">
          <button class="btn" onclick="restoreAll()">Restore All</button>
          <button class="btn danger" onclick="deleteAllPermanent()">Delete All</button>
        </div>
        <div id="deletedList">
    \`;
    if (!del.length) {
      html += \`<div class="empty-state"><div class="icon">🗑️</div><div class="title">Empty</div></div>\`;
    } else {
      del.forEach(d => {
        const days = Math.max(0, Math.ceil((d.expires_at - Date.now()) / 86400000));
        html += \`
          <div class="deleted-item">
            <img class="thumb" src="/photos/\${d.file}">
            <div class="info"><div class="name">\${d.name}</div><div class="days">\${days} days left</div></div>
            <div class="actions">
              <button onclick="restorePhoto('\${d.id}')">↩️</button>
              <button onclick="deletePermanent('\${d.id}')">✖</button>
            </div>
          </div>
        \`;
      });
    }
    html += \`</div></div>\`;
  } else if (s === 'albums') {
    const albums = state.albums;
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Albums</span><span onclick="showCreateAlbum()" style="cursor:pointer">+</span></div>
        <div id="albumList">
    \`;
    if (!albums.length) {
      html += \`<div class="empty-state"><div class="icon">📁</div><div class="title">No Albums</div></div>\`;
    } else {
      albums.forEach(a => {
        html += \`
          <div class="album-item">
            <div class="thumb">📁</div>
            <div class="info"><div class="name">\${a.name}</div><div class="count">0 photos</div></div>
          </div>
        \`;
      });
    }
    html += \`</div></div>\`;
  } else if (s === 'settings') {
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Settings</span></div>
        <div class="settings-list">
          <div class="settings-item" onclick="navigate('change-pin')"><span class="icon">🔑</span><span class="label">Change PIN</span><span class="arrow">›</span></div>
          <div class="settings-item" onclick="navigate('auto-lock')"><span class="icon">⏱</span><span class="label">Auto Lock</span><span class="arrow">›</span></div>
          <div class="settings-item" onclick="navigate('storage')"><span class="icon">💾</span><span class="label">Storage Usage</span><span class="arrow">›</span></div>
          <div class="settings-item" onclick="navigate('about')"><span class="icon">ℹ</span><span class="label">About</span><span class="arrow">›</span></div>
        </div>
      </div>
    \`;
  } else if (s === 'change-pin') {
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Change PIN</span></div>
        <div class="glass" style="margin-top:16px">
          <form id="changePinForm">
            <div style="margin-bottom:12px"><label>Current PIN</label><input type="password" id="curPin" maxlength="4" pattern="[0-9]*" inputmode="numeric"></div>
            <div style="margin-bottom:12px"><label>New PIN</label><input type="password" id="newPin" maxlength="4" pattern="[0-9]*" inputmode="numeric"></div>
            <div style="margin-bottom:12px"><label>Confirm PIN</label><input type="password" id="confPin" maxlength="4" pattern="[0-9]*" inputmode="numeric"></div>
            <button type="submit" class="btn primary" style="width:100%">Update PIN</button>
          </form>
        </div>
      </div>
    \`;
  } else if (s === 'auto-lock') {
    const minutes = state.autoLockMinutes || 5;
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Auto Lock</span></div>
        <div class="glass" style="margin-top:16px">
          <div><label><input type="radio" name="autoLock" value="0" \${minutes===0?'checked':''}> Off</label></div>
          <div><label><input type="radio" name="autoLock" value="1" \${minutes===1?'checked':''}> 1 Minute</label></div>
          <div><label><input type="radio" name="autoLock" value="5" \${minutes===5?'checked':''}> 5 Minutes</label></div>
          <div><label><input type="radio" name="autoLock" value="15" \${minutes===15?'checked':''}> 15 Minutes</label></div>
          <div><label><input type="radio" name="autoLock" value="30" \${minutes===30?'checked':''}> 30 Minutes</label></div>
          <button class="btn primary" style="width:100%;margin-top:12px" onclick="saveAutoLock()">Save</button>
        </div>
      </div>
    \`;
  } else if (s === 'storage') {
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>Storage Usage</span></div>
        <div class="glass" style="margin-top:16px" id="storageInfo">Loading...</div>
      </div>
    \`;
  } else if (s === 'about') {
    html = \`
      <div class="screen active">
        <div class="topbar"><span class="back" onclick="goBack()">←</span><span>About</span></div>
        <div class="glass" style="text-align:center;margin-top:16px">
          <div style="font-size:48px">🔒</div>
          <h2>Private Photo Vault</h2>
          <p>Version 2.0</p>
          <p style="margin-top:16px;color:#aaa">Secure local photo storage with PIN protection.<br>All data stored locally.<br>No cloud upload.</p>
        </div>
      </div>
    \`;
  }

  app.innerHTML = html;
  document.getElementById('bottomNav').style.display = (s === 'pin' || s === 'viewer') ? 'none' : 'flex';

  if (s === 'pin') attachPinEvents();
  if (s === 'import') attachImportEvents();
  if (s === 'change-pin') attachChangePinEvents();
  if (s === 'auto-lock') loadAutoLock();
  if (s === 'storage') loadStorage();
}

function attachPinEvents() {
  let pin = '';
  const dots = document.getElementById('pinDots');
  const err = document.getElementById('pinError');
  document.querySelectorAll('.pin-key:not(.empty)').forEach(k => {
    k.onclick = () => {
      const v = k.dataset.v;
      if (v === 'del') { pin = pin.slice(0, -1); }
      else if (pin.length < 4) { pin += v; }
      let d = ''; for (let i = 0; i < 4; i++) d += (i < pin.length) ? '●' : '○';
      dots.textContent = d;
      if (pin.length === 4) {
        api.post('/api/login', { pin }).then(r => {
          if (r.success) {
            state.token = r.token;
            localStorage.setItem('token', r.token);
            state.screen = 'home';
            loadAllData();
            render();
          } else {
            err.textContent = 'Wrong PIN';
            pin = '';
            dots.textContent = '●●●●';
          }
        }).catch(() => {
          err.textContent = 'Error';
          pin = '';
          dots.textContent = '●●●●';
        });
      }
    };
  });
}

function attachImportEvents() {
  const inp = document.getElementById('fileInput');
  if (inp) {
    inp.onchange = async function() {
      const files = this.files;
      if (!files.length) return;
      const fd = new FormData();
      for (let f of files) fd.append('photos', f);
      document.getElementById('status').textContent = 'Uploading...';
      try {
        const r = await api.upload('/api/upload', fd, state.token);
        document.getElementById('status').textContent = '✓ ' + r.count + ' imported';
        loadAllData();
      } catch (e) {
        document.getElementById('status').textContent = '✗ Failed';
      }
      this.value = '';
    };
  }
}

function attachChangePinEvents() {
  document.getElementById('changePinForm').onsubmit = async (e) => {
    e.preventDefault();
    const cur = document.getElementById('curPin').value;
    const np = document.getElementById('newPin').value;
    const cf = document.getElementById('confPin').value;
    if (np !== cf) { alert('PINs do not match'); return; }
    if (np.length !== 4) { alert('PIN must be 4 digits'); return; }
    try {
      await api.post('/api/change-pin', { currentPin: cur, newPin: np }, state.token);
      alert('PIN changed successfully');
      goBack();
    } catch (e) {
      alert('Error: ' + (e.message || 'Wrong current PIN'));
    }
  };
}

function loadAutoLock() {
  api.get('/api/settings/auto-lock', state.token).then(r => {
    const m = r.minutes || 5;
    document.querySelectorAll('input[name="autoLock"]').forEach(el => {
      el.checked = (parseInt(el.value) === m);
    });
  });
}
window.saveAutoLock = function() {
  const sel = document.querySelector('input[name="autoLock"]:checked');
  if (!sel) return;
  const val = parseInt(sel.value);
  api.post('/api/settings/auto-lock', { minutes: val }, state.token).then(() => {
    alert('Saved');
    goBack();
  });
};

function loadStorage() {
  api.get('/api/storage', state.token).then(r => {
    const mb = (r.photoStorage / (1024 * 1024)).toFixed(1);
    document.getElementById('storageInfo').innerHTML = \`
      <div><strong>Photos:</strong> \${r.photos}</div>
      <div><strong>Albums:</strong> \${r.albums}</div>
      <div><strong>Storage Used:</strong> \${mb} MB</div>
    \`;
  });
}

window.navigate = function(screen) {
  if (state.screen !== screen) {
    state.stack.push(state.screen);
    state.screen = screen;
    render();
    if (screen === 'home' || screen === 'photos' || screen === 'deleted' || screen === 'albums' || screen === 'storage') {
      loadAllData();
    }
  }
};
window.goBack = function() {
  if (state.stack.length) {
    state.screen = state.stack.pop();
    render();
    loadAllData();
  }
};
window.viewPhoto = function(id) {
  state.viewerId = id;
  state.screen = 'viewer';
  render();
};
window.deletePhoto = function(id) {
  if (confirm('Move to deleted?')) {
    api.del('/api/photos/' + id, state.token).then(() => {
      loadAllData();
      goBack();
    });
  }
};
window.restorePhoto = function(id) {
  api.post('/api/photos/' + id + '/restore', {}, state.token).then(() => loadAllData());
};
window.deletePermanent = function(id) {
  if (confirm('Permanently delete?')) {
    api.del('/api/photos/' + id + '/permanent', state.token).then(() => loadAllData());
  }
};
window.restoreAll = function() {
  if (confirm('Restore all?')) {
    api.post('/api/deleted/restore-all', {}, state.token).then(() => loadAllData());
  }
};
window.deleteAllPermanent = function() {
  if (confirm('Delete all permanently?')) {
    api.del('/api/deleted/delete-all', state.token).then(() => loadAllData());
  }
};
window.showCreateAlbum = function() {
  const name = prompt('Album name:');
  if (name) {
    api.post('/api/albums', { name }, state.token).then(() => loadAllData());
  }
};

function loadAllData() {
  if (!state.token) return;
  Promise.all([
    api.get('/api/photos', state.token),
    api.get('/api/deleted', state.token),
    api.get('/api/albums', state.token)
  ]).then(([photos, deleted, albums]) => {
    state.photos = photos;
    state.deleted = deleted;
    state.albums = albums;
    render();
  }).catch(() => {});
}

if (state.token) {
  state.screen = 'home';
  loadAllData();
} else {
  state.screen = 'pin';
  render();
}

// Auto-lock timer
let lockTimer;
function resetLockTimer() {
  clearTimeout(lockTimer);
  if (!state.token) return;
  api.get('/api/settings/auto-lock', state.token).then(r => {
    const min = r.minutes || 5;
    if (min > 0) {
      lockTimer = setTimeout(() => {
        state.token = null;
        localStorage.removeItem('token');
        state.screen = 'pin';
        render();
      }, min * 60 * 1000);
    }
  }).catch(() => {});
}
document.addEventListener('click', resetLockTimer);
document.addEventListener('touchstart', resetLockTimer);
resetLockTimer();

console.log('🔐 Private Vault loaded. Default PIN: 1234');
</script>
</body>
</html>
  `);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('================================');
  console.log('PRIVATE PHOTO VAULT');
  console.log('================================');
  console.log('Server: http://127.0.0.1:' + PORT);
  console.log('Default PIN: 1234');
  console.log('================================');
});

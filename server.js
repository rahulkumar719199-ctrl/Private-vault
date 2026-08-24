const express = require('express');
const path = require('path');
const fs = require('fs-extra');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = './db.json';
const PHOTO_DIR = './photos';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

fs.ensureDirSync(PHOTO_DIR);

// Simple database
const readDB = () => {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeJsonSync(DB_PATH, { pin: '1234', photos: [], deleted: [], albums: [], token: null });
  }
  return fs.readJsonSync(DB_PATH);
};
const writeDB = (data) => fs.writeJsonSync(DB_PATH, data);

app.use('/photos', express.static(PHOTO_DIR));

// Login - simple PIN check
app.post('/api/login', (req, res) => {
  const { pin } = req.body;
  const db = readDB();
  if (pin === db.pin) {
    const token = uuidv4();
    db.token = token;
    writeDB(db);
    res.json({ success: true, token });
  } else {
    res.status(401).json({ error: 'Wrong PIN' });
  }
});

app.get('/api/photos', (req, res) => {
  const db = readDB();
  res.json(db.photos);
});

app.get('/api/deleted', (req, res) => {
  const db = readDB();
  res.json(db.deleted);
});

app.get('/api/albums', (req, res) => {
  const db = readDB();
  res.json(db.albums);
});

app.post('/api/albums', (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const db = readDB();
  const album = { id: uuidv4(), name, created: Date.now() };
  db.albums.push(album);
  writeDB(db);
  res.json(album);
});

// Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, PHOTO_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype))
});

app.post('/api/upload', upload.array('photos'), (req, res) => {
  const files = req.files;
  if (!files || !files.length) return res.status(400).json({ error: 'No files' });
  const db = readDB();
  const newPhotos = files.map(f => ({
    id: uuidv4(),
    name: f.originalname,
    file: f.filename,
    created: Date.now()
  }));
  db.photos.push(...newPhotos);
  writeDB(db);
  res.json({ count: files.length });
});

app.delete('/api/photos/:id', (req, res) => {
  const db = readDB();
  const idx = db.photos.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const photo = db.photos.splice(idx, 1)[0];
  db.deleted.push({
    id: photo.id,
    name: photo.name,
    file: photo.file,
    deleted_at: Date.now(),
    expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000
  });
  writeDB(db);
  res.json({ success: true });
});

app.post('/api/photos/:id/restore', (req, res) => {
  const db = readDB();
  const idx = db.deleted.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const del = db.deleted.splice(idx, 1)[0];
  db.photos.push({ id: del.id, name: del.name, file: del.file, created: Date.now() });
  writeDB(db);
  res.json({ success: true });
});

app.delete('/api/photos/:id/permanent', (req, res) => {
  const db = readDB();
  const idx = db.deleted.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const del = db.deleted.splice(idx, 1)[0];
  const filePath = path.join(PHOTO_DIR, del.file);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  writeDB(db);
  res.json({ success: true });
});

app.post('/api/deleted/restore-all', (req, res) => {
  const db = readDB();
  const list = [...db.deleted];
  list.forEach(d => {
    db.photos.push({ id: d.id, name: d.name, file: d.file, created: Date.now() });
  });
  db.deleted = [];
  writeDB(db);
  res.json({ success: true });
});

app.delete('/api/deleted/delete-all', (req, res) => {
  const db = readDB();
  db.deleted.forEach(d => {
    const filePath = path.join(PHOTO_DIR, d.file);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  });
  db.deleted = [];
  writeDB(db);
  res.json({ success: true });
});

app.get('/api/storage', (req, res) => {
  const db = readDB();
  let photoSize = 0;
  try { fs.readdirSync(PHOTO_DIR).forEach(f => photoSize += fs.statSync(path.join(PHOTO_DIR, f)).size); } catch(e) {}
  res.json({ photos: db.photos.length, albums: db.albums.length, photoStorage: photoSize });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('================================');
  console.log('PRIVATE PHOTO VAULT');
  console.log('================================');
  console.log('Server running on port:', PORT);
  console.log('Default PIN: 1234');
  console.log('================================');
});

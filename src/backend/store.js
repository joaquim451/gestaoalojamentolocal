const fs = require('fs');
const path = require('path');

const DEFAULT_DB_PATH = path.join(__dirname, '..', '..', 'data', 'db.json');

function getDbPath() {
  return process.env.DB_PATH || DEFAULT_DB_PATH;
}

function ensureDb() {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    const initial = { users: [], accommodations: [], reservations: [] };
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    fs.writeFileSync(dbPath, JSON.stringify(initial, null, 2), 'utf8');
  }
}

function parseJsonFile(content) {
  // Remove BOM when files are created by tools that prepend UTF-8 signature.
  const normalized = String(content).replace(/^\uFEFF/, '');
  return JSON.parse(normalized);
}

function readDb() {
  const dbPath = getDbPath();
  ensureDb();
  return parseJsonFile(fs.readFileSync(dbPath, 'utf8'));
}

function writeDb(data) {
  const dbPath = getDbPath();
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2), 'utf8');
}

function nextId(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

module.exports = {
  readDb,
  writeDb,
  nextId
};

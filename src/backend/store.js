const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', '..', 'data', 'db.json');

function ensureDb() {
  if (!fs.existsSync(DB_PATH)) {
    const initial = { accommodations: [], reservations: [] };
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), 'utf8');
  }
}

function parseJsonFile(content) {
  // Remove BOM when files are created by tools that prepend UTF-8 signature.
  const normalized = String(content).replace(/^\uFEFF/, '');
  return JSON.parse(normalized);
}

function readDb() {
  ensureDb();
  return parseJsonFile(fs.readFileSync(DB_PATH, 'utf8'));
}

function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function nextId(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

module.exports = {
  readDb,
  writeDb,
  nextId
};

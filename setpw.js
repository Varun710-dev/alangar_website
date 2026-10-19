// Run with the server STOPPED:  node setpw.js
// Sets the admin ID and password directly (bypasses .env parsing). Typing is visible on purpose.
const readline = require('readline'), fs = require('fs'), path = require('path'), bcrypt = require('bcryptjs');
const dir = path.join(__dirname, 'data'), file = path.join(dir, 'admin.json');
fs.mkdirSync(dir, { recursive: true });
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(r => rl.question(q, r));
(async () => {
  const id = (await ask('Admin ID: ')).trim();
  const pw = (await ask('New admin password (visible): ')).trim();
  rl.close();
  const ok = id && pw.length >= 12 && /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /\d/.test(pw) && /[^A-Za-z0-9]/.test(pw);
  if (!ok) { console.log('Rejected: need an ID, and a password of 12+ characters with uppercase, lowercase, number and special character.'); process.exit(1); }
  let old = {}; try { old = JSON.parse(fs.readFileSync(file)); } catch {}
  fs.writeFileSync(file, JSON.stringify({ id, hash: bcrypt.hashSync(pw, 12), ver: (old.ver || 0) + 1, created: old.created || new Date().toISOString(), last: null }, null, 1));
  console.log('Saved. Start the server with npm start and log in as "' + id + '" with that password.');
})();

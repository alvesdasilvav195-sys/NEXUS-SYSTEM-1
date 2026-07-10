/* =====================================================================
   Servidor do ERP "Livro"
   - Express serve a interface (pasta /public) e a API (/api/...)
   - Os dados ficam guardados em um banco Postgres (ex: Neon), definido
     pela variável de ambiente DATABASE_URL
   - O login usa JWT guardado em um cookie httpOnly (mais seguro do que
     guardar a senha no navegador)
   ===================================================================== */

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
// Se você não configurar JWT_SECRET no servidor de hospedagem, o sistema
// gera um segredo temporário ao iniciar (funciona, mas todo mundo precisa
// logar de novo sempre que o servidor reiniciar). O ideal é configurar
// a variável JWT_SECRET com um valor fixo — veja o guia de configuração.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const isProd = process.env.NODE_ENV === 'production';

if (!DATABASE_URL) {
  console.error('ERRO: a variável de ambiente DATABASE_URL não foi configurada. Configure-a com a string de conexão do seu banco Postgres (Neon).');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
});

async function iniciarBanco() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      usuario TEXT UNIQUE NOT NULL,
      senha_hash TEXT NOT NULL,
      criado_em TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_data (
      id INTEGER PRIMARY KEY DEFAULT 1,
      dados JSONB NOT NULL DEFAULT '{}'::jsonb,
      atualizado_em TIMESTAMP DEFAULT NOW()
    );
  `);
  const existe = await pool.query('SELECT 1 FROM app_data WHERE id = 1');
  if (existe.rowCount === 0) {
    await pool.query("INSERT INTO app_data (id, dados) VALUES (1, '{}'::jsonb)");
  }
}

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------------- Autenticação ---------------- */
const COOKIE_NAME = 'livro_sessao';
function assinarToken(usuario) {
  return jwt.sign({ id: usuario.id, usuario: usuario.usuario }, JWT_SECRET, { expiresIn: '30d' });
}
function setCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}
function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ erro: 'Não autenticado.' });
  try {
    req.usuario = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ erro: 'Sessão expirada, faça login novamente.' });
  }
}

app.get('/api/auth/status', async (req, res) => {
  try {
    const r = await pool.query('SELECT COUNT(*)::int AS total FROM usuarios');
    const existeUsuario = r.rows[0].total > 0;
    let logado = false;
    const token = req.cookies[COOKIE_NAME];
    if (token) {
      try { jwt.verify(token, JWT_SECRET); logado = true; } catch (e) { logado = false; }
    }
    res.json({ existeUsuario, logado });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao consultar o banco de dados.' });
  }
});

// Só funciona enquanto não existir nenhum usuário cadastrado (primeiro acesso)
app.post('/api/auth/setup', async (req, res) => {
  try {
    const { usuario, senha } = req.body || {};
    if (!usuario || !senha || senha.length < 4) {
      return res.status(400).json({ erro: 'Usuário e senha (mínimo 4 caracteres) são obrigatórios.' });
    }
    const existe = await pool.query('SELECT COUNT(*)::int AS total FROM usuarios');
    if (existe.rows[0].total > 0) {
      return res.status(403).json({ erro: 'Já existe um usuário cadastrado. Use a tela de login.' });
    }
    const hash = await bcrypt.hash(senha, 10);
    const r = await pool.query(
      'INSERT INTO usuarios (usuario, senha_hash) VALUES ($1, $2) RETURNING id, usuario',
      [usuario, hash]
    );
    const token = assinarToken(r.rows[0]);
    setCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao criar usuário.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { usuario, senha } = req.body || {};
    if (!usuario || !senha) return res.status(400).json({ erro: 'Informe usuário e senha.' });
    const r = await pool.query('SELECT id, usuario, senha_hash FROM usuarios WHERE usuario = $1', [usuario]);
    if (r.rowCount === 0) return res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
    const ok = await bcrypt.compare(senha, r.rows[0].senha_hash);
    if (!ok) return res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
    const token = assinarToken(r.rows[0]);
    setCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao entrar.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { usuarioAtual, novaSenha } = req.body || {};
    if (!usuarioAtual || !novaSenha || novaSenha.length < 4) {
      return res.status(400).json({ erro: 'Usuário e nova senha (mínimo 4 caracteres) são obrigatórios.' });
    }
    const hash = await bcrypt.hash(novaSenha, 10);
    await pool.query('UPDATE usuarios SET usuario = $1, senha_hash = $2 WHERE id = $3', [usuarioAtual, hash, req.usuario.id]);
    const token = assinarToken({ id: req.usuario.id, usuario: usuarioAtual });
    setCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    if (e.code === '23505') return res.status(409).json({ erro: 'Esse nome de usuário já está em uso.' });
    res.status(500).json({ erro: 'Erro ao atualizar usuário/senha.' });
  }
});

/* ---------------- Dados do ERP ---------------- */
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT dados FROM app_data WHERE id = 1');
    res.json(r.rows[0] ? r.rows[0].dados : {});
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao carregar dados.' });
  }
});

app.put('/api/data', requireAuth, async (req, res) => {
  try {
    const dados = req.body || {};
    await pool.query(
      'UPDATE app_data SET dados = $1, atualizado_em = NOW() WHERE id = 1',
      [JSON.stringify(dados)]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao salvar dados.' });
  }
});

app.get('/healthz', (req, res) => res.send('ok'));

// Qualquer outra rota (que não seja /api/...) devolve a interface do ERP
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

iniciarBanco()
  .then(() => {
    app.listen(PORT, () => console.log(`Servidor do Livro ERP rodando na porta ${PORT}`));
  })
  .catch((e) => {
    console.error('Não foi possível preparar o banco de dados:', e);
    process.exit(1);
  });

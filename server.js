// API DE LOGIN - SERVIDOR COM DOF2 (hospedagem TCAdmin / HeavyHost)
//
// A cada login, ela busca SÓ o arquivo daquele jogador por SFTP na hospedagem.
// Não guarda cópia das contas e os dados estão sempre atualizados.
//
// Instalar:   npm install
// Rodar:      node server.js
//
// SEGREDOS (usuário e senha do SFTP) NÃO ficam neste arquivo:
//   - No seu PC: crie o arquivo segredos.json (copie o segredos.exemplo.json e preencha)
//   - No Render/outro serviço: use as "Environment Variables" com os mesmos nomes
// NUNCA envie o segredos.json para o GitHub.
//
// A API precisa estar em HTTPS (o site do GitHub é HTTPS e o navegador bloqueia o resto).

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

/* ===================== CONFIGURAÇÃO ===================== */

// Endereço do seu site no GitHub Pages: SÓ o domínio, sem /nome-do-repositório e sem barra no final
const SITE_URL = "https://SEUUSUARIO.github.io";

// "sftp" = busca na hospedagem (seu caso)  |  "local" = lê de uma pasta neste computador
const MODO = "sftp";

// Pasta das contas dentro do servidor. Veja no Gerenciador de Arquivos do TCAdmin.
// Exemplo: "scriptfiles/Contas"  (sem barra no começo)
const PASTA_CONTAS = "scriptfiles/Contas";

// Só usado se MODO = "local"
const PASTA_LOCAL = "C:/servidor/scriptfiles/Contas";

// Extensão dos arquivos de conta
const EXTENSAO = ".ini";

// Nomes dos campos no arquivo de conta
const CAMPO_SENHA = "Senha";
const CAMPO_SKIN = "Skin";
const CAMPO_NOME = "Nome";

// Como a senha é calculada (SHA256 de senha + salt)
const SHA256_MODO = "senha+salt";
const SALT_FIXO = "78sdjs86d2h";

// O que aparece no perfil do site.
//   chave: nome do campo no arquivo  |  moeda: mostra como R$ 1.000
//   ocultarSeZero: não mostra se o valor for 0 ou vazio
// NUNCA coloque aqui: Senha, CheckSenha, CheckIP, CheckSerial.
const CAMPOS = [
  { rotulo: "Nível",    chave: "Level" },
  { rotulo: "Dinheiro", chave: "Dinheiro", moeda: true },
  { rotulo: "Banco",    chave: "SaldoBancario", moeda: true },
  { rotulo: "Coins",    chave: "Coins" },
  { rotulo: "Tempo de jogo", tipo: "tempo" },
  { rotulo: "VIP",      chave: "Vip", ocultarSeZero: true },
  { rotulo: "Admin",    chave: "Admin", ocultarSeZero: true }
];

/* ======================================================== */

// Lê usuário/senha do SFTP: primeiro das variáveis de ambiente, depois do segredos.json
function carregarSegredos() {
  let arq = {};
  try { arq = JSON.parse(fs.readFileSync(path.join(__dirname, "segredos.json"), "utf8")); } catch (e) {}
  const v = (k) => process.env[k] || arq[k];
  return { host: v("SFTP_HOST"), port: Number(v("SFTP_PORT") || 22), username: v("SFTP_USER"), password: v("SFTP_PASS") };
}
const SEGREDOS = carregarSegredos();

const app = express();
app.set("trust proxy", 1); // necessário atrás de Render/Cloudflare/Nginx
app.use(express.json({ limit: "2kb" }));
app.use(cors({ origin: SITE_URL }));

// No máximo 10 tentativas a cada 15 minutos por pessoa
app.use("/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { ok: false, erro: "Muitas tentativas. Aguarde alguns minutos." }
}));

// Página simples para você conferir se a API está no ar
app.get("/", (req, res) => res.type("text").send("API de login online."));

// ---------- Leitura dos arquivos ----------

function interpretar(texto) {
  const dados = {};
  for (const linha of texto.split(/\r?\n/)) {
    const i = linha.indexOf("=");
    if (i < 1) continue;
    dados[linha.slice(0, i).trim().toLowerCase()] = linha.slice(i + 1).trim();
  }
  return dados;
}
const pegar = (dados, campo) => dados[String(campo).toLowerCase()];

// Procura o arquivo ignorando maiúsculas/minúsculas. Só aceita nomes que existem na pasta.
function acharNome(nomes, nick) {
  const alvo = (nick + EXTENSAO).toLowerCase();
  return nomes.find((n) => n.toLowerCase() === alvo) || null;
}

async function buscarContaLocal(nick) {
  const nome = acharNome(fs.readdirSync(PASTA_LOCAL), nick);
  if (!nome) return null;
  return { nickReal: path.basename(nome, EXTENSAO), texto: fs.readFileSync(path.join(PASTA_LOCAL, nome), "latin1") };
}

// Guarda a lista de arquivos por 60 segundos para não pedir toda hora
let cacheLista = { quando: 0, nomes: [] };

async function buscarContaSftp(nick) {
  const Client = require("ssh2-sftp-client");
  const sftp = new Client();
  try {
    await sftp.connect({ host: SEGREDOS.host, port: SEGREDOS.port, username: SEGREDOS.username, password: SEGREDOS.password, readyTimeout: 15000 });
    if (Date.now() - cacheLista.quando > 60000) {
      cacheLista = { quando: Date.now(), nomes: (await sftp.list(PASTA_CONTAS)).map((f) => f.name) };
    }
    const nome = acharNome(cacheLista.nomes, nick);
    if (!nome) return null;
    const buf = await sftp.get(PASTA_CONTAS + "/" + nome);
    return { nickReal: path.basename(nome, EXTENSAO), texto: Buffer.from(buf).toString("latin1") };
  } finally {
    try { await sftp.end(); } catch (e) {}
  }
}

const buscarConta = MODO === "local" ? buscarContaLocal : buscarContaSftp;

// ---------- Senha ----------

const iguais = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};
const sha256 = (t) => crypto.createHash("sha256").update(t, "latin1").digest("hex").toUpperCase();

function calcularHash(senha, nick) {
  switch (SHA256_MODO) {
    case "senha":      return sha256(senha);
    case "senha+nick": return sha256(senha + nick);
    case "nick+senha": return sha256(nick + senha);
    case "senha+salt": return sha256(senha + SALT_FIXO);
    case "salt+senha": return sha256(SALT_FIXO + senha);
    default:           return "";
  }
}

function verificarSenha(digitada, nick, dados) {
  const guardada = pegar(dados, CAMPO_SENHA);
  if (!guardada) return false;
  return iguais(calcularHash(digitada, nick), guardada.toUpperCase());
}

function montarCampos(dados) {
  const lista = [];
  for (const c of CAMPOS) {
    let valor;
    if (c.tipo === "tempo") {
      valor = (pegar(dados, "DiasJogadas") || 0) + "d " + (pegar(dados, "HorasJogadas") || 0) + "h " + (pegar(dados, "MinutosJogadas") || 0) + "min";
    } else {
      valor = pegar(dados, c.chave);
      if (valor === undefined) continue;
      if (c.ocultarSeZero && (Number(valor) === 0 || valor === "")) continue;
      if (c.moeda) valor = "R$ " + Number(valor).toLocaleString("pt-BR");
    }
    lista.push({ rotulo: c.rotulo, valor });
  }
  return lista;
}

// ---------- Login ----------

app.post("/login", async (req, res) => {
  const nick = String(req.body.nick || "").trim();
  const senha = String(req.body.senha || "");
  const erroGenerico = { ok: false, erro: "Nick ou senha incorretos." };

  // Só aceita caracteres válidos de nick do SA-MP
  if (!/^[A-Za-z0-9_\[\]\$=@\.\(\)]{3,24}$/.test(nick) || !senha || senha.length > 64) {
    return res.status(401).json(erroGenerico);
  }

  try {
    const conta = await buscarConta(nick);
    if (!conta) return res.status(401).json(erroGenerico);

    const dados = interpretar(conta.texto);
    if (!verificarSenha(senha, conta.nickReal, dados)) return res.status(401).json(erroGenerico);

    // Devolve SOMENTE o que pode ser mostrado. Nunca envie senha, hash, IP ou serial.
    res.json({
      ok: true,
      perfil: {
        nick: pegar(dados, CAMPO_NOME) || conta.nickReal,
        skin: pegar(dados, CAMPO_SKIN),
        campos: montarCampos(dados)
      }
    });
  } catch (e) {
    console.error("Erro no login:", e.message);
    res.status(500).json({ ok: false, erro: "Erro interno. Tente novamente mais tarde." });
  }
});

app.listen(process.env.PORT || 3000, () => console.log("API de login rodando na porta " + (process.env.PORT || 3000)));

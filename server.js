// API DE LOGIN PARA SERVIDOR COM DOF2
// Roda na MESMA máquina onde está a pasta scriptfiles do servidor. NÃO roda no GitHub.
//
// Instalar:   npm init -y && npm i express cors express-rate-limit
// Rodar:      node server.js
//
// ANTES DE USAR, ajuste a seção "CONFIGURAÇÃO" abaixo.
// A API precisa estar em HTTPS (o site do GitHub é HTTPS e o navegador bloqueia o resto).
// Ela só LÊ os arquivos. Nunca escreve nada na pasta do servidor.

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

/* ===================== CONFIGURAÇÃO ===================== */

// Endereço do seu site no GitHub Pages (sem barra no final)
const SITE_URL = "https://SEUUSUARIO.github.io";

// Pasta onde o DOF2 salva as contas dos jogadores
const PASTA_CONTAS = "C:/servidor/scriptfiles/Contas";

// Extensão dos arquivos de conta
const EXTENSAO = ".ini";

// Nomes dos campos no arquivo de conta
const CAMPO_SENHA = "Senha";
const CAMPO_SKIN = "Skin";
const CAMPO_NOME = "Nome";

// Como a senha é calculada. Rode o testar-hash.js para descobrir qual é a sua.
//   "senha"       -> SHA256 da senha pura
//   "senha+nick"  -> SHA256 de (senha + nick)
//   "nick+senha"  -> SHA256 de (nick + senha)
//   "senha+salt"  -> SHA256 de (senha + SALT_FIXO)
//   "salt+senha"  -> SHA256 de (SALT_FIXO + senha)
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
  // Adicione mais, por exemplo: { rotulo: "Casa", chave: "Casa", ocultarSeZero: true },
];

/* ======================================================== */

const app = express();
app.set("trust proxy", 1); // necessário se estiver atrás de Cloudflare/Nginx
app.use(express.json({ limit: "2kb" }));
app.use(cors({ origin: SITE_URL }));

// No máximo 10 tentativas a cada 15 minutos por pessoa
app.use("/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { ok: false, erro: "Muitas tentativas. Aguarde alguns minutos." }
}));

// Lê um arquivo do DOF2 (linhas "Campo = Valor") e devolve um objeto
function lerArquivo(caminho) {
  const dados = {};
  const texto = fs.readFileSync(caminho, "latin1");
  for (const linha of texto.split(/\r?\n/)) {
    const i = linha.indexOf("=");
    if (i < 1) continue;
    dados[linha.slice(0, i).trim().toLowerCase()] = linha.slice(i + 1).trim();
  }
  return dados;
}
const pegar = (dados, campo) => dados[String(campo).toLowerCase()];

// Procura o arquivo da conta ignorando maiúsculas/minúsculas.
// Só aceita arquivos que realmente existem na pasta (evita acessar outras pastas).
function acharArquivo(nick) {
  const alvo = (nick + EXTENSAO).toLowerCase();
  const nome = fs.readdirSync(PASTA_CONTAS).find((n) => n.toLowerCase() === alvo);
  return nome ? path.join(PASTA_CONTAS, nome) : null;
}

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
      const d = pegar(dados, "DiasJogadas") || 0;
      const h = pegar(dados, "HorasJogadas") || 0;
      const m = pegar(dados, "MinutosJogadas") || 0;
      valor = d + "d " + h + "h " + m + "min";
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

app.post("/login", async (req, res) => {
  const nick = String(req.body.nick || "").trim();
  const senha = String(req.body.senha || "");
  const erroGenerico = { ok: false, erro: "Nick ou senha incorretos." };

  // Só aceita caracteres válidos de nick do SA-MP
  if (!/^[A-Za-z0-9_\[\]\$=@\.\(\)]{3,24}$/.test(nick) || !senha || senha.length > 64) {
    return res.status(401).json(erroGenerico);
  }

  try {
    const arquivo = acharArquivo(nick);
    if (!arquivo) return res.status(401).json(erroGenerico);

    const nickReal = path.basename(arquivo, EXTENSAO);
    const dados = lerArquivo(arquivo);
    if (!verificarSenha(senha, nickReal, dados)) return res.status(401).json(erroGenerico);

    // Devolve SOMENTE o que pode ser mostrado. Nunca envie senha, hash, IP ou serial.
    res.json({
      ok: true,
      perfil: {
        nick: pegar(dados, CAMPO_NOME) || nickReal,
        skin: pegar(dados, CAMPO_SKIN),
        campos: montarCampos(dados)
      }
    });
  } catch (e) {
    console.error("Erro no login:", e.message);
    res.status(500).json({ ok: false, erro: "Erro interno. Tente novamente mais tarde." });
  }
});

app.listen(3000, () => console.log("API de login rodando na porta 3000"));

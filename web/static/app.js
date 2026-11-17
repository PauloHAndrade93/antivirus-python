"use strict";

const TOKEN = document.querySelector('meta[name="avpy-token"]').content;
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

const VIEWS = {
  painel:        ["Painel", "Visão geral da proteção deste computador"],
  varreduras:    ["Varreduras", "Procure malware em pastas ou em drives inteiros"],
  monitoramento: ["Monitoramento", "Rede e comportamento em tempo real"],
  auditoria:     ["Auditoria", "Persistência, processos e integridade do sistema"],
  inteligencia:  ["Inteligência", "Reputação externa e feeds de ameaças"],
  quarentena:    ["Quarentena", "Arquivos isolados pelo AV-Py"],
  relatorios:    ["Relatórios", "Logs gravados pelas varreduras"],
};

const ESTADOS = {
  rodando:   "Executando",
  limpo:     "Limpo",
  ameaca:    "Atenção",
  erro:      "Erro",
  cancelado: "Cancelado",
};

let STATUS = null;
let jobAtual = null;
let pollTimer = null;
let linhasVistas = 0;

/* ------------------------------------------------------------ util */

async function api(caminho, opts = {}) {
  const resp = await fetch(caminho, {
    ...opts,
    headers: { "Content-Type": "application/json", "X-AVPY-Token": TOKEN, ...(opts.headers || {}) },
  });
  let dados = null;
  try { dados = await resp.json(); } catch { /* sem corpo */ }
  if (!resp.ok) throw new Error((dados && dados.erro) || `HTTP ${resp.status}`);
  return dados;
}

const fmtNum = (n) => (n ?? 0).toLocaleString("pt-BR");
const fmtHora = (ts) => new Date(ts * 1000).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtData = (ts) => new Date(ts * 1000).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });

function fmtDuracao(seg) {
  if (seg == null) return "–";
  seg = Math.max(0, Math.round(seg));
  if (seg < 60) return `${seg}s`;
  const m = Math.floor(seg / 60), s = seg % 60;
  if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

function fmtBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

function el(tag, attrs = {}, ...filhos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const f of filhos) if (f != null) n.append(f);
  return n;
}

function icone(nome) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "ic");
  const use = document.createElementNS(ns, "use");
  use.setAttribute("href", `#i-${nome}`);
  svg.append(use);
  return svg;
}

function toast(msg, tipo = "") {
  const t = el("div", { class: `toast ${tipo}`, text: msg });
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 4200);
}

function estadoDoJob(j) {
  if (j.status === "rodando") return "rodando";
  if (j.status === "cancelado") return "cancelado";
  if (j.codigo === 0) return "limpo";
  if (j.codigo === 1) return "ameaca";
  return "erro";
}

function badge(estado) {
  return el("span", { class: `badge ${estado}`, text: ESTADOS[estado] });
}

/* ------------------------------------------------------------ navegação */

function mostrarView(nome) {
  if (!VIEWS[nome]) nome = "painel";
  $$(".nav-item").forEach((b) => b.classList.toggle("ativo", b.dataset.view === nome));
  $$(".view").forEach((s) => { s.hidden = s.id !== `view-${nome}`; });
  $("#view-title").textContent = VIEWS[nome][0];
  $("#view-sub").textContent = VIEWS[nome][1];
  if (nome === "quarentena") carregarQuarentena();
  if (nome === "relatorios") carregarRelatorios();
  try { localStorage.setItem("avpy-view", nome); } catch { /* sem storage */ }
}

/* ------------------------------------------------------------ status */

function marcarPill(seletor, ligado) {
  const p = $(seletor);
  if (!p) return;
  p.classList.toggle("on", ligado);
  p.classList.toggle("off", !ligado);
  p.title = ligado ? "Chave configurada" : "Chave não configurada";
}

async function carregarStatus() {
  try {
    STATUS = await api("/api/status");
  } catch (e) {
    toast(`Não consegui ler o status: ${e.message}`, "erro");
    return;
  }
  $("#st-hashes").textContent = fmtNum(STATUS.hashes);
  $("#st-regras").textContent = fmtNum(STATUS.regras);
  $("#st-urls").textContent = fmtNum(STATUS.urls);
  $("#st-quarentena").textContent = fmtNum(STATUS.quarentena);

  for (const [a, b] of [["#pill-vt", "#pill-vt-2"]]) { marcarPill(a, STATUS.chaves.virustotal); marcarPill(b, STATUS.chaves.virustotal); }
  for (const [a, b] of [["#pill-abuse", "#pill-abuse-2"]]) { marcarPill(a, STATUS.chaves.abusech); marcarPill(b, STATUS.chaves.abusech); }

  const pasta = $("#scan-pasta");
  if (!pasta.value) pasta.value = `${STATUS.home}\\Downloads`;

  // drives: select + chips
  const sel = $("#fs-drive");
  const atual = sel.value;
  sel.replaceChildren(el("option", { value: "todos", text: "Todos os drives" }));
  const chips = $("#drives");
  chips.replaceChildren();
  for (const d of STATUS.drives) {
    const letra = d.letra.replace(/\\$/, "");
    const usb = d.tipo === "removable";
    const tipo = usb ? "Removível (USB)" : d.tipo === "fixed" ? "Disco fixo" : d.tipo;
    sel.append(el("option", { value: letra, text: `${letra}  ·  ${tipo}` }));
    chips.append(el("button", {
      class: `chip${usb ? " usb" : ""}`, type: "button", title: `Varredura completa em ${letra}`,
      onclick: () => {
        mostrarView("varreduras");
        sel.value = letra;
        $("#fs-drive").scrollIntoView({ behavior: "smooth", block: "center" });
      },
    }, icone(usb ? "usb" : "drive"), el("div", {}, el("b", { text: letra }), el("small", { text: `${tipo} · ${d.fs}` }))));
  }
  if ([...sel.options].some((o) => o.value === atual)) sel.value = atual;

  atualizarHero();
}

function atualizarHero(ultimoJob) {
  const hero = $("#hero");
  const titulo = $("#hero-titulo");
  const sub = $("#hero-sub");
  const iconeUse = $("#hero-icone");
  hero.classList.remove("alerta", "neutro");

  if (ultimoJob && ultimoJob.status !== "rodando") {
    const est = estadoDoJob(ultimoJob);
    if (est === "ameaca") {
      hero.classList.add("alerta");
      iconeUse.setAttribute("href", "#i-alerta");
      titulo.textContent = "Atenção: algo foi encontrado";
      sub.textContent = `“${ultimoJob.rotulo}” levantou alertas. Abra o console para ver os detalhes.`;
      return;
    }
    if (est === "limpo") {
      iconeUse.setAttribute("href", "#i-shield");
      titulo.textContent = "Tudo limpo";
      sub.textContent = `“${ultimoJob.rotulo}” terminou sem ameaças às ${fmtHora(ultimoJob.fim)}.`;
      return;
    }
  }

  const fs = STATUS && STATUS.ultimo_fullscan;
  iconeUse.setAttribute("href", "#i-shield");
  if (!fs) {
    hero.classList.add("neutro");
    titulo.textContent = "Pronto para proteger";
    sub.textContent = "Nenhuma varredura completa registrada ainda. Comece pelos Downloads.";
  } else if (fs.deteccoes) {
    hero.classList.add("alerta");
    iconeUse.setAttribute("href", "#i-alerta");
    titulo.textContent = `${fmtNum(fs.deteccoes)} detecção(ões) na última varredura`;
    sub.textContent = `Varredura completa de ${fmtData(fs.quando)}. Veja em Relatórios.`;
  } else {
    titulo.textContent = "Sistema protegido";
    sub.textContent = `Última varredura completa em ${fmtData(fs.quando)}, sem ameaças.`;
  }
}

/* ------------------------------------------------------------ jobs */

async function iniciar(acao, params, rotulo, botao) {
  if (botao) botao.disabled = true;
  try {
    const { id } = await api("/api/jobs", { method: "POST", body: JSON.stringify({ acao, params, rotulo }) });
    abrirConsole(id, rotulo);
    carregarJobs();
  } catch (e) {
    toast(e.message, "erro");
  } finally {
    if (botao) setTimeout(() => { botao.disabled = false; }, 600);
  }
}

function resetarMetricas() {
  for (const id of ["m-arquivos", "m-deteccoes", "m-erros"]) $(`#${id}`).textContent = "0";
  $("#m-taxa").textContent = "–";
  $("#console-metricas").hidden = true;
}

function abrirConsole(id, rotulo) {
  clearTimeout(pollTimer);
  jobAtual = id;
  linhasVistas = 0;
  $("#console-out").replaceChildren();
  $("#console-titulo").textContent = rotulo || "Tarefa";
  definirBadge("rodando");
  resetarMetricas();
  $("#console").classList.add("aberto");
  poll();
}

function definirBadge(estado) {
  const b = $("#console-badge");
  b.hidden = false;
  b.className = `badge ${estado}`;
  b.textContent = ESTADOS[estado];
  $("#btn-cancelar").hidden = estado !== "rodando";
}

function classeDaLinha(l) {
  if (l.startsWith("[!!]")) return "l-ransom";
  if (l.startsWith("[!]")) return "l-alerta";
  if (l.startsWith("[+]")) return "l-ok";
  if (l.startsWith("[i]")) return "l-info";
  if (/\[progresso/.test(l)) return "l-prog";
  if (/^\s*=+/.test(l)) return "l-sec";
  return "";
}

function lerProgresso(l) {
  const m = l.match(/(\d+) arquivos.*deteccoes=(\d+)\s+erros=(\d+)\s+\((\d+) arq\/s\)/);
  if (!m) return;
  $("#console-metricas").hidden = false;
  $("#m-arquivos").textContent = fmtNum(+m[1]);
  $("#m-deteccoes").textContent = fmtNum(+m[2]);
  $("#m-erros").textContent = fmtNum(+m[3]);
  $("#m-taxa").textContent = `${m[4]}/s`;
}

function adicionarLinhas(linhas) {
  if (!linhas.length) return;
  const out = $("#console-out");
  const perto = out.scrollHeight - out.scrollTop - out.clientHeight < 60;
  const frag = document.createDocumentFragment();
  for (const l of linhas) {
    frag.append(el("div", { class: classeDaLinha(l), text: l || " " }));
    lerProgresso(l);
  }
  out.append(frag);
  while (out.childElementCount > 4000) out.firstElementChild.remove();
  if (perto) out.scrollTop = out.scrollHeight;
}

async function poll() {
  clearTimeout(pollTimer);
  const id = jobAtual;
  if (!id) return;
  try {
    const j = await api(`/api/jobs/${id}?desde=${linhasVistas}`);
    if (id !== jobAtual) return;
    adicionarLinhas(j.linhas);
    linhasVistas = j.total;
    if (j.status === "rodando") {
      pollTimer = setTimeout(poll, 600);
    } else {
      finalizar(j);
    }
  } catch {
    pollTimer = setTimeout(poll, 1500);
  }
}

function finalizar(j) {
  const est = estadoDoJob(j);
  definirBadge(est);
  if (!$("#console-out").childElementCount) {
    adicionarLinhas(["[i] Tarefa terminou sem saída."]);
  }
  const msg = {
    limpo: `✔ ${j.rotulo}: nada encontrado`,
    ameaca: `⚠ ${j.rotulo}: há alertas — confira o console`,
    erro: `${j.rotulo}: terminou com erro`,
    cancelado: `${j.rotulo}: cancelada`,
  }[est];
  toast(msg, est === "limpo" ? "ok" : est === "ameaca" || est === "erro" ? "erro" : "");
  carregarStatus().then(() => atualizarHero(j));
  carregarJobs();
}

async function cancelar() {
  if (!jobAtual) return;
  try {
    await api(`/api/jobs/${jobAtual}/cancelar`, { method: "POST" });
  } catch (e) {
    toast(e.message, "erro");
  }
}

async function carregarJobs() {
  let jobs = [];
  try { jobs = await api("/api/jobs"); } catch { return; }
  const corpo = $("#jobs-corpo");
  corpo.replaceChildren();
  $("#jobs-vazio").hidden = jobs.length > 0;
  for (const j of jobs) {
    const dur = (j.fim || Date.now() / 1000) - j.inicio;
    corpo.append(el("tr", {
      class: "clicavel", title: "Abrir no console",
      onclick: () => abrirConsole(j.id, j.rotulo),
    },
      el("td", { text: j.rotulo }),
      el("td", { text: fmtHora(j.inicio) }),
      el("td", { text: fmtDuracao(dur) }),
      el("td", {}, badge(estadoDoJob(j))),
    ));
  }
  if (jobs.some((j) => j.status === "rodando")) setTimeout(carregarJobs, 2000);
}

/* ------------------------------------------------------------ quarentena / relatórios */

async function carregarQuarentena() {
  let itens = [];
  try { itens = await api("/api/quarentena"); } catch (e) { toast(e.message, "erro"); return; }
  const corpo = $("#q-corpo");
  corpo.replaceChildren();
  $("#q-vazio").hidden = itens.length > 0;
  for (const q of itens) {
    corpo.append(el("tr", {},
      el("td", { text: (q.momento || "").replace("T", " ") }),
      el("td", { class: "td-mono", text: q.origem || "" }),
      el("td", { class: "td-mono", text: q.motivo || "" }),
    ));
  }
}

async function carregarRelatorios() {
  let itens = [];
  try { itens = await api("/api/relatorios"); } catch (e) { toast(e.message, "erro"); return; }
  const lista = $("#rel-lista");
  lista.replaceChildren();
  $("#rel-vazio").hidden = itens.length > 0;
  for (const r of itens) {
    lista.append(el("button", {
      class: "rel-item", type: "button",
      onclick: (ev) => abrirRelatorio(r.nome, ev.currentTarget),
    }, el("span", { text: r.nome }), el("small", { text: `${fmtData(r.quando)} · ${fmtBytes(r.tamanho)}` })));
  }
}

async function abrirRelatorio(nome, botao) {
  $$(".rel-item").forEach((b) => b.classList.toggle("ativo", b === botao));
  try {
    const r = await api(`/api/relatorios/${encodeURIComponent(nome)}`);
    $("#rel-titulo").textContent = r.nome;
    $("#rel-conteudo").textContent = r.conteudo || "(vazio)";
  } catch (e) {
    toast(e.message, "erro");
  }
}

/* ------------------------------------------------------------ eventos */

function coletar(form) {
  const p = {};
  for (const [k, v] of new FormData(form)) p[k] = v;
  $$('input[type="checkbox"]', form).forEach((c) => { p[c.name] = c.checked; });
  return p;
}

$$(".nav-item").forEach((b) => b.addEventListener("click", () => mostrarView(b.dataset.view)));

$$("form[data-acao]").forEach((f) => f.addEventListener("submit", (ev) => {
  ev.preventDefault();
  iniciar(f.dataset.acao, coletar(f), f.dataset.rotulo, f.querySelector('button[type="submit"]'));
}));

const RAPIDOS = {
  "scan-downloads": () => ["scan", { pasta: `${STATUS ? STATUS.home : ""}\\Downloads` }, "Escanear Downloads"],
  procs: () => ["procs", {}, "Auditoria de processos"],
  hosts: () => ["hosts", {}, "Integridade do hosts"],
};
$$("[data-rapido]").forEach((b) => b.addEventListener("click", () => {
  const [acao, params, rotulo] = RAPIDOS[b.dataset.rapido]();
  iniciar(acao, params, rotulo, b);
}));

// pendrive marcado => o drive escolhido deixa de valer
const usbCheck = $('form[data-acao="fullscan"] input[name="usb_only"]');
usbCheck.addEventListener("change", () => { $("#fs-drive").disabled = usbCheck.checked; });

$("#btn-cancelar").addEventListener("click", cancelar);
$("#btn-fechar-console").addEventListener("click", () => $("#console").classList.remove("aberto"));
$("#btn-abrir-console").addEventListener("click", () => $("#console").classList.toggle("aberto"));
$("#btn-recarregar-q").addEventListener("click", carregarQuarentena);
$("#btn-recarregar-r").addEventListener("click", carregarRelatorios);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") $("#console").classList.remove("aberto");
});

/* ------------------------------------------------------------ início */

let inicial = "painel";
try { inicial = localStorage.getItem("avpy-view") || "painel"; } catch { /* sem storage */ }
mostrarView(inicial);
carregarStatus();
carregarJobs();

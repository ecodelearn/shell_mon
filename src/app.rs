//! Estado da aplicação: filtros, ordenação, seleção e refresh.

use crate::analysis::{browser_ancestor, zone, Zone};
use crate::events::EventLog;
use crate::procinfo::{self, Io};
use crate::rdns::Resolver;
use crate::socket::{collect, Socket, Summary};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Por quanto tempo uma conexão nova fica destacada, independente do intervalo
/// de refresh (a 200ms, um único ciclo seria curto demais para enxergar).
const HIGHLIGHT_DURATION: Duration = Duration::from_millis(1500);

/// UDP "escuta" em estado UNCONN; sockets UDP efêmeros (consultas DNS/QUIC)
/// ligam-se a `0.0.0.0` por um instante. Só consideramos um UDP exposto depois
/// que ele persiste por esse tempo — evita blips no contador e no log.
const EXPOSE_DEBOUNCE: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// Rede (TCP+UDP) — padrão; UNIX fica de fora para não inundar.
    Net,
    Tcp,
    Udp,
    Unix,
}

impl Proto {
    pub fn label(&self) -> &'static str {
        match self {
            Proto::Net => "rede",
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Unix => "unix",
        }
    }
    pub fn next(self) -> Proto {
        match self {
            Proto::Net => Proto::Tcp,
            Proto::Tcp => Proto::Udp,
            Proto::Udp => Proto::Unix,
            Proto::Unix => Proto::Net,
        }
    }

    /// O socket passa por este filtro de protocolo?
    pub fn matches(self, netid: &str) -> bool {
        match self {
            Proto::Net => netid == "tcp" || netid == "udp",
            Proto::Tcp => netid == "tcp",
            Proto::Udp => netid == "udp",
            Proto::Unix => netid.starts_with("u_"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    State,
    Local,
    Peer,
    Process,
    RecvQ,
    SendQ,
}

impl SortKey {
    pub fn label(&self) -> &'static str {
        match self {
            SortKey::State => "estado",
            SortKey::Local => "local",
            SortKey::Peer => "remoto",
            SortKey::Process => "processo",
            SortKey::RecvQ => "recv-q",
            SortKey::SendQ => "send-q",
        }
    }
    pub fn next(self) -> SortKey {
        use SortKey::*;
        match self {
            State => Local,
            Local => Peer,
            Peer => Process,
            Process => RecvQ,
            RecvQ => SendQ,
            SendQ => State,
        }
    }
}

pub struct App {
    pub sockets: Vec<Socket>,
    pub summary: Summary,
    pub proto: Proto,
    pub sort: SortKey,
    pub filter: String,
    pub filter_mode: bool,
    pub selected: usize,
    pub paused: bool,
    pub is_root: bool,
    pub interval: Duration,
    pub last_refresh: Instant,
    pub last_error: Option<String>,
    /// Chaves vistas no último refresh, para marcar conexões novas.
    seen_keys: HashSet<String>,
    /// Quando cada conexão nova foi detectada (para expirar o destaque).
    new_at: HashMap<String, Instant>,
    /// Cache por PID: nome do navegador ancestral, se houver.
    browser: HashMap<u32, Option<String>>,
    /// Quando cada socket exposto foi visto pela primeira vez (debounce de UDP).
    exposed_since: HashMap<String, Instant>,
    /// Já estabelecemos a linha de base de exposição? (1º refresh = imediato).
    exposed_baselined: bool,
    /// Log de eventos defensivos em disco (None se desabilitado).
    log: Option<EventLog>,
    /// Resolvedor de DNS reverso em background (nomes humanos pros IPs).
    rdns: Resolver,
    /// Painel de inspeção do processo selecionado aberto?
    pub inspector: bool,
    /// Amostra anterior para calcular taxas: (pid, io, cpu_ticks, total, quando).
    /// Cada métrica é Option porque o I/O pode ser ilegível (yama) enquanto a
    /// CPU (de /proc/stat) continua acessível.
    proc_sample: Option<(u32, Option<Io>, Option<u64>, Option<u64>, Instant)>,
    /// Taxas calculadas do processo inspecionado (None = sem permissão/sem dado).
    inspect_rd: Option<f64>,
    inspect_wr: Option<f64>,
    inspect_cpu: Option<f64>,
    pub should_quit: bool,
}

impl App {
    pub fn new(interval: Duration, is_root: bool, log: Option<EventLog>, rdns_enabled: bool) -> Self {
        let mut app = App {
            sockets: Vec::new(),
            summary: Summary::default(),
            proto: Proto::Net,
            sort: SortKey::State,
            filter: String::new(),
            filter_mode: false,
            selected: 0,
            paused: false,
            is_root,
            interval,
            last_refresh: Instant::now(),
            last_error: None,
            seen_keys: HashSet::new(),
            new_at: HashMap::new(),
            browser: HashMap::new(),
            exposed_since: HashMap::new(),
            exposed_baselined: false,
            log,
            rdns: Resolver::new(rdns_enabled),
            inspector: false,
            proc_sample: None,
            inspect_rd: None,
            inspect_wr: None,
            inspect_cpu: None,
            should_quit: false,
        };
        app.refresh();
        // Auditoria de configuração de rede uma vez no início: sinaliza DNS
        // não reconhecido (possível sequestro pela rede local) no log e via
        // notificação.
        if let Some(log) = app.log.as_mut() {
            for w in crate::netcfg::NetAudit::collect().warnings() {
                log.warn("DNS_SUSPECT", &w);
            }
            for w in crate::netcfg::Firewall::detect().warnings() {
                log.warn("FIREWALL", &w);
            }
        }
        app
    }

    /// Caminho do log de eventos, se habilitado.
    pub fn log_path(&self) -> Option<&std::path::Path> {
        self.log.as_ref().map(|l| l.path())
    }

    /// Notificações de desktop estão ativas?
    pub fn notifying(&self) -> bool {
        self.log.as_ref().map(|l| l.notifying()).unwrap_or(false)
    }

    /// Marca (DNS reverso) já resolvida para um IP, se houver.
    pub fn brand(&self, ip: &str) -> Option<String> {
        self.rdns.get(ip)
    }

    pub fn toggle_inspector(&mut self) {
        self.inspector = !self.inspector;
        // Zera a amostra para não calcular taxa contra um PID antigo.
        self.proc_sample = None;
        self.inspect_rd = None;
        self.inspect_wr = None;
        self.inspect_cpu = None;
    }

    /// Socket atualmente selecionado na lista visível.
    pub fn selected_socket(&self) -> Option<&Socket> {
        self.visible().into_iter().nth(self.selected)
    }

    /// Taxas do processo inspecionado: (leitura B/s, escrita B/s, cpu %).
    pub fn inspect_rates(&self) -> (Option<f64>, Option<f64>, Option<f64>) {
        (self.inspect_rd, self.inspect_wr, self.inspect_cpu)
    }

    /// Amostra o I/O de disco e a CPU do PID, calculando taxas vs a amostra
    /// anterior. Sem permissão (processo de outro usuário sem root) → None.
    fn sample_proc(&mut self, pid: Option<u32>) {
        let Some(pid) = pid else {
            self.proc_sample = None;
            self.inspect_rd = None;
            self.inspect_wr = None;
            self.inspect_cpu = None;
            return;
        };
        let io = procinfo::io(pid);
        let cpu = procinfo::cpu_ticks(pid);
        let total = procinfo::total_jiffies();

        // Calcula taxas contra a amostra anterior (cada métrica independente).
        self.inspect_rd = None;
        self.inspect_wr = None;
        self.inspect_cpu = None;
        if let Some((ppid, pio, pcpu, ptot, at)) = &self.proc_sample {
            if *ppid == pid {
                let dt = at.elapsed().as_secs_f64().max(0.001);
                if let (Some(c), Some(p)) = (io, *pio) {
                    self.inspect_rd = Some(c.read_bytes.saturating_sub(p.read_bytes) as f64 / dt);
                    self.inspect_wr = Some(c.write_bytes.saturating_sub(p.write_bytes) as f64 / dt);
                }
                if let (Some(c), Some(pc), Some(t), Some(pt)) = (cpu, *pcpu, total, *ptot) {
                    let dtot = t.saturating_sub(pt);
                    if dtot > 0 {
                        self.inspect_cpu = Some(100.0 * c.saturating_sub(pc) as f64 / dtot as f64);
                    }
                }
            }
        }
        self.proc_sample = Some((pid, io, cpu, total, Instant::now()));
    }

    pub fn refresh(&mut self) {
        match collect() {
            Ok(sockets) => {
                let current: HashSet<String> = sockets.iter().map(|s| s.key()).collect();
                let now = Instant::now();
                // Marca conexões que não existiam no refresh anterior (mas não
                // no primeiro refresh, senão tudo apareceria como "novo").
                if !self.seen_keys.is_empty() {
                    for k in current.difference(&self.seen_keys) {
                        self.new_at.insert(k.clone(), now);
                    }
                }
                // Mantém apenas destaques recentes e que ainda existem.
                self.new_at
                    .retain(|k, t| current.contains(k) && now.duration_since(*t) < HIGHLIGHT_DURATION);
                self.seen_keys = current;
                // Cache de navegador só para PIDs de sockets de rede (os de IPC
                // local não importam para a detecção de escalada).
                let pids: HashSet<u32> =
                    sockets.iter().filter(|s| s.is_network()).filter_map(|s| s.pid).collect();
                self.browser.retain(|pid, _| pids.contains(pid));
                for pid in pids {
                    self.browser
                        .entry(pid)
                        .or_insert_with(|| browser_ancestor(pid));
                }
                // Debounce de exposição: TCP em LISTEN é estável na hora; UDP
                // (UNCONN em 0.0.0.0) só conta depois de persistir, para não
                // piscar com sockets efêmeros. Sockets já presentes na linha de
                // base entram como estáveis (não viram "novo").
                let mut stable: HashSet<String> = HashSet::new();
                let mut still: HashMap<String, Instant> = HashMap::new();
                for s in &sockets {
                    if !s.is_exposed() {
                        continue;
                    }
                    let key = s.key();
                    let since = self.exposed_since.get(&key).copied().unwrap_or_else(|| {
                        if self.exposed_baselined {
                            now
                        } else {
                            now.checked_sub(EXPOSE_DEBOUNCE).unwrap_or(now)
                        }
                    });
                    if s.netid == "tcp" || now.duration_since(since) >= EXPOSE_DEBOUNCE {
                        stable.insert(key.clone());
                    }
                    still.insert(key, since);
                }
                self.exposed_since = still;
                self.exposed_baselined = true;

                self.summary = Summary::from(&sockets);
                self.summary.exposed = stable.len(); // contagem com debounce
                self.sockets = sockets;
                self.last_error = None;
                // Pede DNS reverso (em background) para pares de rede na internet.
                for s in &self.sockets {
                    if s.is_network() && zone(&s.peer_addr) == Zone::Public {
                        self.rdns.request(&s.peer_addr);
                    }
                }
                // Registra eventos defensivos (listeners/entradas da LAN).
                if let Some(log) = self.log.as_mut() {
                    log.record(&self.sockets, &stable);
                }
                // Atualiza as taxas de I/O/CPU do processo inspecionado.
                if self.inspector {
                    let pid = {
                        let v = self.visible();
                        v.get(self.selected).and_then(|s| s.pid)
                    };
                    self.sample_proc(pid);
                }
            }
            Err(e) => self.last_error = Some(e),
        }
        self.last_refresh = Instant::now();
    }

    /// Uma conexão está "nova" se foi detectada há menos de `HIGHLIGHT_DURATION`.
    pub fn is_new(&self, key: &str) -> bool {
        self.new_at.contains_key(key)
    }

    /// Nome do navegador ancestral de um PID, se a conexão foi aberta por
    /// um (descendente de) navegador.
    pub fn browser_of(&self, pid: Option<u32>) -> Option<&str> {
        pid.and_then(|p| self.browser.get(&p))
            .and_then(|o| o.as_deref())
    }

    pub fn maybe_refresh(&mut self) {
        if !self.paused && self.last_refresh.elapsed() >= self.interval {
            self.refresh();
            self.clamp_selection();
        }
    }

    /// Lista filtrada e ordenada que vai pra tela.
    pub fn visible(&self) -> Vec<&Socket> {
        let needle = self.filter.to_lowercase();
        let mut v: Vec<&Socket> = self
            .sockets
            .iter()
            .filter(|s| self.proto.matches(&s.netid))
            .filter(|s| {
                if needle.is_empty() {
                    return true;
                }
                s.local().to_lowercase().contains(&needle)
                    || s.peer().to_lowercase().contains(&needle)
                    || s.process.to_lowercase().contains(&needle)
                    || s.state.to_lowercase().contains(&needle)
                    || s.pid.map(|p| p.to_string()).unwrap_or_default().contains(&needle)
            })
            .collect();

        v.sort_by(|a, b| match self.sort {
            SortKey::State => a.state.cmp(&b.state),
            SortKey::Local => port_num(&a.local_port).cmp(&port_num(&b.local_port)),
            SortKey::Peer => a.peer_addr.cmp(&b.peer_addr),
            SortKey::Process => a.process.cmp(&b.process),
            SortKey::RecvQ => b.recv_q.cmp(&a.recv_q),
            SortKey::SendQ => b.send_q.cmp(&a.send_q),
        });
        v
    }

    pub fn clamp_selection(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    pub fn move_down(&mut self) {
        let len = self.visible().len();
        if len > 0 && self.selected + 1 < len {
            self.selected += 1;
        }
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn page_down(&mut self, page: usize) {
        let len = self.visible().len();
        if len > 0 {
            self.selected = (self.selected + page).min(len - 1);
        }
    }

    pub fn page_up(&mut self, page: usize) {
        self.selected = self.selected.saturating_sub(page);
    }
}

/// Ordena portas numericamente; portas não-numéricas (raras com `-n`) vão pro fim.
fn port_num(p: &str) -> u32 {
    p.parse().unwrap_or(u32::MAX)
}

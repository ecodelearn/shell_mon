//! Log de eventos defensivos em disco — registra apenas eventos de alto sinal
//! (listeners aparecendo/sumindo e conexões entrando da LAN), para revisão
//! posterior ("o que rolou enquanto eu não estava olhando").

use crate::analysis::{browser_ancestor, zone, Zone};
use crate::notify::Notifier;
use crate::socket::Socket;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
enum Severity {
    Info,
    High,
}

impl Severity {
    fn tag(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::High => "HIGH",
        }
    }
}

/// Informação de um listener para descrição e diff.
struct ListenInfo {
    exposed: bool,
    desc: String,
}

pub struct EventLog {
    path: PathBuf,
    file: File,
    notifier: Notifier,
    prev_listeners: HashMap<String, ListenInfo>,
    prev_inbound: HashMap<String, String>,
    started: bool,
}

impl EventLog {
    /// Abre (criando se preciso) o log no caminho padrão:
    /// `$SHELLMON_LOG`, ou `$XDG_DATA_HOME/shellmon/events.log`, ou
    /// `$HOME/.local/share/shellmon/events.log`.
    pub fn open_default(notify_enabled: bool) -> std::io::Result<EventLog> {
        let path = default_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(EventLog {
            path,
            file,
            notifier: Notifier::new(notify_enabled),
            prev_listeners: HashMap::new(),
            prev_inbound: HashMap::new(),
            started: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Notificações de desktop estão ativas?
    pub fn notifying(&self) -> bool {
        self.notifier.enabled()
    }

    /// Registra um aviso de alta severidade (ex.: DNS suspeito do `netcfg`).
    pub fn warn(&mut self, kind: &str, desc: &str) {
        self.write(Severity::High, kind, desc);
    }

    /// Diffa o estado atual contra o anterior e registra os eventos relevantes.
    pub fn record(&mut self, sockets: &[Socket]) {
        let (listeners, inbound) = snapshot(sockets);

        if !self.started {
            // Primeira passada: estabelece a linha de base sem despejar tudo
            // como "novo".
            let exposed = listeners.values().filter(|l| l.exposed).count();
            self.write(
                Severity::Info,
                "SESSION_START",
                &format!(
                    "monitorando — base: {} listeners ({} expostos), {} entradas da LAN",
                    listeners.len(),
                    exposed,
                    inbound.len()
                ),
            );
            self.prev_listeners = listeners;
            self.prev_inbound = inbound;
            self.started = true;
            return;
        }

        // Coleta os eventos antes de escrever, para não pegar `self` emprestado
        // mutável e imutável ao mesmo tempo.
        let mut events: Vec<(Severity, &str, String)> = Vec::new();
        for (k, info) in &listeners {
            if !self.prev_listeners.contains_key(k) {
                let sev = if info.exposed { Severity::High } else { Severity::Info };
                events.push((sev, "LISTEN_NEW", info.desc.clone()));
            }
        }
        for (k, info) in &self.prev_listeners {
            if !listeners.contains_key(k) {
                events.push((Severity::Info, "LISTEN_GONE", info.desc.clone()));
            }
        }
        for (k, desc) in &inbound {
            if !self.prev_inbound.contains_key(k) {
                events.push((Severity::High, "LAN_INBOUND", desc.clone()));
            }
        }
        for (k, desc) in &self.prev_inbound {
            if !inbound.contains_key(k) {
                events.push((Severity::Info, "LAN_INBOUND_END", desc.clone()));
            }
        }

        for (sev, kind, desc) in events {
            self.write(sev, kind, &desc);
        }

        self.prev_listeners = listeners;
        self.prev_inbound = inbound;
    }

    fn write(&mut self, sev: Severity, kind: &str, desc: &str) {
        let line = format!("{}  [{}] {:16} {}\n", now_local(), sev.tag(), kind, desc);
        // Erros de escrita no log não devem derrubar o monitor.
        let _ = self.file.write_all(line.as_bytes());
        let _ = self.file.flush();
        // Eventos de alta severidade também viram notificação de desktop.
        if matches!(sev, Severity::High) {
            self.notifier.notify(notif_title(kind), desc);
        }
    }
}

/// Título amigável da notificação conforme o tipo de evento.
fn notif_title(kind: &str) -> &'static str {
    match kind {
        "LISTEN_NEW" => "🛡 Novo serviço escutando exposto",
        "LAN_INBOUND" => "🛡 Conexão entrando da rede local",
        "DNS_SUSPECT" => "🛡 DNS suspeito na rede",
        "FIREWALL" => "🛡 Firewall desprotegido",
        _ => "🛡 shell_mon",
    }
}

/// Caminho padrão do log.
fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SHELLMON_LOG") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("shellmon").join("events.log")
}

/// Extrai os conjuntos de listeners e de conexões entrantes da LAN.
fn snapshot(sockets: &[Socket]) -> (HashMap<String, ListenInfo>, HashMap<String, String>) {
    let listen_ports: HashSet<(&str, &str)> = sockets
        .iter()
        .filter(|s| s.state == "LISTEN")
        .map(|s| (s.netid.as_str(), s.local_port.as_str()))
        .collect();

    let mut listeners = HashMap::new();
    let mut inbound = HashMap::new();

    for s in sockets {
        if s.state == "LISTEN" {
            let z = zone(&s.local_addr);
            let exposed = matches!(z, Zone::Any | Zone::Lan | Zone::Public);
            let scope = match z {
                Zone::Any => "todas as interfaces",
                _ => z.label(),
            };
            listeners.insert(
                s.key(),
                ListenInfo {
                    exposed,
                    desc: format!("{} {} ({}) [{}]", s.netid, s.local(), proc_label(s), scope),
                },
            );
        }
        if s.state == "ESTAB"
            && zone(&s.peer_addr) == Zone::Lan
            && listen_ports.contains(&(s.netid.as_str(), s.local_port.as_str()))
        {
            inbound.insert(
                s.key(),
                format!("{} → {} ({})", s.peer(), s.local(), proc_label(s)),
            );
        }
    }
    (listeners, inbound)
}

/// Rótulo do processo, com aviso se a conexão vem de um navegador.
fn proc_label(s: &Socket) -> String {
    let name = if s.process.is_empty() { "?" } else { &s.process };
    let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
    if s.pid.and_then(browser_ancestor).is_some() {
        format!("{name}, pid {pid} ⚠via-navegador")
    } else {
        format!("{name}, pid {pid}")
    }
}

/// Data/hora local formatada como `YYYY-MM-DD HH:MM:SS`, via libc `localtime_r`.
fn now_local() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // SAFETY: localtime_r escreve numa `Tm` válida que fornecemos; `secs` é um
    // ponteiro para um i64 vivo no stack.
    let mut tm = Tm::default();
    unsafe {
        localtime_r(&secs, &mut tm);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

#[repr(C)]
struct Tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const i8,
}

impl Default for Tm {
    fn default() -> Self {
        Tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: std::ptr::null(),
        }
    }
}

extern "C" {
    fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(state: &str, netid: &str, la: &str, lp: &str, pa: &str, pp: &str) -> Socket {
        Socket {
            netid: netid.into(),
            state: state.into(),
            recv_q: 0,
            send_q: 0,
            local_addr: la.into(),
            local_port: lp.into(),
            peer_addr: pa.into(),
            peer_port: pp.into(),
            process: String::new(),
            pid: None,
        }
    }

    #[test]
    fn listener_exposto_vs_loopback() {
        let socks = vec![
            sock("LISTEN", "tcp", "0.0.0.0", "4444", "0.0.0.0", "*"),
            sock("LISTEN", "tcp", "127.0.0.1", "11434", "0.0.0.0", "*"),
        ];
        let (listeners, _) = snapshot(&socks);
        assert_eq!(listeners.len(), 2);
        let exposed = listeners.values().filter(|l| l.exposed).count();
        assert_eq!(exposed, 1); // só o 0.0.0.0:4444
    }

    #[test]
    fn detecta_entrada_da_lan() {
        let socks = vec![
            sock("LISTEN", "tcp", "0.0.0.0", "22", "0.0.0.0", "*"),
            sock("ESTAB", "tcp", "192.168.0.10", "22", "192.168.0.5", "51234"),
            // conexão de saída para a internet não conta como entrada
            sock("ESTAB", "tcp", "192.168.0.10", "55000", "8.8.8.8", "443"),
        ];
        let (_, inbound) = snapshot(&socks);
        assert_eq!(inbound.len(), 1);
    }
}

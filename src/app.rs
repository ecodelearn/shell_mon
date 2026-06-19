//! Estado da aplicação: filtros, ordenação, seleção e refresh.

use crate::socket::{collect, Socket, Summary};
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    All,
    Tcp,
    Udp,
}

impl Proto {
    pub fn label(&self) -> &'static str {
        match self {
            Proto::All => "all",
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
    pub fn next(self) -> Proto {
        match self {
            Proto::All => Proto::Tcp,
            Proto::Tcp => Proto::Udp,
            Proto::Udp => Proto::All,
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
    pub new_keys: HashSet<String>,
    pub should_quit: bool,
    pub status: String,
}

impl App {
    pub fn new(interval: Duration, is_root: bool) -> Self {
        let mut app = App {
            sockets: Vec::new(),
            summary: Summary::default(),
            proto: Proto::All,
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
            new_keys: HashSet::new(),
            should_quit: false,
            status: String::new(),
        };
        app.refresh();
        app
    }

    pub fn refresh(&mut self) {
        match collect() {
            Ok(sockets) => {
                let current: HashSet<String> = sockets.iter().map(|s| s.key()).collect();
                // Conexões que não existiam no refresh anterior.
                self.new_keys = if self.seen_keys.is_empty() {
                    HashSet::new()
                } else {
                    current.difference(&self.seen_keys).cloned().collect()
                };
                self.seen_keys = current;
                self.summary = Summary::from(&sockets);
                self.sockets = sockets;
                self.last_error = None;
            }
            Err(e) => self.last_error = Some(e),
        }
        self.last_refresh = Instant::now();
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
            .filter(|s| match self.proto {
                Proto::All => true,
                Proto::Tcp => s.netid == "tcp",
                Proto::Udp => s.netid == "udp",
            })
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

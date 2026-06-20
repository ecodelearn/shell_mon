//! Notificações de desktop via `notify-send` para eventos de alta severidade.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

/// Janela de deduplicação: não repete a mesma notificação dentro desse tempo.
const DEDUP: Duration = Duration::from_secs(30);

pub struct Notifier {
    enabled: bool,
    recent: HashMap<String, Instant>,
}

impl Notifier {
    /// `requested` vem da flag do usuário; só fica ativo se `notify-send` existir.
    pub fn new(requested: bool) -> Self {
        Notifier {
            enabled: requested && available(),
            recent: HashMap::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Dispara uma notificação crítica (não bloqueia o monitor; reaproveita uma
    /// thread para aguardar/reapear o processo). Deduplica por corpo.
    pub fn notify(&mut self, title: &str, body: &str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        if let Some(t) = self.recent.get(body) {
            if now.duration_since(*t) < DEDUP {
                return;
            }
        }
        self.recent.retain(|_, t| now.duration_since(*t) < DEDUP);
        self.recent.insert(body.to_string(), now);

        let title = title.to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            let _ = Command::new("notify-send")
                .args(["-a", "shell_mon", "-u", "critical", &title, &body])
                .status();
        });
    }
}

/// `notify-send` está utilizável?
///
/// Sem um barramento de sessão D-Bus (ex.: rodando via `sudo`, que limpa o
/// ambiente), o `notify-send` tenta `dbus-launch --autolaunch` e falha com erro
/// no terminal. Por isso só habilitamos se `DBUS_SESSION_BUS_ADDRESS` existir.
fn available() -> bool {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        return false;
    }
    Command::new("notify-send")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

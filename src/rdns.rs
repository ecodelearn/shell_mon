//! DNS reverso (PTR) para humanizar IPs remotos: `140.82.113.25 → github`.
//!
//! Usa `getent hosts` (respeita o resolvedor do sistema). Na TUI roda em
//! background, com cache compartilhado, para nunca bloquear o loop de render.

use std::collections::HashMap;
use std::process::Command;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

/// Domínios de infraestrutura mapeados para a marca real.
fn infra_brand(domain: &str) -> Option<&'static str> {
    Some(match domain {
        "1e100.net" | "gvt1.com" | "gvt2.com" | "googleusercontent.com" | "googlevideo.com" => "google",
        "fbcdn.net" | "fbsbx.com" => "facebook",
        "akamaitechnologies.com" | "akamai.net" => "akamai",
        "amazonaws.com" => "aws",
        "cloudfront.net" => "cloudfront",
        _ => return None,
    })
}

/// PTR de um IP via `getent hosts`.
fn reverse(ip: &str) -> Option<String> {
    let out = Command::new("getent").args(["hosts", ip]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace().nth(1).map(|h| h.to_string())
}

/// Sufixos de segundo nível (ex.: `com.br`, `co.uk`): nesses casos a marca é o
/// rótulo anterior.
const SECOND_LEVEL: &[&str] = &[
    "com", "net", "org", "gov", "edu", "co", "mil", "ac", "gob", "or", "ne", "go",
];

/// Marca amigável a partir do hostname PTR (heurística: domínio registrável).
fn brand_from_host(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').collect();
    let n = labels.len();
    if n < 2 {
        return h;
    }
    // Domínios de infraestrutura conhecidos (sempre 2 níveis).
    let last2 = format!("{}.{}", labels[n - 2], labels[n - 1]);
    if let Some(b) = infra_brand(&last2) {
        return b.to_string();
    }
    // Marca = rótulo antes do TLD, pulando TLDs de 2 níveis (com.br, co.uk…).
    let idx = if n >= 3 && SECOND_LEVEL.contains(&labels[n - 2]) {
        n - 3
    } else {
        n - 2
    };
    labels[idx].to_string()
}

/// Resolve o IP para uma marca, ou `None` se não houver PTR.
pub fn brand_of(ip: &str) -> Option<String> {
    reverse(ip).map(|h| brand_from_host(&h))
}

/// Resolve vários IPs em paralelo (uso one-shot, ex.: `--triage`).
pub fn resolve_all(ips: &[String]) -> HashMap<String, String> {
    let handles: Vec<_> = ips
        .iter()
        .cloned()
        .map(|ip| thread::spawn(move || (ip.clone(), brand_of(&ip))))
        .collect();
    let mut map = HashMap::new();
    for h in handles {
        if let Ok((ip, Some(b))) = h.join() {
            map.insert(ip, b);
        }
    }
    map
}

/// Resolvedor em background para a TUI: aceita pedidos sem bloquear e preenche
/// um cache que a interface consulta.
pub struct Resolver {
    enabled: bool,
    cache: Arc<Mutex<HashMap<String, Option<String>>>>,
    tx: Option<Sender<String>>,
}

impl Resolver {
    pub fn new(enabled: bool) -> Self {
        let cache: Arc<Mutex<HashMap<String, Option<String>>>> = Arc::new(Mutex::new(HashMap::new()));
        if !enabled {
            return Resolver { enabled: false, cache, tx: None };
        }
        let (tx, rx) = mpsc::channel::<String>();
        let rx = Arc::new(Mutex::new(rx));
        // Pequeno pool de workers; o lock é solto antes do lookup, então há
        // paralelismo real entre eles.
        for _ in 0..4 {
            let rx = rx.clone();
            let cache = cache.clone();
            thread::spawn(move || loop {
                let msg = {
                    let guard = rx.lock().unwrap();
                    guard.recv()
                };
                match msg {
                    Ok(ip) => {
                        let brand = brand_of(&ip);
                        cache.lock().unwrap().insert(ip, brand);
                    }
                    Err(_) => break, // canal fechado: encerra
                }
            });
        }
        Resolver { enabled: true, cache, tx: Some(tx) }
    }

    /// Pede a resolução de um IP (não bloqueia; ignora se já pedido/resolvido).
    pub fn request(&self, ip: &str) {
        if !self.enabled {
            return;
        }
        let mut c = self.cache.lock().unwrap();
        if c.contains_key(ip) {
            return;
        }
        c.insert(ip.to_string(), None); // marca como pendente
        drop(c);
        if let Some(tx) = &self.tx {
            let _ = tx.send(ip.to_string());
        }
    }

    /// Marca já resolvida para o IP, se houver.
    pub fn get(&self, ip: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        self.cache.lock().unwrap().get(ip).cloned().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marca_do_host() {
        assert_eq!(brand_from_host("lb-140-82-113-25-iad.github.com"), "github");
        assert_eq!(brand_from_host("gru06s59-in-f14.1e100.net"), "google");
        assert_eq!(brand_from_host("whatsapp-cdn-shv-02-gru1.fbcdn.net"), "facebook");
        assert_eq!(brand_from_host("x.telegram.org"), "telegram");
        assert_eq!(brand_from_host("server.amazonaws.com"), "aws");
        // TLD de 2 níveis: a marca é o rótulo antes de com.br
        assert_eq!(brand_from_host("152-255-36-173.user.vivozap.com.br"), "vivozap");
        assert_eq!(brand_from_host("host.empresa.co.uk"), "empresa");
    }
}

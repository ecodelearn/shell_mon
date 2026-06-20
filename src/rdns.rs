//! DNS reverso (PTR) para humanizar IPs remotos: `140.82.113.25 → github`.
//!
//! Usa `getent hosts` (respeita o resolvedor do sistema). Na TUI roda em
//! background, com cache compartilhado, para nunca bloquear o loop de render.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Por quanto tempo uma marca em cache é considerada válida (PTR muda raramente).
const CACHE_TTL_SECS: u64 = 14 * 24 * 3600;

/// Caminho do cache em disco: `$SHELLMON_RDNS_CACHE`, ou
/// `$XDG_CACHE_HOME/shellmon/rdns.tsv`, ou `$HOME/.cache/shellmon/rdns.tsv`.
fn cache_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SHELLMON_RDNS_CACHE") {
        return Some(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("shellmon").join("rdns.tsv"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parseia uma linha `ip\tmarca\tepoch`, devolvendo `(ip, marca)` se ainda
/// estiver dentro do TTL.
fn parse_cache_line(line: &str, now: u64) -> Option<(String, String)> {
    let mut it = line.split('\t');
    let ip = it.next()?.trim();
    let brand = it.next()?.trim();
    let epoch: u64 = it.next()?.trim().parse().ok()?;
    if ip.is_empty() || brand.is_empty() || now.saturating_sub(epoch) > CACHE_TTL_SECS {
        return None;
    }
    Some((ip.to_string(), brand.to_string()))
}

/// Carrega o cache do disco (entradas válidas dentro do TTL).
fn load_cache(path: &PathBuf) -> HashMap<String, Option<String>> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        let now = now_secs();
        for line in content.lines() {
            if let Some((ip, brand)) = parse_cache_line(line, now) {
                map.insert(ip, Some(brand));
            }
        }
    }
    map
}

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
        // Pré-carrega o cache em disco (resoluções de sessões anteriores).
        let path = cache_path();
        if let Some(p) = &path {
            *cache.lock().unwrap() = load_cache(p);
        }
        // Abre o arquivo de cache em modo append para gravar novas resoluções.
        let file: Option<Arc<Mutex<File>>> = path.as_ref().and_then(|p| {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
                .map(|f| Arc::new(Mutex::new(f)))
        });

        let (tx, rx) = mpsc::channel::<String>();
        let rx = Arc::new(Mutex::new(rx));
        // Pequeno pool de workers; o lock é solto antes do lookup, então há
        // paralelismo real entre eles.
        for _ in 0..4 {
            let rx = rx.clone();
            let cache = cache.clone();
            let file = file.clone();
            thread::spawn(move || loop {
                let msg = {
                    let guard = rx.lock().unwrap();
                    guard.recv()
                };
                match msg {
                    Ok(ip) => {
                        let brand = brand_of(&ip);
                        // Persiste resoluções positivas no cache em disco.
                        if let (Some(b), Some(f)) = (&brand, &file) {
                            let line = format!("{ip}\t{b}\t{}\n", now_secs());
                            if let Ok(mut f) = f.lock() {
                                let _ = f.write_all(line.as_bytes());
                            }
                        }
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

    #[test]
    fn cache_line_valida_e_expira() {
        let now = 2_000_000_000;
        // recente → ok
        let l = format!("140.82.113.25\tgithub\t{}", now - 10);
        assert_eq!(
            parse_cache_line(&l, now),
            Some(("140.82.113.25".into(), "github".into()))
        );
        // expirada → None
        let old = format!("1.2.3.4\tfoo\t{}", now - CACHE_TTL_SECS - 1);
        assert_eq!(parse_cache_line(&old, now), None);
        // malformada → None
        assert_eq!(parse_cache_line("lixo", now), None);
    }
}

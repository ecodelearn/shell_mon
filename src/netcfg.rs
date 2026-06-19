//! Auditoria da configuração de rede: gateway, rotas, DNS e vizinhos da LAN.
//!
//! Foco defensivo: um roteador comprometido entrega config via DHCP (DNS,
//! gateway, rotas). Aqui classificamos os servidores DNS em uso e sinalizamos
//! os que não são resolvedores públicos conhecidos — sinal clássico de
//! sequestro de DNS pela rede local.

use crate::analysis::{zone, Zone};
use std::process::Command;

/// Resolvedores públicos conhecidos (Quad9, Cloudflare, Google, OpenDNS,
/// AdGuard, Tailscale MagicDNS, stub do systemd-resolved).
const KNOWN_DNS: &[&str] = &[
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "8.8.8.8", "8.8.4.4",
    "208.67.222.222", "208.67.220.220",
    "94.140.14.14", "94.140.15.15",
    "100.100.100.100", "127.0.0.53",
    "2620:fe::fe", "2620:fe::9",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "fd7a:115c:a1e0::53",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass {
    /// Resolvedor público conhecido e confiável.
    Known,
    /// Endereço local/LAN — normalmente o próprio roteador fazendo DNS.
    Local,
    /// IP público que não reconhecemos — suspeito.
    UnknownPublic,
}

/// Classifica um endereço de servidor DNS.
pub fn classify_dns(ip: &str) -> DnsClass {
    if KNOWN_DNS.contains(&ip) {
        return DnsClass::Known;
    }
    match zone(ip) {
        Zone::Public => DnsClass::UnknownPublic,
        _ => DnsClass::Local,
    }
}

pub struct NetAudit {
    pub gateways: Vec<String>,
    pub dns: Vec<(String, DnsClass)>,
    pub neighbors: Vec<(String, String, String)>, // ip, mac, estado
}

impl NetAudit {
    pub fn collect() -> Self {
        NetAudit {
            gateways: gateways(),
            dns: dns_servers(),
            neighbors: neighbors(),
        }
    }

    /// Avisos acionáveis (DNS público não reconhecido).
    pub fn warnings(&self) -> Vec<String> {
        self.dns
            .iter()
            .filter(|(_, c)| *c == DnsClass::UnknownPublic)
            .map(|(ip, _)| {
                format!("DNS não reconhecido {ip} em uso — possivelmente entregue pelo roteador via DHCP; verifique o roteador")
            })
            .collect()
    }

    pub fn print(&self) {
        println!("\n🧭 GATEWAY / ROTAS");
        if self.gateways.is_empty() {
            println!("   — não foi possível ler (comando `ip` indisponível?)");
        }
        for g in &self.gateways {
            println!("   • rota padrão via {g}");
        }

        println!("\n🧩 SERVIDORES DNS EM USO");
        if self.dns.is_empty() {
            println!("   — não foi possível determinar");
        }
        for (ip, class) in &self.dns {
            let verdict = match class {
                DnsClass::Known => "ok (resolvedor conhecido)",
                DnsClass::Local => "local (o roteador faz DNS)",
                DnsClass::UnknownPublic => "⚠ NÃO RECONHECIDO — investigue",
            };
            println!("   • {ip:24} {verdict}");
        }

        println!("\n🖧 DISPOSITIVOS NA REDE LOCAL  ({})", self.neighbors.len());
        for (ip, mac, state) in &self.neighbors {
            println!("   • {ip:18} {mac:18} {state}");
        }

        let warns = self.warnings();
        if !warns.is_empty() {
            println!("\n⛔ ATENÇÃO:");
            for w in &warns {
                println!("   • {w}");
            }
        }
    }
}

/// Estado do firewall de host.
pub struct Firewall {
    pub backend: String,
    pub active: bool,
    pub default_zone: Option<String>,
    /// Política/target de entrada da zona padrão (DROP/REJECT/default/ACCEPT).
    pub incoming: Option<String>,
}

/// Um target de firewalld que efetivamente bloqueia entrada não solicitada.
fn target_denies(t: &str) -> bool {
    matches!(
        t.to_ascii_uppercase().as_str(),
        "DROP" | "REJECT" | "%%REJECT%%" | "DEFAULT"
    )
}

impl Firewall {
    pub fn detect() -> Firewall {
        // firewalld
        let running = cmd("firewall-cmd", &["--state"])
            .map(|s| s.trim() == "running")
            .unwrap_or(false);
        if running {
            let zone = cmd("firewall-cmd", &["--get-default-zone"]).map(|s| s.trim().to_string());
            let incoming = zone.as_deref().and_then(zone_target);
            return Firewall {
                backend: "firewalld".into(),
                active: true,
                default_zone: zone,
                incoming,
            };
        }
        // outros backends (sem inspeção profunda de regras, que exigiria root)
        for svc in ["ufw", "nftables", "iptables"] {
            if cmd("systemctl", &["is-active", svc]).map(|s| s.trim() == "active").unwrap_or(false) {
                return Firewall {
                    backend: svc.into(),
                    active: true,
                    default_zone: None,
                    incoming: None,
                };
            }
        }
        let backend = if installed("firewall-cmd") {
            "firewalld (parado)"
        } else if installed("ufw") {
            "ufw (parado)"
        } else {
            "nenhum"
        };
        Firewall {
            backend: backend.into(),
            active: false,
            default_zone: None,
            incoming: None,
        }
    }

    /// `Some(true)` se a entrada é negada por padrão; `Some(false)` se aceita;
    /// `None` se não foi possível determinar.
    pub fn deny_incoming(&self) -> Option<bool> {
        self.incoming.as_deref().map(target_denies)
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if !self.active {
            w.push("Firewall inativo — entrada da rede não está sendo filtrada".to_string());
        } else if self.deny_incoming() == Some(false) {
            let z = self.default_zone.as_deref().unwrap_or("padrão");
            w.push(format!(
                "Firewall: zona '{z}' aceita entrada (ACCEPT) — máquina exposta na rede"
            ));
        }
        w
    }

    pub fn print(&self) {
        println!("\n🧱 FIREWALL");
        println!(
            "   backend: {} ({})",
            self.backend,
            if self.active { "ativo" } else { "INATIVO" }
        );
        if let Some(z) = &self.default_zone {
            println!("   zona padrão: {z}");
        }
        match (&self.incoming, self.deny_incoming()) {
            (Some(t), Some(true)) => println!("   entrada: {t}  → bloqueada por padrão ✅"),
            (Some(t), Some(false)) => println!("   entrada: {t}  → ⚠ ACEITA (exposto)"),
            _ if self.active => println!("   entrada: política não inspecionada (precisa de root?)"),
            _ => {}
        }
        for w in self.warnings() {
            println!("   ⛔ {w}");
        }
    }
}

/// Target da zona via `firewall-cmd --zone=<z> --list-all`.
fn zone_target(zone: &str) -> Option<String> {
    let out = cmd("firewall-cmd", &["--zone", zone, "--list-all"])?;
    out.lines().find_map(|l| {
        l.trim()
            .strip_prefix("target:")
            .map(|r| r.trim().to_string())
    })
}

/// O binário existe no PATH? (checa via `--version`, aceitando qualquer saída).
fn installed(prog: &str) -> bool {
    std::process::Command::new(prog)
        .arg("--version")
        .output()
        .is_ok()
}

fn cmd(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Gateways padrão de `ip -4 route` (linhas `default via X dev Y`).
fn gateways() -> Vec<String> {
    let mut v = Vec::new();
    if let Some(out) = cmd("ip", &["-4", "route"]) {
        for line in out.lines() {
            if line.split_whitespace().next() == Some("default") {
                // default via <gw> dev <iface> ...
                let mut gw = String::new();
                let mut dev = String::new();
                let mut toks = line.split_whitespace();
                while let Some(t) = toks.next() {
                    match t {
                        "via" => gw = toks.next().unwrap_or("").to_string(),
                        "dev" => dev = toks.next().unwrap_or("").to_string(),
                        _ => {}
                    }
                }
                if !gw.is_empty() {
                    v.push(if dev.is_empty() { gw } else { format!("{gw} (dev {dev})") });
                }
            }
        }
    }
    v
}

/// Servidores DNS efetivos, classificados. Tenta `resolvectl`, depois
/// `/etc/resolv.conf`.
fn dns_servers() -> Vec<(String, DnsClass)> {
    let mut ips: Vec<String> = Vec::new();

    if let Some(out) = cmd("resolvectl", &["status"]) {
        for line in out.lines() {
            let l = line.trim();
            if l.starts_with("DNS Servers:") || l.starts_with("Current DNS Server:") {
                if let Some(rest) = l.split_once(':').map(|x| x.1) {
                    for tok in rest.split_whitespace() {
                        // remove nome após '#': 9.9.9.9#dns.quad9.net
                        let ip = tok.split('#').next().unwrap_or(tok);
                        if looks_like_ip(ip) {
                            ips.push(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    if ips.is_empty() {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                if let Some(rest) = line.trim().strip_prefix("nameserver") {
                    let ip = rest.trim();
                    if looks_like_ip(ip) {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    }

    // dedup preservando ordem
    let mut seen = std::collections::HashSet::new();
    ips.into_iter()
        .filter(|ip| seen.insert(ip.clone()))
        .map(|ip| {
            let c = classify_dns(&ip);
            (ip, c)
        })
        .collect()
}

fn looks_like_ip(s: &str) -> bool {
    !s.is_empty() && (s.contains('.') || s.contains(':')) && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
}

/// Vizinhos da LAN de `ip neigh` (ignora entradas sem endereço resolvido).
fn neighbors() -> Vec<(String, String, String)> {
    let mut v = Vec::new();
    if let Some(out) = cmd("ip", &["neigh"]) {
        for line in out.lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() < 2 {
                continue;
            }
            let ip = toks[0].to_string();
            let state = toks.last().unwrap_or(&"").to_string();
            if state == "FAILED" || state == "INCOMPLETE" {
                continue;
            }
            let mac = toks
                .iter()
                .position(|t| *t == "lladdr")
                .and_then(|i| toks.get(i + 1))
                .unwrap_or(&"?")
                .to_string();
            v.push((ip, mac, state));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifica_dns() {
        assert_eq!(classify_dns("9.9.9.9"), DnsClass::Known);
        assert_eq!(classify_dns("1.1.1.1"), DnsClass::Known);
        assert_eq!(classify_dns("192.168.15.1"), DnsClass::Local);
        assert_eq!(classify_dns("1.1.4.4"), DnsClass::UnknownPublic); // o achado real
        assert_eq!(classify_dns("8.8.8.8"), DnsClass::Known);
        assert_eq!(classify_dns("45.90.28.0"), DnsClass::UnknownPublic);
    }

    #[test]
    fn ip_parsing() {
        assert!(looks_like_ip("1.1.4.4"));
        assert!(looks_like_ip("2606:4700:4700::1111"));
        assert!(!looks_like_ip("dns.quad9.net"));
        assert!(!looks_like_ip(""));
    }

    #[test]
    fn firewall_target_bloqueia() {
        assert!(target_denies("DROP"));
        assert!(target_denies("REJECT"));
        assert!(target_denies("default")); // firewalld rejeita não-solicitado
        assert!(!target_denies("ACCEPT"));
    }
}

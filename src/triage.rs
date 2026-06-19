//! Triagem defensiva: relatório humanizado do estado atual dos sockets.
//!
//! Roda melhor com privilégios (`sudo shellmon --triage` ou via a elevação
//! instalada), para atribuir processo/PID aos serviços de sistema.

use crate::analysis::{ancestry, browser_ancestor, is_root, zone, Zone};
use crate::socket::{collect, Socket};
use std::collections::HashSet;
use std::io;

pub fn run() -> io::Result<()> {
    let sockets = match collect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("erro: {e}");
            std::process::exit(1);
        }
    };

    let listen_ports: HashSet<(&str, &str)> = sockets
        .iter()
        .filter(|s| s.state == "LISTEN" && s.is_network())
        .map(|s| (s.netid.as_str(), s.local_port.as_str()))
        .collect();

    let mut exposed: Vec<&Socket> = Vec::new();
    let mut inbound_lan: Vec<&Socket> = Vec::new();
    let mut out_public: Vec<&Socket> = Vec::new();
    let mut out_lan: Vec<&Socket> = Vec::new();

    for s in sockets.iter().filter(|s| s.is_network()) {
        if s.state == "LISTEN" && matches!(zone(&s.local_addr), Zone::Any | Zone::Lan | Zone::Public) {
            exposed.push(s);
        }
        if s.state == "ESTAB" {
            let pz = zone(&s.peer_addr);
            let is_inbound = listen_ports.contains(&(s.netid.as_str(), s.local_port.as_str()));
            match pz {
                Zone::Lan if is_inbound => inbound_lan.push(s),
                Zone::Public => out_public.push(s),
                Zone::Lan => out_lan.push(s),
                _ => {}
            }
        }
    }

    let bar = "=".repeat(78);
    println!("{bar}");
    println!(" TRIAGEM shell_mon — visão defensiva (read-only)");
    println!("{bar}");
    if !is_root() {
        println!("  ⚠ sem root: processos de serviços de sistema podem não aparecer.");
        println!("    Para o relatório completo: sudo shellmon --triage");
    }

    println!("\n🔊 SERVIÇOS ESCUTANDO EXPOSTOS À REDE  ({})", exposed.len());
    println!("   (qualquer um na sua LAN pode tentar se conectar nestes)");
    if exposed.is_empty() {
        println!("   — nenhum (só loopback). Bom sinal.");
    }
    for s in &exposed {
        let scope = match zone(&s.local_addr) {
            Zone::Any => "TODAS as interfaces".to_string(),
            z => z.label().to_string(),
        };
        println!("   • {:3} {:30} {:32} [{}]", s.netid, s.local(), label(s), scope);
    }

    println!("\n🏠 CONEXÕES ENTRANDO DA REDE LOCAL  ({})", inbound_lan.len());
    println!("   (alguém na sua LAN conectado a um serviço SEU — atenção ao roteador)");
    if inbound_lan.is_empty() {
        println!("   — nenhuma agora.");
    }
    for s in &inbound_lan {
        println!("   • {:24} → {:24}  {}", s.peer(), s.local(), label(s));
    }

    // DNS reverso (paralelo) para humanizar os IPs públicos.
    let public_ips: Vec<String> = {
        let mut v: Vec<String> = out_public.iter().map(|s| s.peer_addr.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let brands = crate::rdns::resolve_all(&public_ips);

    println!("\n🌐 CONEXÕES ATIVAS COM A INTERNET  ({})", out_public.len());
    for s in &out_public {
        let peer = match brands.get(&s.peer_addr) {
            Some(b) => format!("{} ({})", s.peer(), b),
            None => s.peer(),
        };
        println!("   • {:22} → {:32}  {}", s.local(), peer, label(s));
    }

    println!("\n🔗 CONEXÕES COM A REDE LOCAL (saída)  ({})", out_lan.len());
    for s in &out_lan {
        println!("   • {:22} → {:24}  {}", s.local(), s.peer(), label(s));
    }

    // Auditoria de configuração de rede (gateway/DNS/vizinhos) e firewall.
    crate::netcfg::NetAudit::collect().print();
    crate::netcfg::Firewall::detect().print();

    let via_nav = out_public
        .iter()
        .filter(|s| s.pid.and_then(browser_ancestor).is_some())
        .count();
    println!("\n{bar}");
    println!(
        " RESUMO: {} expostos · {} entradas da LAN · {} p/ internet ({} via navegador)",
        exposed.len(),
        inbound_lan.len(),
        out_public.len(),
        via_nav
    );
    println!("{bar}");
    Ok(())
}

/// Rótulo do processo de um socket, com aviso quando vem de navegador.
fn label(s: &Socket) -> String {
    let name = if s.process.is_empty() { "?" } else { &s.process };
    let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
    match s.pid.and_then(browser_ancestor) {
        Some(_) => {
            let chain: Vec<String> = s
                .pid
                .map(ancestry)
                .unwrap_or_default()
                .into_iter()
                .take(4)
                .collect();
            format!("{name}(pid {pid})  ⚠ via NAVEGADOR ({})", chain.join(" ← "))
        }
        None => format!("{name}(pid {pid})"),
    }
}

//! Coleta e parsing da saída do comando `ss`.

use crate::analysis::{zone, Zone};
use std::collections::HashSet;
use std::process::Command;

/// Um socket individual, já normalizado a partir da saída do `ss`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socket {
    pub netid: String, // tcp, udp, ...
    pub state: String, // ESTAB, LISTEN, UNCONN, TIME-WAIT, ...
    pub recv_q: u64,
    pub send_q: u64,
    pub local_addr: String,
    pub local_port: String,
    pub peer_addr: String,
    pub peer_port: String,
    /// Nome do processo dono (vazio se desconhecido / sem permissão).
    pub process: String,
    pub pid: Option<u32>,
}

impl Socket {
    /// Chave estável para detectar conexões novas/fechadas entre refreshes.
    pub fn key(&self) -> String {
        format!(
            "{}|{}:{}|{}:{}",
            self.netid, self.local_addr, self.local_port, self.peer_addr, self.peer_port
        )
    }

    pub fn local(&self) -> String {
        format!("{}:{}", self.local_addr, self.local_port)
    }

    pub fn peer(&self) -> String {
        format!("{}:{}", self.peer_addr, self.peer_port)
    }
}

/// Resumo agregado (estilo `ss -s`), calculado localmente.
#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub total: usize,
    pub tcp: usize,
    pub udp: usize,
    pub estab: usize,
    pub listen: usize,
    pub time_wait: usize,
    /// Serviços em LISTEN acessíveis pela rede (não-loopback).
    pub exposed: usize,
    /// Conexões estabelecidas ENTRANDO da rede local (peer LAN num serviço nosso).
    pub inbound_lan: usize,
}

impl Summary {
    pub fn from(sockets: &[Socket]) -> Self {
        let mut s = Summary {
            total: sockets.len(),
            ..Default::default()
        };
        // Portas em que temos serviços escutando (para detectar conexões entrantes).
        let listen_ports: HashSet<(&str, &str)> = sockets
            .iter()
            .filter(|sk| sk.state == "LISTEN")
            .map(|sk| (sk.netid.as_str(), sk.local_port.as_str()))
            .collect();

        for sock in sockets {
            match sock.netid.as_str() {
                "tcp" => s.tcp += 1,
                "udp" => s.udp += 1,
                _ => {}
            }
            match sock.state.as_str() {
                "ESTAB" => s.estab += 1,
                "LISTEN" => s.listen += 1,
                "TIME-WAIT" => s.time_wait += 1,
                _ => {}
            }
            if sock.state == "LISTEN"
                && matches!(zone(&sock.local_addr), Zone::Any | Zone::Lan | Zone::Public)
            {
                s.exposed += 1;
            }
            if sock.state == "ESTAB"
                && zone(&sock.peer_addr) == Zone::Lan
                && listen_ports.contains(&(sock.netid.as_str(), sock.local_port.as_str()))
            {
                s.inbound_lan += 1;
            }
        }
        s
    }
}

/// Executa `ss` e devolve a lista de sockets parseada.
///
/// Flags: `-t -u` (TCP+UDP), `-a` (todos os estados), `-n` (numérico,
/// portas como número), `-p` (processo) e `-H` (sem cabeçalho).
pub fn collect() -> Result<Vec<Socket>, String> {
    let output = Command::new("ss")
        .args(["-tuanpH"])
        .output()
        .map_err(|e| format!("falha ao executar `ss`: {e}"))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("`ss` retornou erro: {}", err.trim()));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.lines().filter_map(parse_line).collect())
}

/// Parseia uma linha do `ss -tuanpH`.
///
/// Layout: `Netid State Recv-Q Send-Q Local:Port Peer:Port [Process...]`
fn parse_line(line: &str) -> Option<Socket> {
    let mut fields = line.split_whitespace();
    let netid = fields.next()?.to_string();
    let state = fields.next()?.to_string();
    let recv_q = fields.next()?.parse().unwrap_or(0);
    let send_q = fields.next()?.parse().unwrap_or(0);
    let local = fields.next()?;
    let peer = fields.next()?;
    // O resto (pode conter espaços) é a descrição do processo.
    let process_raw: String = fields.collect::<Vec<_>>().join(" ");

    let (local_addr, local_port) = split_addr_port(local);
    let (peer_addr, peer_port) = split_addr_port(peer);
    let (process, pid) = parse_process(&process_raw);

    Some(Socket {
        netid,
        state,
        recv_q,
        send_q,
        local_addr,
        local_port,
        peer_addr,
        peer_port,
        process,
        pid,
    })
}

/// Separa "endereço:porta" pelo último `:`, lidando com IPv6 (`[::1]:80`,
/// `::1:80`) e interfaces (`192.168.0.1%enp2s0`).
fn split_addr_port(s: &str) -> (String, String) {
    match s.rfind(':') {
        Some(idx) => {
            let addr = s[..idx].trim_matches(['[', ']']).to_string();
            let port = s[idx + 1..].to_string();
            (addr, port)
        }
        None => (s.to_string(), String::new()),
    }
}

/// Extrai nome e PID do campo `users:(("nome",pid=123,fd=5),...)`.
fn parse_process(raw: &str) -> (String, Option<u32>) {
    if raw.is_empty() {
        return (String::new(), None);
    }
    let name = raw
        .find("((\"")
        .map(|i| &raw[i + 3..])
        .and_then(|rest| rest.find('"').map(|j| rest[..j].to_string()))
        .unwrap_or_default();

    let pid = raw
        .find("pid=")
        .map(|i| &raw[i + 4..])
        .and_then(|rest| {
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse().ok()
        });

    (name, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp_sem_processo() {
        let s = parse_line("udp UNCONN 0 0 0.0.0.0:48958 0.0.0.0:*").unwrap();
        assert_eq!(s.netid, "udp");
        assert_eq!(s.local_port, "48958");
        assert_eq!(s.peer_addr, "0.0.0.0");
        assert!(s.process.is_empty());
        assert_eq!(s.pid, None);
    }

    #[test]
    fn parse_tcp_com_processo() {
        let line = r#"tcp ESTAB 0 0 192.168.0.10:22 192.168.0.5:51234 users:(("sshd",pid=3772,fd=5))"#;
        let s = parse_line(line).unwrap();
        assert_eq!(s.state, "ESTAB");
        assert_eq!(s.process, "sshd");
        assert_eq!(s.pid, Some(3772));
    }

    #[test]
    fn parse_ipv6() {
        let s = parse_line("tcp LISTEN 0 128 [::1]:631 [::]:*").unwrap();
        assert_eq!(s.local_addr, "::1");
        assert_eq!(s.local_port, "631");
        assert_eq!(s.peer_addr, "::");
    }

    #[test]
    fn parse_interface_no_addr() {
        let s = parse_line("udp ESTAB 0 0 192.168.15.126%enp2s0:68 192.168.15.1:67").unwrap();
        assert_eq!(s.local_addr, "192.168.15.126%enp2s0");
        assert_eq!(s.local_port, "68");
    }
}

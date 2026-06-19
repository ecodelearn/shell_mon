//! Análise defensiva: zonas de confiança de endereços e linhagem de processos.

/// Detecta root via euid efetivo (sem dependências externas).
pub fn is_root() -> bool {
    // SAFETY: geteuid() é sempre seguro e não tem efeitos colaterais.
    unsafe { geteuid() == 0 }
}

extern "C" {
    fn geteuid() -> u32;
}

/// Pistas (substring, minúsculo) para identificar navegadores na árvore de
/// processos. Cobre os processos-filho do Firefox (que descendem do principal).
pub const BROWSER_HINTS: [&str; 4] = ["firefox", "chrome", "chromium", "brave"];

/// Zona de confiança de um endereço IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    /// `*`, `0.0.0.0` ou `::` — curinga (escuta em todas as interfaces).
    Any,
    /// `127.0.0.0/8`, `::1` — só a própria máquina.
    Loopback,
    /// `169.254/16`, `fe80::/10` — link-local.
    LinkLocal,
    /// Redes privadas: `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT/
    /// Tailscale), `fc00::/7` (ULA).
    Lan,
    /// Qualquer outro — internet pública.
    Public,
}

impl Zone {
    pub fn label(self) -> &'static str {
        match self {
            Zone::Any => "todas",
            Zone::Loopback => "local",
            Zone::LinkLocal => "link-local",
            Zone::Lan => "rede local",
            Zone::Public => "internet",
        }
    }
}

/// Classifica um endereço (sem porta) numa zona de confiança.
pub fn zone(addr: &str) -> Zone {
    // Remove sufixo de interface (ex.: `192.168.0.1%enp2s0`).
    let ip = addr.split('%').next().unwrap_or(addr);

    if ip.is_empty() || ip == "*" || ip == "0.0.0.0" || ip == "::" {
        return Zone::Any;
    }
    if ip == "::1" || ip.starts_with("127.") {
        return Zone::Loopback;
    }
    if ip.starts_with("169.254.") {
        return Zone::LinkLocal;
    }

    let low = ip.to_ascii_lowercase();
    if ip.contains(':') {
        // IPv6
        if low.starts_with("fe80") {
            return Zone::LinkLocal;
        }
        if low.starts_with("fc") || low.starts_with("fd") {
            return Zone::Lan; // ULA
        }
        return Zone::Public;
    }

    // IPv4
    let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() == 4 {
        let (a, b) = (octets[0], octets[1]);
        if a == 10
            || (a == 192 && b == 168)
            || (a == 172 && (16..=31).contains(&b))
            || (a == 100 && (64..=127).contains(&b))
        {
            return Zone::Lan;
        }
        return Zone::Public;
    }

    Zone::Public
}

/// Lê `comm` (nome) e `ppid` de `/proc/<pid>/stat`. `comm` pode conter espaços
/// e parênteses, por isso usamos o último `)` como delimitador.
fn proc_stat(pid: u32) -> Option<(String, u32)> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rp = data.rfind(')')?;
    let comm = data.get(data.find('(')? + 1..rp)?.to_string();
    // Após o `)`: " state ppid ...".
    let mut after = data[rp + 1..].split_whitespace();
    let _state = after.next()?;
    let ppid: u32 = after.next()?.parse().ok()?;
    Some((comm, ppid))
}

/// Cadeia de nomes de processo do PID até a raiz (`init`), incluindo ele mesmo.
pub fn ancestry(pid: u32) -> Vec<String> {
    let mut chain = Vec::new();
    let mut cur = pid;
    // Limite de profundidade como rede de segurança contra ciclos.
    for _ in 0..64 {
        let Some((comm, ppid)) = proc_stat(cur) else {
            break;
        };
        chain.push(comm);
        if cur == 1 || ppid == 0 || ppid == cur {
            break;
        }
        cur = ppid;
    }
    chain
}

/// Se o PID (ou algum ancestral) for um navegador, devolve o nome encontrado.
pub fn browser_ancestor(pid: u32) -> Option<String> {
    ancestry(pid).into_iter().find(|comm| {
        let low = comm.to_ascii_lowercase();
        BROWSER_HINTS.iter().any(|h| low.contains(h))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zonas_basicas() {
        assert_eq!(zone("127.0.0.1"), Zone::Loopback);
        assert_eq!(zone("::1"), Zone::Loopback);
        assert_eq!(zone("0.0.0.0"), Zone::Any);
        assert_eq!(zone("*"), Zone::Any);
        assert_eq!(zone("192.168.15.126"), Zone::Lan);
        assert_eq!(zone("10.0.0.5"), Zone::Lan);
        assert_eq!(zone("172.16.0.1"), Zone::Lan);
        assert_eq!(zone("172.32.0.1"), Zone::Public);
        assert_eq!(zone("100.124.145.122"), Zone::Lan); // tailscale/CGNAT
        assert_eq!(zone("8.8.8.8"), Zone::Public);
        assert_eq!(zone("142.250.79.206"), Zone::Public);
    }

    #[test]
    fn zonas_com_interface() {
        assert_eq!(zone("192.168.15.126%enp2s0"), Zone::Lan);
        assert_eq!(zone("fe80::1%wlan0"), Zone::LinkLocal);
    }

    #[test]
    fn zonas_ipv6() {
        assert_eq!(zone("fd7a:115c:a1e0::1"), Zone::Lan);
        assert_eq!(zone("2606:4700:4700::1111"), Zone::Public);
    }
}

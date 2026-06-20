//! Informações de processo via `/proc/<pid>`: linha de comando, I/O de disco,
//! CPU e memória. Lê tudo do dono do socket — completo quando rodando com root.

/// Bytes acumulados de leitura/escrita em disco (de `/proc/<pid>/io`).
#[derive(Debug, Clone, Copy)]
pub struct Io {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// Lê `read_bytes`/`write_bytes` de `/proc/<pid>/io` (precisa ser dono ou root).
pub fn io(pid: u32) -> Option<Io> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    let mut read_bytes = None;
    let mut write_bytes = None;
    for line in data.lines() {
        if let Some(v) = line.strip_prefix("read_bytes:") {
            read_bytes = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("write_bytes:") {
            write_bytes = v.trim().parse().ok();
        }
    }
    Some(Io {
        read_bytes: read_bytes?,
        write_bytes: write_bytes?,
    })
}

/// Linha de comando completa (`/proc/<pid>/cmdline`, args separados por NUL).
/// Cai para o `comm` entre colchetes se for thread de kernel (cmdline vazia).
pub fn cmdline(pid: u32) -> String {
    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        if !raw.is_empty() {
            let s: String = raw
                .split(|b| *b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p))
                .collect::<Vec<_>>()
                .join(" ");
            if !s.trim().is_empty() {
                return s;
            }
        }
    }
    match comm(pid) {
        Some(c) => format!("[{c}]"),
        None => "?".to_string(),
    }
}

/// Nome curto do processo (`/proc/<pid>/comm`).
pub fn comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Memória residente (RSS) em kB, de `/proc/<pid>/status`.
pub fn rss_kb(pid: u32) -> Option<u64> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in data.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            return v.trim().trim_end_matches("kB").trim().parse().ok();
        }
    }
    None
}

/// Ticks de CPU do processo (utime+stime) de `/proc/<pid>/stat`.
pub fn cpu_ticks(pid: u32) -> Option<u64> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &data[data.rfind(')')? + 1..];
    let toks: Vec<&str> = after.split_whitespace().collect();
    // Após o `)`: índice 0 = state(campo 3); utime = campo 14 → índice 11,
    // stime = campo 15 → índice 12.
    let utime: u64 = toks.get(11)?.parse().ok()?;
    let stime: u64 = toks.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// Total de jiffies de CPU do sistema (1ª linha de `/proc/stat`), para
/// calcular percentual de uso de um processo.
pub fn total_jiffies() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/stat").ok()?;
    let line = data.lines().next()?;
    let rest = line.strip_prefix("cpu")?;
    Some(rest.split_whitespace().filter_map(|t| t.parse::<u64>().ok()).sum())
}

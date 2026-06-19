//! shell_mon — monitor de sockets em tempo real (TUI) sobre o comando `ss`.

mod analysis;
mod app;
mod events;
mod netcfg;
mod notify;
mod rdns;
mod socket;
mod triage;
mod ui;

use app::{App, Proto};
use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::widgets::TableState;
use std::io::{self, stdout};
use std::time::Duration;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    // Triagem defensiva: relatório humanizado e sai.
    if args.iter().any(|a| a == "--triage") {
        return triage::run();
    }

    // Modo "lista simples": imprime e sai (scriptável).
    let one_shot = args.iter().any(|a| a == "-l" || a == "--list");

    // Intervalo de refresh em segundos (padrão 0.2s = 5x/s, sensação de tempo real).
    let interval_secs = parse_interval(&args).unwrap_or(0.2).max(0.05);
    let interval = Duration::from_secs_f64(interval_secs);

    let is_root = analysis::is_root();

    if one_shot {
        return run_oneshot(is_root);
    }

    let log_enabled = !args.iter().any(|a| a == "--no-log");
    let notify_enabled = !args.iter().any(|a| a == "--no-notify");
    let rdns_enabled = !args.iter().any(|a| a == "--no-rdns");
    run_tui(interval, is_root, log_enabled, notify_enabled, rdns_enabled)
}

fn run_oneshot(is_root: bool) -> io::Result<()> {
    let sockets = match socket::collect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("erro: {e}");
            std::process::exit(1);
        }
    };
    let summary = socket::Summary::from(&sockets);
    println!(
        "total {}  tcp {}  udp {}  estab {}  listen {}  time-wait {}",
        summary.total, summary.tcp, summary.udp, summary.estab, summary.listen, summary.time_wait
    );
    if !is_root {
        eprintln!("(dica: rode com sudo para ver o processo de sockets de outros usuários)");
    }
    println!(
        "{:<5} {:<11} {:<24} {:<24} {:<16} PID",
        "PROTO", "ESTADO", "LOCAL", "REMOTO", "PROCESSO"
    );
    for s in &sockets {
        println!(
            "{:<5} {:<11} {:<24} {:<24} {:<16} {}",
            s.netid,
            s.state,
            s.local(),
            s.peer(),
            s.process,
            s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
        );
    }
    Ok(())
}

fn run_tui(
    interval: Duration,
    is_root: bool,
    log_enabled: bool,
    notify_enabled: bool,
    rdns_enabled: bool,
) -> io::Result<()> {
    // Abre o log de eventos antes de entrar na tela alternativa, para que um
    // eventual aviso de erro fique visível.
    let log = if log_enabled {
        match events::EventLog::open_default(notify_enabled) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("shellmon: não foi possível abrir o log de eventos: {e}");
                None
            }
        }
    } else {
        None
    };

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(out);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut app = App::new(interval, is_root, log, rdns_enabled);
    let res = event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

fn event_loop<B: ratatui::backend::Backend>(
    terminal: &mut ratatui::Terminal<B>,
    app: &mut App,
) -> io::Result<()> {
    // Estado da tabela persistente: mantém o offset de scroll entre os
    // refreshes de 200ms, sem pular para o topo a cada atualização.
    let mut table_state = TableState::default();
    loop {
        terminal.draw(|f| ui::draw(f, app, &mut table_state))?;

        // Poll curto para manter o relógio de refresh responsivo.
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                handle_key(app, key.code, key.modifiers);
            }
        }

        app.maybe_refresh();
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    // Modo de digitação do filtro.
    if app.filter_mode {
        match code {
            KeyCode::Enter => {
                app.filter_mode = false;
                app.clamp_selection();
            }
            KeyCode::Esc => {
                app.filter_mode = false;
                app.filter.clear();
            }
            KeyCode::Backspace => {
                app.filter.pop();
            }
            KeyCode::Char(c) => app.filter.push(c),
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.should_quit = true,
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('p') => app.paused = !app.paused,
        KeyCode::Char('r') => {
            app.refresh();
            app.clamp_selection();
        }
        KeyCode::Char('/') => {
            app.filter_mode = true;
            app.filter.clear();
        }
        KeyCode::Char('t') => {
            app.proto = app.proto.next();
            app.clamp_selection();
        }
        KeyCode::Char('s') => app.sort = app.sort.next(),
        KeyCode::Char('a') => {
            app.proto = Proto::Net;
            app.clamp_selection();
        }
        KeyCode::Down | KeyCode::Char('j') => app.move_down(),
        KeyCode::Up | KeyCode::Char('k') => app.move_up(),
        KeyCode::PageDown => app.page_down(10),
        KeyCode::PageUp => app.page_up(10),
        KeyCode::Home => app.selected = 0,
        _ => {}
    }
}

fn parse_interval(args: &[String]) -> Option<f64> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-i" || a == "--interval" {
            return it.next().and_then(|v| v.parse().ok());
        }
        if let Some(v) = a.strip_prefix("--interval=") {
            return v.parse().ok();
        }
    }
    None
}

fn print_help() {
    println!(
        "shell_mon — monitor de sockets em tempo real (sobre `ss`)

USO:
    shellmon [OPÇÕES]

OPÇÕES:
    -l, --list              imprime a lista uma vez e sai (scriptável)
        --triage            relatório defensivo (expostos, LAN, navegador) e sai
    -i, --interval <SEGS>   intervalo de refresh (padrão: 0.2)
        --no-log            não registrar eventos em disco (log on por padrão)
        --no-notify         não enviar notificações de desktop (on por padrão)
        --no-rdns           não resolver nomes (DNS reverso) dos IPs remotos
    -h, --help              esta ajuda

LOG E ALERTAS (modo TUI):
    Registra listeners, entradas da LAN e DNS suspeito em
    $SHELLMON_LOG ou ~/.local/share/shellmon/events.log
    Eventos de alta severidade também disparam notify-send (desktop).

TECLAS (modo TUI):
    q / Esc / Ctrl-C   sair
    p                  pausar/retomar auto-refresh
    r                  refresh manual
    /                  filtrar (endereço, processo, estado, PID)
    t                  alternar protocolo (rede → tcp → udp → unix)
    a                  voltar para rede (tcp+udp)
    s                  alternar ordenação
    ↑/↓ ou k/j         navegar  ·  PgUp/PgDn  ·  Home

DICA: rode com `sudo` para ver o processo de sockets de outros usuários."
    );
}

//! Renderização da TUI com ratatui.

use crate::analysis::{zone, Zone};
use crate::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

/// Cor associada a cada estado de socket — paleta escolhida para diferenciar
/// os estados de relance.
pub fn state_color(state: &str) -> Color {
    match state {
        "ESTAB" => Color::Green,           // conexão ativa
        "LISTEN" => Color::LightBlue,      // aguardando conexões
        "SYN-SENT" | "SYN-RECV" => Color::Yellow, // handshake em andamento
        "TIME-WAIT" => Color::Magenta,     // fechando, aguardando timeout
        "CLOSE-WAIT" | "LAST-ACK" | "CLOSING" => Color::LightRed, // meio-fechado
        "FIN-WAIT-1" | "FIN-WAIT-2" => Color::Red, // encerrando
        "UNCONN" => Color::DarkGray,       // UDP sem conexão
        _ => Color::White,
    }
}

/// Cor por zona de confiança do par remoto.
fn zone_color(z: Zone) -> Color {
    match z {
        Zone::Loopback => Color::DarkGray,  // só a própria máquina
        Zone::LinkLocal => Color::DarkGray,
        Zone::Lan => Color::Cyan,           // rede local
        Zone::Public => Color::LightYellow, // internet (chama atenção)
        Zone::Any => Color::DarkGray,
    }
}

pub fn draw(f: &mut Frame, app: &App, table_state: &mut TableState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // resumo
            Constraint::Min(5),    // tabela
            Constraint::Length(1), // status
        ])
        .split(f.area());

    draw_summary(f, app, chunks[0]);
    draw_table(f, app, chunks[1], table_state);
    draw_status(f, app, chunks[2]);
}

fn draw_summary(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.summary;
    let pause = if app.paused { " [PAUSADO]" } else { "" };
    // Cores alinhadas com a paleta de estados (ver `state_color`).
    let text = Line::from(vec![
        Span::styled("total ", Style::default().fg(Color::DarkGray)),
        Span::styled(s.total.to_string(), bold(Color::White)),
        Span::raw("   "),
        Span::styled("tcp ", Style::default().fg(Color::DarkGray)),
        Span::styled(s.tcp.to_string(), bold(Color::Cyan)),
        Span::raw("  "),
        Span::styled("udp ", Style::default().fg(Color::DarkGray)),
        Span::styled(s.udp.to_string(), bold(Color::Magenta)),
        Span::raw("   "),
        Span::styled("estab ", Style::default().fg(Color::DarkGray)),
        Span::styled(s.estab.to_string(), bold(Color::Green)),
        Span::raw("  "),
        Span::styled("listen ", Style::default().fg(Color::DarkGray)),
        Span::styled(s.listen.to_string(), bold(Color::LightBlue)),
        Span::raw("  "),
        Span::styled("time-wait ", Style::default().fg(Color::DarkGray)),
        Span::styled(s.time_wait.to_string(), bold(Color::Magenta)),
        Span::raw("    "),
        // Indicadores defensivos: vermelho quando há algo a observar.
        Span::styled("expostos ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.exposed.to_string(),
            bold(if s.exposed > 0 { Color::Yellow } else { Color::Green }),
        ),
        Span::raw("  "),
        Span::styled("lan-in ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            s.inbound_lan.to_string(),
            bold(if s.inbound_lan > 0 { Color::Red } else { Color::Green }),
        ),
        Span::styled(pause, bold(Color::Yellow)),
    ]);
    let title = format!(
        " shell_mon  ·  proto:{}  ordem:{}{}  ",
        app.proto.label(),
        app.sort.label(),
        if app.filter.is_empty() {
            String::new()
        } else {
            format!("  filtro:\"{}\"", app.filter)
        }
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Blue));
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_table(f: &mut Frame, app: &App, area: Rect, table_state: &mut TableState) {
    let visible = app.visible();
    let header = Row::new(
        ["PROTO", "ESTADO", "RECV-Q", "SEND-Q", "LOCAL", "REMOTO", "PROCESSO", "PID"]
            .into_iter()
            .map(|h| Cell::from(h).style(bold(Color::Black).bg(Color::Gray))),
    )
    .height(1);

    let rows = visible.iter().map(|s| {
        let is_new = app.is_new(&s.key());
        // Linha nova: fundo verde escuro por ~1,5s para chamar a atenção.
        let base = if is_new {
            Style::default().bg(Color::Rgb(0, 60, 0))
        } else {
            Style::default()
        };
        // Conexão aberta por (descendente de) navegador — vetor que escala
        // a partir da navegação. Marca o processo com ⚠.
        let browser = app.browser_of(s.pid);
        let proc_cell = match browser {
            Some(_) => Cell::from(format!("⚠ {}", s.process)).style(bold(Color::Red)),
            None => Cell::from(s.process.clone()).style(Style::default().fg(Color::Magenta)),
        };
        Row::new(vec![
            Cell::from(s.netid.clone()).style(Style::default().fg(Color::Cyan)),
            Cell::from(s.state.clone()).style(bold(state_color(&s.state))),
            Cell::from(s.recv_q.to_string()),
            Cell::from(s.send_q.to_string()),
            Cell::from(s.local()),
            Cell::from(s.peer()).style(Style::default().fg(zone_color(zone(&s.peer_addr)))),
            proc_cell,
            Cell::from(s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
        ])
        .style(base)
    });

    let widths = [
        Constraint::Length(6),
        Constraint::Length(11),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Percentage(28),
        Constraint::Percentage(28),
        Constraint::Min(10),
        Constraint::Length(7),
    ];

    let count = visible.len();
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▌")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" sockets ({count}) ")),
        );

    // A seleção é a fonte da verdade em `app`; o offset de scroll persiste no
    // próprio `table_state` entre os refreshes (não recriamos a cada frame).
    if count > 0 {
        table_state.select(Some(app.selected.min(count - 1)));
    } else {
        table_state.select(None);
    }
    f.render_stateful_widget(table, area, table_state);
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = Vec::new();

    if let Some(err) = &app.last_error {
        spans.push(Span::styled(format!(" ERRO: {err} "), bold(Color::Red)));
    } else if app.filter_mode {
        spans.push(Span::styled(format!(" /{}", app.filter), bold(Color::Yellow)));
        spans.push(Span::styled("█", Style::default().fg(Color::Yellow)));
        spans.push(Span::styled(
            "  (Enter aplica · Esc cancela)",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        let help = "q sair · p pausa · / filtro · t proto · s ordem · r refresh · ↑↓ navega";
        spans.push(Span::styled(help, Style::default().fg(Color::DarkGray)));
        if app.log_path().is_some() {
            spans.push(Span::styled("  ·  📝 log", Style::default().fg(Color::Green)));
        }
        if !app.is_root {
            spans.push(Span::styled(
                "  ·  sem root: processos de outros usuários ocultos (sudo shellmon)",
                Style::default().fg(Color::Yellow),
            ));
        }
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

//! Renderização da TUI com ratatui.

use crate::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // resumo
            Constraint::Min(5),    // tabela
            Constraint::Length(1), // status
        ])
        .split(f.area());

    draw_summary(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_status(f, app, chunks[2]);
}

fn draw_summary(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.summary;
    let pause = if app.paused { " [PAUSADO]" } else { "" };
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
        Span::styled(s.listen.to_string(), bold(Color::Yellow)),
        Span::raw("  "),
        Span::styled("time-wait ", Style::default().fg(Color::DarkGray)),
        Span::styled(s.time_wait.to_string(), bold(Color::Red)),
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

fn draw_table(f: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible();
    let header = Row::new(
        ["PROTO", "ESTADO", "RECV-Q", "SEND-Q", "LOCAL", "REMOTO", "PROCESSO", "PID"]
            .into_iter()
            .map(|h| Cell::from(h).style(bold(Color::Black).bg(Color::Gray))),
    )
    .height(1);

    let rows = visible.iter().map(|s| {
        let is_new = app.new_keys.contains(&s.key());
        let state_color = match s.state.as_str() {
            "ESTAB" => Color::Green,
            "LISTEN" => Color::Yellow,
            "TIME-WAIT" | "CLOSE-WAIT" | "FIN-WAIT-1" | "FIN-WAIT-2" => Color::Red,
            "UNCONN" => Color::DarkGray,
            _ => Color::White,
        };
        let base = if is_new {
            Style::default().fg(Color::Black).bg(Color::Green)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(s.netid.clone()).style(Style::default().fg(Color::Cyan)),
            Cell::from(s.state.clone()).style(Style::default().fg(state_color)),
            Cell::from(s.recv_q.to_string()),
            Cell::from(s.send_q.to_string()),
            Cell::from(s.local()),
            Cell::from(s.peer()),
            Cell::from(s.process.clone()).style(Style::default().fg(Color::Magenta)),
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

    let mut state = TableState::default();
    if count > 0 {
        state.select(Some(app.selected.min(count - 1)));
    }
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = Vec::new();

    if let Some(err) = &app.last_error {
        spans.push(Span::styled(format!(" ERRO: {err} "), bold(Color::Red)));
    } else if app.filter_mode {
        spans.push(Span::styled(
            format!(" /{}", app.filter),
            bold(Color::Yellow),
        ));
        spans.push(Span::styled("█", Style::default().fg(Color::Yellow)));
        spans.push(Span::styled(
            "  (Enter aplica · Esc cancela)",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        let help = "q sair · p pausa · / filtro · t proto · s ordem · r refresh · ↑↓ navega";
        spans.push(Span::styled(help, Style::default().fg(Color::DarkGray)));
        if !app.is_root {
            spans.push(Span::styled(
                "  ·  sem root: processos de outros usuários ocultos (sudo shellmon)",
                Style::default().fg(Color::Yellow),
            ));
        }
        if !app.status.is_empty() {
            spans.push(Span::styled(format!("  ·  {}", app.status), Style::default().fg(Color::Green)));
        }
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

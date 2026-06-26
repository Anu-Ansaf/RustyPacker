use super::theme::{self, palette, radius, space, Theme};
use eframe::egui::{
    self, Align, Align2, Color32, FontFamily, FontId, Frame, Id, LayerId, Layout, Margin, Order,
    Rect, Response, RichText, Rounding, Sense, Stroke, TextStyle, Ui, Vec2,
};

#[derive(Clone, Debug)]
pub enum AppStatus {
    Ready { hint: String },
    Building,
    Cleaning,
}

fn status_color(s: &AppStatus) -> Color32 {
    match s {
        AppStatus::Ready { .. } => palette::ok(),
        AppStatus::Building     => palette::accent(),
        AppStatus::Cleaning     => palette::warn(),
    }
}

fn status_text(s: &AppStatus) -> String {
    match s {
        AppStatus::Ready { hint } => hint.clone(),
        AppStatus::Building       => "building…".into(),
        AppStatus::Cleaning       => "cleaning…".into(),
    }
}

pub fn title_bar(
    ui: &mut Ui,
    version: &str,
    status: &AppStatus,
    theme: &mut Theme,
) -> bool {
    let mut changed = false;
    Frame::none()
        .fill(palette::bg_chrome())
        .inner_margin(Margin {
            left: space::LG,
            right: space::LG,
            top: space::SM + 2.0,
            bottom: space::SM + 2.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                changed = theme_picker(ui, theme);
                ui.add_space(space::SM);

                ui.label(
                    RichText::new("RUSTYPACKER")
                        .font(theme::font_mono_bold(12.0))
                        .color(palette::accent()),
                );
                ui.add_space(space::SM);
                ui.label(
                    RichText::new(format!("v{version}"))
                        .font(theme::font_mono(11.0))
                        .color(palette::text_muted()),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let col = status_color(status);
                    let txt = status_text(status);
                    ui.label(
                        RichText::new(txt)
                            .font(theme::font_sans(11.0))
                            .color(palette::text_muted()),
                    );
                    ui.add_space(space::XS + 2.0);
                    draw_pip(ui, col);
                });
            });
        });
    let r = ui.max_rect();
    ui.painter()
        .hline(r.x_range(), r.bottom(), Stroke::new(1.0, palette::border_strong()));
    changed
}

fn theme_picker(ui: &mut Ui, theme: &mut Theme) -> bool {
    let font = theme::font_mono(10.5);
    let label = format!("◆ {}", theme.label().to_uppercase());
    let pad = Vec2::new(space::SM + 2.0, space::XS + 1.0);
    let galley = ui.painter().layout_no_wrap(label.clone(), font.clone(), palette::accent());
    let size = galley.size() + Vec2::new(pad.x * 2.0, pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());

    let stroke = if resp.hovered() { palette::accent_hi() } else { palette::accent_dim() };
    let fg     = if resp.hovered() { palette::accent_hi() } else { palette::accent() };
    let fill   = if resp.hovered() { palette::accent_alpha(0x14) } else { palette::accent_alpha(0x08) };
    ui.painter().rect(rect, radius::INPUT, fill, Stroke::new(1.0, stroke));
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, label, font, fg);

    let popup = ui.make_persistent_id("rp_theme_picker_popup");
    if resp.clicked() {
        ui.memory_mut(|m| m.toggle_popup(popup));
    }

    let mut changed = false;
    egui::popup::popup_below_widget(ui, popup, &resp, |ui| {
        ui.set_min_width(140.0);
        Frame::none()
            .fill(palette::bg_panel())
            .stroke(Stroke::new(1.0, palette::border_strong()))
            .rounding(radius::CARD)
            .inner_margin(Margin::same(4.0))
            .show(ui, |ui| {
                for t in Theme::ALL {
                    let active = *t == *theme;
                    let r = ui.add(egui::SelectableLabel::new(
                        active,
                        RichText::new(format!("  {}", t.label()))
                            .font(theme::font_sans(12.0))
                            .color(if active { palette::accent() } else { palette::text() }),
                    ));
                    if r.clicked() && *theme != *t {
                        *theme = *t;
                        changed = true;
                        ui.memory_mut(|m| m.close_popup());
                    }
                }
            });
    });
    changed
}

fn draw_pip(ui: &mut Ui, color: Color32) {
    let size = Vec2::splat(8.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let p = ui.painter();
    p.circle_filled(
        rect.center(),
        5.0,
        Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), 64),
    );
    p.circle_filled(rect.center(), 3.5, color);
}

pub fn tab_strip<T: PartialEq + Clone>(
    ui: &mut Ui,
    current: &mut T,
    items: &[(T, &str)],
) {
    Frame::none()
        .fill(palette::bg_chrome())
        .inner_margin(Margin {
            left: space::LG,
            right: space::LG,
            top: 0.0,
            bottom: 0.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for (val, label) in items {
                    let active = current == val;
                    if tab_button(ui, label, active).clicked() {
                        *current = val.clone();
                    }
                }
            });
        });
    let r = ui.max_rect();
    ui.painter()
        .hline(r.x_range(), r.bottom(), Stroke::new(1.0, palette::border_strong()));
}

fn tab_button(ui: &mut Ui, label: &str, active: bool) -> Response {
    let pad = Vec2::new(space::LG, space::SM + 1.0);
    let color = if active { palette::accent() } else { palette::text_muted() };
    let upper = label.to_uppercase();
    let font = theme::font_sans(11.0);
    let galley = ui.painter().layout_no_wrap(upper.clone(), font.clone(), color);
    let size = galley.size() + Vec2::new(pad.x * 2.0, pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());

    if active {
        ui.painter().rect_filled(rect, Rounding::ZERO, palette::accent_alpha(0x0a));
    } else if resp.hovered() {
        ui.painter().rect_filled(
            rect,
            Rounding::ZERO,
            Color32::from_rgba_premultiplied(0xff, 0xff, 0xff, 0x05),
        );
    }
    if active {
        let y = rect.bottom() - 1.0;
        ui.painter().line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            Stroke::new(2.0, palette::accent()),
        );
    }
    let fg = if resp.hovered() && !active { palette::text_label() } else { color };
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, upper, font, fg);
    resp
}

pub fn section_header(ui: &mut Ui, label: &str, count_suffix: Option<&str>) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(3.0, 14.0), Sense::hover());
        ui.painter().rect_filled(rect, Rounding::same(1.0), palette::accent());
        ui.add_space(space::XS + 2.0);
        ui.label(
            RichText::new(label.to_uppercase())
                .font(theme::font_sans(10.0))
                .color(palette::text())
                .strong(),
        );
        if let Some(s) = count_suffix {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(s.to_uppercase())
                        .font(theme::font_sans(10.0))
                        .color(palette::text_muted()),
                );
            });
        }
    });
    ui.add_space(space::XS + 2.0);
}

pub fn card<R>(ui: &mut Ui, body: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::none()
        .fill(palette::bg_panel())
        .stroke(Stroke::new(1.0, palette::border()))
        .rounding(radius::CARD)
        .inner_margin(Margin::symmetric(space::MD + 2.0, space::MD))
        .show(ui, body)
        .inner
}

pub fn field_row(ui: &mut Ui, label: &str, body: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(
            Vec2::new(96.0, 22.0),
            egui::Label::new(
                RichText::new(label)
                    .font(theme::font_sans(11.0))
                    .color(palette::text_label()),
            ),
        );
        body(ui);
    });
}

#[derive(Clone, Copy, Debug)]
pub enum PillKind {
    Accent,
    Warn,
    Danger,
}

pub fn pill(ui: &mut Ui, text: &str, kind: PillKind) -> Response {
    let (fg, bg, border) = match kind {
        PillKind::Accent => (
            palette::accent(),
            palette::accent_alpha(0x22),
            palette::accent_alpha(0x66),
        ),
        PillKind::Warn => (
            palette::warn(),
            palette::warn_alpha(0x22),
            palette::warn_alpha(0x66),
        ),
        PillKind::Danger => (
            palette::danger_hi(),
            palette::danger_alpha(0x22),
            palette::danger_alpha(0x66),
        ),
    };
    let font = theme::font_sans(9.0);
    let upper = text.to_uppercase();
    let galley = ui.painter().layout_no_wrap(upper.clone(), font.clone(), fg);
    let pad = Vec2::new(8.0, 3.0);
    let size = galley.size() + Vec2::new(pad.x * 2.0, pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect(rect, Rounding::same(10.0), bg, Stroke::new(1.0, border));
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, upper, font, fg);
    resp
}

pub fn segmented<T: PartialEq + Clone>(
    ui: &mut Ui,
    current: &mut T,
    items: &[(T, &str)],
) {
    Frame::none()
        .fill(palette::bg_input())
        .stroke(Stroke::new(1.0, palette::border()))
        .rounding(radius::INPUT)
        .inner_margin(Margin::same(2.0))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.horizontal(|ui| {
                for (val, label) in items {
                    let active = current == val;
                    if segment_button(ui, label, active).clicked() {
                        *current = val.clone();
                    }
                }
            });
        });
}

fn segment_button(ui: &mut Ui, label: &str, active: bool) -> Response {
    let font = theme::font_sans(11.0);
    let fg = if active { palette::bg_base() } else { palette::text_label() };
    let galley = ui.painter().layout_no_wrap(label.to_string(), font.clone(), fg);
    let pad = Vec2::new(space::MD, space::XS);
    let size = galley.size() + Vec2::new(pad.x * 2.0, pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    if active {
        ui.painter().rect_filled(rect, Rounding::same(2.0), palette::accent());
    } else if resp.hovered() {
        ui.painter().rect_filled(
            rect,
            Rounding::same(2.0),
            Color32::from_rgba_premultiplied(0xff, 0xff, 0xff, 0x08),
        );
    }
    let final_fg = if active {
        palette::bg_base()
    } else if resp.hovered() {
        palette::text()
    } else {
        palette::text_label()
    };
    let font2 = if active { theme::font_mono_bold(11.0) } else { font };
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, label, font2, final_fg);
    resp
}

#[derive(Clone, Copy, Debug)]
pub enum StepAccent {
    Normal,
    Warn,
    Danger,
}

pub struct StepView<'a> {
    pub idx: u32,
    pub title: &'a str,
    pub pill_text: &'a str,
    pub accent: StepAccent,
}

pub fn step_card(ui: &mut Ui, step: &StepView<'_>) {
    let bar_color = match step.accent {
        StepAccent::Normal => palette::accent(),
        StepAccent::Warn   => palette::warn(),
        StepAccent::Danger => palette::danger(),
    };
    let kind = match step.accent {
        StepAccent::Normal => PillKind::Accent,
        StepAccent::Warn   => PillKind::Warn,
        StepAccent::Danger => PillKind::Danger,
    };

    Frame::none()
        .fill(palette::bg_panel())
        .stroke(Stroke::new(1.0, palette::border()))
        .rounding(radius::CARD)
        .inner_margin(Margin::symmetric(space::MD + 2.0, space::SM + 2.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (bar_rect, _) =
                    ui.allocate_exact_size(Vec2::new(3.0, 18.0), Sense::hover());
                ui.painter().rect_filled(bar_rect, Rounding::same(1.0), bar_color);
                ui.add_space(space::SM);
                ui.label(
                    RichText::new(format!("{:02}", step.idx))
                        .font(theme::font_mono_bold(11.0))
                        .color(palette::text_muted()),
                );
                ui.add_space(space::SM);
                ui.label(
                    RichText::new(step.title)
                        .font(theme::font_sans(13.0))
                        .color(palette::text())
                        .strong(),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    pill(ui, step.pill_text, kind);
                });
            });
        });
}

pub fn primary_button(ui: &mut Ui, label: &str) -> Response {
    let font = theme::font_sans(11.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font.clone(), palette::bg_base());
    let pad = Vec2::new(space::MD, space::XS + 2.0);
    let size = galley.size() + Vec2::new(pad.x * 2.0, pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let fill = if resp.hovered() { palette::accent_hi() } else { palette::accent() };
    ui.painter().rect_filled(rect, radius::INPUT, fill);
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        label,
        theme::font_mono_bold(11.0),
        palette::bg_base(),
    );
    resp
}

pub fn primary_button_disabled(ui: &mut Ui, label: &str) -> Response {
    let font = theme::font_sans(11.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font.clone(), palette::text_muted());
    let pad = Vec2::new(space::MD, space::XS + 2.0);
    let size = galley.size() + Vec2::new(pad.x * 2.0, pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect(
        rect,
        radius::INPUT,
        palette::bg_panel(),
        Stroke::new(1.0, palette::border()),
    );
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        label,
        theme::font_mono_bold(11.0),
        palette::text_muted(),
    );
    resp
}

pub fn ghost_button(ui: &mut Ui, label: &str) -> Response {
    let font = theme::font_sans(11.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font.clone(), palette::accent());
    let pad = Vec2::new(space::SM + 2.0, space::XS + 1.0);
    let size = galley.size() + Vec2::new(pad.x * 2.0, pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let stroke = if resp.hovered() { palette::accent_hi() } else { palette::accent() };
    let fg = stroke;
    let fill = if resp.hovered() { palette::accent_alpha(0x14) } else { Color32::TRANSPARENT };
    ui.painter().rect(rect, radius::INPUT, fill, Stroke::new(1.0, stroke));
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, label, font, fg);
    resp
}

pub struct TerminalOpts {
    pub max_rows: usize,
    pub min_rows: usize,
}

impl Default for TerminalOpts {
    fn default() -> Self {
        Self { max_rows: 22, min_rows: 14 }
    }
}

pub fn terminal_view(ui: &mut Ui, log: &str, opts: TerminalOpts) {
    Frame::none()
        .fill(Color32::from_rgb(0x0a, 0x09, 0x07))
        .stroke(Stroke::new(1.0, palette::border()))
        .rounding(radius::CARD)
        .inner_margin(Margin::symmetric(space::MD + 2.0, space::SM + 4.0))
        .show(ui, |ui| {
            let row_h = ui.text_style_height(&TextStyle::Monospace);
            let min_h = row_h * opts.min_rows as f32;
            let max_h = row_h * opts.max_rows as f32;
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .min_scrolled_height(min_h)
                .max_height(max_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    if log.is_empty() {
                        ui.label(
                            RichText::new("waiting for build…")
                                .font(theme::font_mono(12.0))
                                .color(palette::text_muted()),
                        );
                    } else {
                        for line in log.lines() {
                            draw_log_line(ui, line);
                        }
                    }
                });
        });
}

fn draw_log_line(ui: &mut Ui, line: &str) {
    let (col, prefix, rest) = classify(line);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        if !prefix.is_empty() {
            ui.label(
                RichText::new(prefix)
                    .font(theme::font_mono_bold(12.0))
                    .color(col),
            );
            ui.label(
                RichText::new(rest)
                    .font(theme::font_mono(12.0))
                    .color(palette::text()),
            );
        } else {
            ui.label(
                RichText::new(line)
                    .font(theme::font_mono(12.0))
                    .color(palette::text_dim()),
            );
        }
    });
}

fn classify(line: &str) -> (Color32, &str, &str) {
    if let Some(rest) = line.strip_prefix("[*]") {
        (palette::accent(), "[*]", rest)
    } else if let Some(rest) = line.strip_prefix("[+]") {
        (palette::ok(), "[+]", rest)
    } else if let Some(rest) = line.strip_prefix("[!]") {
        (palette::warn(), "[!]", rest)
    } else if let Some(rest) = line.strip_prefix("[-]") {
        (palette::danger_hi(), "[-]", rest)
    } else {
        (palette::text_dim(), "", line)
    }
}

pub fn input_readonly(ui: &mut Ui, value: &str, width: f32) {
    let mut s = value.to_string();
    ui.add(
        egui::TextEdit::singleline(&mut s)
            .desired_width(width)
            .interactive(false)
            .font(FontId::new(12.0, FontFamily::Monospace))
            .text_color(palette::text_dim())
            .margin(Vec2::new(space::SM, space::XS + 1.0)),
    );
}

pub fn description(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .font(theme::font_sans(11.0))
            .color(palette::text_dim()),
    );
}

pub fn meta_line(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .font(theme::font_mono(10.5))
            .color(palette::text_muted()),
    );
}

pub fn warn_banner(ui: &mut Ui, text: &str) {
    Frame::none()
        .fill(palette::danger_alpha(0x14))
        .stroke(Stroke::new(1.0, palette::danger_alpha(0x55)))
        .rounding(radius::INPUT)
        .inner_margin(Margin::symmetric(space::SM + 2.0, space::SM))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("⚠")
                        .font(theme::font_sans(12.0))
                        .color(palette::danger_hi()),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(text)
                        .font(theme::font_sans(11.0))
                        .color(palette::danger_hi()),
                );
            });
        });
}

pub fn paint_scanlines(ctx: &egui::Context, area: Rect) {
    let painter = ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("rp_scanlines")));
    let accent = palette::accent();
    let color = Color32::from_rgba_premultiplied(
        ((accent.r() as u16 * 0x0c) / 255) as u8,
        ((accent.g() as u16 * 0x0c) / 255) as u8,
        ((accent.b() as u16 * 0x0c) / 255) as u8,
        0x0c,
    );
    let mut y = area.top();
    while y < area.bottom() {
        painter.line_segment(
            [egui::pos2(area.left(), y), egui::pos2(area.right(), y)],
            Stroke::new(1.0, color),
        );
        y += 3.0;
    }
}

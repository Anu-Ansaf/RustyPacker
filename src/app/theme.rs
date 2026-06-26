use eframe::egui::{
    self, Color32, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke, Style, TextStyle,
    Vec2, Visuals,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    Tactical,
    Cyberpunk,
}

impl Default for Theme {
    fn default() -> Self {
        Theme::Cyberpunk
    }
}

impl Theme {
    pub const ALL: &'static [Theme] = &[Theme::Tactical, Theme::Cyberpunk];

    pub fn label(self) -> &'static str {
        match self {
            Theme::Tactical => "Tactical",
            Theme::Cyberpunk => "Cyberpunk",
        }
    }

    pub fn palette(self) -> &'static Palette {
        match self {
            Theme::Tactical => &TACTICAL,
            Theme::Cyberpunk => &CYBERPUNK,
        }
    }

    pub fn mono_only(self) -> bool {
        matches!(self, Theme::Cyberpunk)
    }

    pub fn scanlines(self) -> bool {
        matches!(self, Theme::Cyberpunk)
    }
}

pub struct Palette {
    pub bg_base: Color32,
    pub bg_chrome: Color32,
    pub bg_panel: Color32,
    pub bg_panel_hi: Color32,
    pub bg_input: Color32,

    pub border: Color32,
    pub border_strong: Color32,

    pub text: Color32,
    pub text_dim: Color32,
    pub text_label: Color32,
    pub text_muted: Color32,

    pub accent: Color32,
    pub accent_hi: Color32,
    pub accent_dim: Color32,

    pub ok: Color32,
    pub warn: Color32,
    pub danger: Color32,
    pub danger_hi: Color32,
}

pub const TACTICAL: Palette = Palette {
    bg_base:       Color32::from_rgb(0x16, 0x14, 0x0f),
    bg_chrome:     Color32::from_rgb(0x10, 0x0e, 0x0a),
    bg_panel:      Color32::from_rgb(0x1a, 0x18, 0x12),
    bg_panel_hi:   Color32::from_rgb(0x21, 0x1d, 0x16),
    bg_input:      Color32::from_rgb(0x0e, 0x0c, 0x08),
    border:        Color32::from_rgb(0x2e, 0x28, 0x20),
    border_strong: Color32::from_rgb(0x3a, 0x34, 0x2a),
    text:          Color32::from_rgb(0xd6, 0xcf, 0xb8),
    text_dim:      Color32::from_rgb(0x8a, 0x82, 0x70),
    text_label:    Color32::from_rgb(0x9e, 0x95, 0x80),
    text_muted:    Color32::from_rgb(0x6e, 0x67, 0x55),
    accent:        Color32::from_rgb(0xd9, 0x97, 0x44),
    accent_hi:     Color32::from_rgb(0xe8, 0xa8, 0x55),
    accent_dim:    Color32::from_rgb(0xb3, 0x90, 0x39),
    ok:            Color32::from_rgb(0x7f, 0xb0, 0x69),
    warn:          Color32::from_rgb(0xd9, 0xb5, 0x66),
    danger:        Color32::from_rgb(0xcc, 0x44, 0x44),
    danger_hi:     Color32::from_rgb(0xe0, 0x70, 0x70),
};

pub const CYBERPUNK: Palette = Palette {
    bg_base:       Color32::from_rgb(0x07, 0x0a, 0x0d),
    bg_chrome:     Color32::from_rgb(0x05, 0x07, 0x09),
    bg_panel:      Color32::from_rgb(0x0a, 0x12, 0x16),
    bg_panel_hi:   Color32::from_rgb(0x0e, 0x1a, 0x20),
    bg_input:      Color32::from_rgb(0x04, 0x07, 0x09),
    border:        Color32::from_rgb(0x0e, 0x3a, 0x2e),
    border_strong: Color32::from_rgb(0x14, 0x66, 0x52),
    text:          Color32::from_rgb(0xcd, 0xff, 0xf0),
    text_dim:      Color32::from_rgb(0x5a, 0x9c, 0x8a),
    text_label:    Color32::from_rgb(0x7f, 0xbf, 0xa9),
    text_muted:    Color32::from_rgb(0x3a, 0x6b, 0x5d),
    accent:        Color32::from_rgb(0x14, 0xff, 0xba),
    accent_hi:     Color32::from_rgb(0x7f, 0xff, 0xe0),
    accent_dim:    Color32::from_rgb(0x0f, 0xcc, 0x9a),
    ok:            Color32::from_rgb(0x14, 0xff, 0xba),
    warn:          Color32::from_rgb(0xff, 0xdb, 0x40),
    danger:        Color32::from_rgb(0xff, 0x40, 0x60),
    danger_hi:     Color32::from_rgb(0xff, 0x70, 0x80),
};

static ACTIVE: AtomicU8 = AtomicU8::new(1);

fn enc(t: Theme) -> u8 {
    match t {
        Theme::Tactical => 0,
        Theme::Cyberpunk => 1,
    }
}
fn dec(v: u8) -> Theme {
    match v {
        0 => Theme::Tactical,
        _ => Theme::Cyberpunk,
    }
}

pub fn current() -> Theme {
    dec(ACTIVE.load(Ordering::Relaxed))
}
pub fn current_palette() -> &'static Palette {
    current().palette()
}

pub mod space {
    pub const XS:  f32 = 4.0;
    pub const SM:  f32 = 8.0;
    pub const MD:  f32 = 12.0;
    pub const LG:  f32 = 18.0;
    pub const XXL: f32 = 32.0;
}

pub mod radius {
    use eframe::egui::Rounding;
    pub const INPUT:  Rounding = Rounding::same(3.0);
    pub const CARD:   Rounding = Rounding::same(4.0);
    pub const CHROME: Rounding = Rounding::same(6.0);
}

pub mod palette {
    use super::current_palette;
    use eframe::egui::Color32;

    pub fn bg_base()       -> Color32 { current_palette().bg_base }
    pub fn bg_chrome()     -> Color32 { current_palette().bg_chrome }
    pub fn bg_panel()      -> Color32 { current_palette().bg_panel }
    pub fn bg_input()      -> Color32 { current_palette().bg_input }

    pub fn border()        -> Color32 { current_palette().border }
    pub fn border_strong() -> Color32 { current_palette().border_strong }

    pub fn text()       -> Color32 { current_palette().text }
    pub fn text_dim()   -> Color32 { current_palette().text_dim }
    pub fn text_label() -> Color32 { current_palette().text_label }
    pub fn text_muted() -> Color32 { current_palette().text_muted }

    pub fn accent()     -> Color32 { current_palette().accent }
    pub fn accent_hi()  -> Color32 { current_palette().accent_hi }
    pub fn accent_dim() -> Color32 { current_palette().accent_dim }

    pub fn ok()        -> Color32 { current_palette().ok }
    pub fn warn()      -> Color32 { current_palette().warn }
    pub fn danger()    -> Color32 { current_palette().danger }
    pub fn danger_hi() -> Color32 { current_palette().danger_hi }

    fn tint(c: Color32, alpha: u8) -> Color32 {
        let r = ((c.r() as u16 * alpha as u16) / 255) as u8;
        let g = ((c.g() as u16 * alpha as u16) / 255) as u8;
        let b = ((c.b() as u16 * alpha as u16) / 255) as u8;
        Color32::from_rgba_premultiplied(r, g, b, alpha)
    }

    pub fn accent_alpha(a: u8) -> Color32 { tint(accent(), a) }
    pub fn warn_alpha(a:   u8) -> Color32 { tint(warn(),   a) }
    pub fn danger_alpha(a: u8) -> Color32 { tint(danger(), a) }
}

const FONT_INTER:     &[u8] = include_bytes!("../../assets/fonts/InterVariable.ttf");
const FONT_JBM:       &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf");
const FONT_JBM_BOLD:  &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Bold.ttf");

pub const FAMILY_MONO_BOLD: &str = "jbm-bold";

pub fn install(ctx: &egui::Context, theme: Theme) {
    ACTIVE.store(enc(theme), Ordering::Relaxed);
    install_fonts(ctx, theme);
    install_style(ctx, theme);
}

fn install_fonts(ctx: &egui::Context, theme: Theme) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("inter".into(),    FontData::from_static(FONT_INTER));
    fonts.font_data.insert("jbm".into(),      FontData::from_static(FONT_JBM));
    fonts.font_data.insert("jbm-bold".into(), FontData::from_static(FONT_JBM_BOLD));

    let proportional_primary = if theme.mono_only() { "jbm" } else { "inter" };

    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, proportional_primary.into());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "jbm".into());

    fonts
        .families
        .insert(FontFamily::Name(FAMILY_MONO_BOLD.into()), vec!["jbm-bold".into()]);

    ctx.set_fonts(fonts);
}

fn install_style(ctx: &egui::Context, theme: Theme) {
    let p = theme.palette();
    let mut style: Style = (*ctx.style()).clone();
    let mut v = Visuals::dark();

    v.override_text_color = Some(p.text);
    v.panel_fill          = p.bg_base;
    v.window_fill         = p.bg_base;
    v.window_stroke       = Stroke::new(1.0, p.border_strong);
    v.window_rounding     = radius::CHROME;
    v.menu_rounding       = radius::CARD;
    v.extreme_bg_color    = p.bg_input;
    v.faint_bg_color      = p.bg_panel;
    v.code_bg_color       = p.bg_input;

    v.selection.bg_fill = p.accent.linear_multiply(0.35);
    v.selection.stroke  = Stroke::new(1.0, p.accent);
    v.hyperlink_color   = p.accent_hi;

    let w = &mut v.widgets;
    w.noninteractive.bg_fill      = p.bg_panel;
    w.noninteractive.weak_bg_fill = p.bg_panel;
    w.noninteractive.bg_stroke    = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke    = Stroke::new(1.0, p.text);
    w.noninteractive.rounding     = radius::CARD;

    w.inactive.bg_fill      = p.bg_input;
    w.inactive.weak_bg_fill = p.bg_input;
    w.inactive.bg_stroke    = Stroke::new(1.0, p.border);
    w.inactive.fg_stroke    = Stroke::new(1.0, p.text_label);
    w.inactive.rounding     = radius::INPUT;

    w.hovered.bg_fill      = p.bg_panel_hi;
    w.hovered.weak_bg_fill = p.bg_panel_hi;
    w.hovered.bg_stroke    = Stroke::new(1.0, p.accent);
    w.hovered.fg_stroke    = Stroke::new(1.0, p.text);
    w.hovered.rounding     = radius::INPUT;

    w.active.bg_fill      = p.accent;
    w.active.weak_bg_fill = p.accent.linear_multiply(0.2);
    w.active.bg_stroke    = Stroke::new(1.0, p.accent);
    w.active.fg_stroke    = Stroke::new(1.0, p.bg_base);
    w.active.rounding     = radius::INPUT;

    w.open.bg_fill   = p.bg_input;
    w.open.bg_stroke = Stroke::new(1.0, p.accent);
    w.open.fg_stroke = Stroke::new(1.0, p.text);
    w.open.rounding  = radius::INPUT;

    v.handle_shape = egui::style::HandleShape::Rect { aspect_ratio: 1.0 };

    style.visuals = v;

    style.spacing.item_spacing     = Vec2::new(space::SM, space::XS + 1.0);
    style.spacing.button_padding   = Vec2::new(space::MD, space::XS + 2.0);
    style.spacing.window_margin    = Margin::same(0.0);
    style.spacing.menu_margin      = Margin::same(6.0);
    style.spacing.indent           = space::LG;
    style.spacing.scroll.bar_width = 8.0;
    style.spacing.interact_size    = Vec2::new(24.0, 22.0);

    let mut text_styles = std::collections::BTreeMap::new();
    text_styles.insert(TextStyle::Heading,   FontId::new(15.0, FontFamily::Proportional));
    text_styles.insert(TextStyle::Body,      FontId::new(13.0, FontFamily::Proportional));
    text_styles.insert(TextStyle::Button,    FontId::new(12.0, FontFamily::Proportional));
    text_styles.insert(TextStyle::Small,     FontId::new(11.0, FontFamily::Proportional));
    text_styles.insert(TextStyle::Monospace, FontId::new(12.0, FontFamily::Monospace));
    style.text_styles = text_styles;

    ctx.set_style(style);
}

pub fn font_sans(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

pub fn font_mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

pub fn font_mono_bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(FAMILY_MONO_BOLD.into()))
}

//! Multi-theme design system for the RustyPacker GUI.
//!
//! Two themes ship today (Tactical, Cyberpunk). Each theme is a single
//! [`Palette`] value; widgets read the current palette via the `palette::*`
//! accessor functions. Switching themes is a single `set_theme()` call that
//! updates the atomic discriminant and re-installs fonts/Visuals.
//!
//! Tactical = the default; Cyberpunk forces all proportional text through
//! JetBrains Mono and enables a scanline overlay (painted by mod.rs).

use eframe::egui::{
    self, Color32, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke, Style,
    TextStyle, Vec2, Visuals,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};

// ---------------------------------------------------------------- Theme

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    Tactical,
    Cyberpunk,
}

impl Default for Theme {
    fn default() -> Self { Self::Cyberpunk }
}

impl Theme {
    pub const ALL: &'static [Theme] = &[Theme::Tactical, Theme::Cyberpunk];

    pub fn label(self) -> &'static str {
        match self {
            Theme::Tactical  => "Tactical",
            Theme::Cyberpunk => "Cyberpunk",
        }
    }

    pub fn palette(self) -> &'static Palette {
        match self {
            Theme::Tactical  => &TACTICAL_PAL,
            Theme::Cyberpunk => &CYBERPUNK_PAL,
        }
    }

    /// True if every text style (including Proportional) should render mono.
    pub fn mono_only(self) -> bool {
        matches!(self, Theme::Cyberpunk)
    }

    /// True if the central panel should overlay a subtle CRT scanline pattern.
    pub fn scanlines(self) -> bool {
        matches!(self, Theme::Cyberpunk)
    }
}

// ---------------------------------------------------------------- Palette

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

    /// Pre-mixed soft tints for filled badges / banners.
    pub accent_tint: Color32,
    pub danger_tint: Color32,
}

pub const TACTICAL_PAL: Palette = Palette {
    bg_base:      Color32::from_rgb(0x16, 0x14, 0x0f),
    bg_chrome:    Color32::from_rgb(0x10, 0x0e, 0x0a),
    bg_panel:     Color32::from_rgb(0x1a, 0x18, 0x12),
    bg_panel_hi:  Color32::from_rgb(0x21, 0x1d, 0x16),
    bg_input:     Color32::from_rgb(0x0e, 0x0c, 0x08),
    border:        Color32::from_rgb(0x2e, 0x28, 0x20),
    border_strong: Color32::from_rgb(0x3a, 0x34, 0x2a),
    text:       Color32::from_rgb(0xd6, 0xcf, 0xb8),
    text_dim:   Color32::from_rgb(0x8a, 0x82, 0x70),
    text_label: Color32::from_rgb(0x9e, 0x95, 0x80),
    text_muted: Color32::from_rgb(0x6e, 0x67, 0x55),
    accent:     Color32::from_rgb(0xd9, 0x97, 0x44),
    accent_hi:  Color32::from_rgb(0xe8, 0xa8, 0x55),
    accent_dim: Color32::from_rgb(0xb3, 0x90, 0x39),
    ok:        Color32::from_rgb(0x7f, 0xb0, 0x69),
    warn:      Color32::from_rgb(0xd9, 0xb5, 0x66),
    danger:    Color32::from_rgb(0xcc, 0x44, 0x44),
    danger_hi: Color32::from_rgb(0xe0, 0x70, 0x70),
    accent_tint: Color32::from_rgba_premultiplied(0x36, 0x26, 0x10, 0x40),
    danger_tint: Color32::from_rgba_premultiplied(0x33, 0x11, 0x11, 0x40),
};

pub const CYBERPUNK_PAL: Palette = Palette {
    bg_base:      Color32::from_rgb(0x07, 0x0a, 0x0d),
    bg_chrome:    Color32::from_rgb(0x05, 0x07, 0x09),
    bg_panel:     Color32::from_rgb(0x0a, 0x12, 0x16),
    bg_panel_hi:  Color32::from_rgb(0x0e, 0x1a, 0x20),
    bg_input:     Color32::from_rgb(0x04, 0x07, 0x09),
    border:        Color32::from_rgb(0x0e, 0x3a, 0x2e),
    border_strong: Color32::from_rgb(0x14, 0x66, 0x52),
    text:       Color32::from_rgb(0xcd, 0xff, 0xf0),
    text_dim:   Color32::from_rgb(0x5a, 0x9c, 0x8a),
    text_label: Color32::from_rgb(0x7f, 0xbf, 0xa9),
    text_muted: Color32::from_rgb(0x3a, 0x6b, 0x5d),
    accent:     Color32::from_rgb(0x14, 0xff, 0xba),
    accent_hi:  Color32::from_rgb(0x7f, 0xff, 0xe0),
    accent_dim: Color32::from_rgb(0x0f, 0xcc, 0x9a),
    ok:        Color32::from_rgb(0x14, 0xff, 0xba),
    warn:      Color32::from_rgb(0xff, 0xdb, 0x40),
    danger:    Color32::from_rgb(0xff, 0x40, 0x60),
    danger_hi: Color32::from_rgb(0xff, 0x70, 0x80),
    accent_tint: Color32::from_rgba_premultiplied(0x06, 0x3c, 0x2c, 0x60),
    danger_tint: Color32::from_rgba_premultiplied(0x3c, 0x0c, 0x14, 0x60),
};

// ---------------------------------------------------------------- active theme

static ACTIVE: AtomicU8 = AtomicU8::new(0);

fn theme_to_u8(t: Theme) -> u8 {
    match t {
        Theme::Tactical  => 0,
        Theme::Cyberpunk => 1,
    }
}
fn u8_to_theme(v: u8) -> Theme {
    match v {
        1 => Theme::Cyberpunk,
        _ => Theme::Tactical,
    }
}

pub fn current_theme() -> Theme {
    u8_to_theme(ACTIVE.load(Ordering::Relaxed))
}
pub fn current_palette() -> &'static Palette {
    current_theme().palette()
}

// ---------------------------------------------------------------- spacing

pub mod space {
    pub const XS: f32  = 4.0;
    pub const SM: f32  = 8.0;
    pub const MD: f32  = 12.0;
    pub const LG: f32  = 18.0;
    pub const XL: f32  = 24.0;
    pub const XXL: f32 = 32.0;
}

// ---------------------------------------------------------------- rounding

pub mod radius {
    use eframe::egui::Rounding;
    pub const PILL: Rounding   = Rounding::same(2.0);
    pub const INPUT: Rounding  = Rounding::same(3.0);
    pub const CARD: Rounding   = Rounding::same(4.0);
    pub const CHROME: Rounding = Rounding::same(6.0);
}

// ---------------------------------------------------------------- palette accessors

/// Widgets read colors through these functions, never through the consts
/// directly — that's what makes the theme switchable at runtime.
pub mod palette {
    use eframe::egui::Color32;
    use super::current_palette;

    pub fn bg_base()       -> Color32 { current_palette().bg_base }
    pub fn bg_chrome()     -> Color32 { current_palette().bg_chrome }
    pub fn bg_panel()      -> Color32 { current_palette().bg_panel }
    pub fn bg_panel_hi()   -> Color32 { current_palette().bg_panel_hi }
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

    pub fn accent_tint() -> Color32 { current_palette().accent_tint }
    pub fn danger_tint() -> Color32 { current_palette().danger_tint }

    /// Convenience: solid accent at the given alpha (0..=255).
    pub fn accent_alpha(alpha: u8) -> Color32 {
        let c = accent();
        // linear_multiply preserves hue while reducing intensity for overlay tints.
        let r = ((c.r() as u16 * alpha as u16) / 255) as u8;
        let g = ((c.g() as u16 * alpha as u16) / 255) as u8;
        let b = ((c.b() as u16 * alpha as u16) / 255) as u8;
        Color32::from_rgba_premultiplied(r, g, b, alpha)
    }
    pub fn danger_alpha(alpha: u8) -> Color32 {
        let c = danger();
        let r = ((c.r() as u16 * alpha as u16) / 255) as u8;
        let g = ((c.g() as u16 * alpha as u16) / 255) as u8;
        let b = ((c.b() as u16 * alpha as u16) / 255) as u8;
        Color32::from_rgba_premultiplied(r, g, b, alpha)
    }
    pub fn warn_alpha(alpha: u8) -> Color32 {
        let c = warn();
        let r = ((c.r() as u16 * alpha as u16) / 255) as u8;
        let g = ((c.g() as u16 * alpha as u16) / 255) as u8;
        let b = ((c.b() as u16 * alpha as u16) / 255) as u8;
        Color32::from_rgba_premultiplied(r, g, b, alpha)
    }
}

// ---------------------------------------------------------------- fonts

const FONT_INTER: &[u8]     = include_bytes!("../../assets/fonts/InterVariable.ttf");
const FONT_MONO: &[u8]      = include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf");
const FONT_MONO_BOLD: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Bold.ttf");

pub const FAMILY_MONO_BOLD: &str = "mono-bold";

// ---------------------------------------------------------------- install

/// Apply theme: persist active discriminant, install fonts + visuals.
/// Safe to call multiple times (e.g. on theme change).
pub fn install(ctx: &egui::Context, theme: Theme) {
    ACTIVE.store(theme_to_u8(theme), Ordering::Relaxed);
    install_fonts(ctx, theme);
    install_style(ctx, theme);
}

fn install_fonts(ctx: &egui::Context, theme: Theme) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert("inter".into(),    FontData::from_static(FONT_INTER));
    fonts.font_data.insert("jbm".into(),      FontData::from_static(FONT_MONO));
    fonts.font_data.insert("jbm-bold".into(), FontData::from_static(FONT_MONO_BOLD));

    // In Cyberpunk, swap Proportional family to mono so every text style
    // (heading/body/button/small) renders monospace without per-widget changes.
    let primary_proportional = if theme.mono_only() { "jbm" } else { "inter" };

    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, primary_proportional.into());

    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "jbm".into());

    fonts.families.insert(
        FontFamily::Name(FAMILY_MONO_BOLD.into()),
        vec!["jbm-bold".into()],
    );

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

    let mut text = std::collections::BTreeMap::new();
    text.insert(TextStyle::Heading,   FontId::new(15.0, FontFamily::Proportional));
    text.insert(TextStyle::Body,      FontId::new(13.0, FontFamily::Proportional));
    text.insert(TextStyle::Button,    FontId::new(12.0, FontFamily::Proportional));
    text.insert(TextStyle::Small,     FontId::new(11.0, FontFamily::Proportional));
    text.insert(TextStyle::Monospace, FontId::new(12.0, FontFamily::Monospace));
    style.text_styles = text;

    ctx.set_style(style);
}

// ---------------------------------------------------------------- font helpers

pub fn font_mono_bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(FAMILY_MONO_BOLD.into()))
}

pub fn font_mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

pub fn font_sans(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

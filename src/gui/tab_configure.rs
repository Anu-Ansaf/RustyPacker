use crate::gui::state::{AppState, Format, SideloadMode};
use crate::gui::theme::{palette, space};
use crate::gui::widgets::{
    card, description, field_row, ghost_button, input_readonly, meta_line, pill, section_header,
    segmented, warn_banner, PillKind,
};
use eframe::egui::{self, FontFamily, FontId, RichText};
use std::fs;
use std::path::PathBuf;

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            draw_shellcode(ui, state);
            ui.add_space(space::MD);
            draw_output(ui, state);
            ui.add_space(space::MD);
            if state.format == Format::DllSideload {
                draw_sideload(ui, state);
                ui.add_space(space::MD);
            }
            draw_encryption(ui, state);
            ui.add_space(space::MD);
            draw_injection(ui, state);
            ui.add_space(space::MD);
            draw_anti_debug(ui, state);
            ui.add_space(space::MD);
            draw_evasion(ui, state);

            if let Err(msg) = crate::gui::validate_state(state) {
                ui.add_space(space::SM);
                warn_banner(ui, &msg);
            }

            ui.add_space(space::LG);
        });
}

// ---------------------------------------------------------------- shellcode

fn draw_shellcode(ui: &mut egui::Ui, state: &mut AppState) {
    let size_suffix = state
        .shellcode_path
        .as_ref()
        .and_then(|p| fs::metadata(p).ok())
        .map(|m| format!("{} bytes", m.len()));
    section_header(ui, "Shellcode", size_suffix.as_deref());

    card(ui, |ui| {
        field_row(ui, "File", |ui| {
            let path_str = state
                .shellcode_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let avail = ui.available_width() - 110.0;
            input_readonly(ui, &path_str, avail.max(180.0));
            if ghost_button(ui, "Browse…").clicked() {
                if let Some(picked) = rfd::FileDialog::new()
                    .add_filter("Raw shellcode", &["bin", "raw"])
                    .pick_file()
                {
                    state.shellcode_path = Some(picked);
                }
            }
        });
        if state.shellcode_path.is_some() && size_suffix.is_some() {
            ui.add_space(4.0);
            meta_line(
                ui,
                &format!(
                    "{} loaded",
                    size_suffix.as_deref().unwrap_or("")
                ),
            );
        }
    });
}

// ---------------------------------------------------------------- output

fn draw_output(ui: &mut egui::Ui, state: &mut AppState) {
    section_header(ui, "Output", None);
    card(ui, |ui| {
        field_row(ui, "Format", |ui| {
            segmented(
                ui,
                &mut state.format,
                &[
                    (Format::Exe, "EXE"),
                    (Format::Dll, "DLL"),
                    (Format::DllSideload, "SIDELOAD"),
                ],
            );
        });
        ui.add_space(6.0);
        field_row(ui, "Save to", |ui| {
            let mut s = state
                .output_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let avail = ui.available_width() - 110.0;
            let resp = ui.add(
                egui::TextEdit::singleline(&mut s)
                    .desired_width(avail.max(180.0))
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .text_color(palette::text())
                    .margin(egui::vec2(space::SM, space::XS + 1.0)),
            );
            if resp.changed() {
                state.output_path = if s.trim().is_empty() {
                    None
                } else {
                    Some(s.into())
                };
            }
            if ghost_button(ui, "Browse…").clicked() {
                let default_name = match state.format {
                    Format::Exe => "out.exe",
                    Format::Dll | Format::DllSideload => "out.dll",
                };
                if let Some(picked) = rfd::FileDialog::new()
                    .set_file_name(default_name)
                    .save_file()
                {
                    state.output_path = Some(picked);
                }
            }
        });
    });
}

// ---------------------------------------------------------------- sideload

fn draw_sideload(ui: &mut egui::Ui, state: &mut AppState) {
    section_header(ui, "DLL Sideload", Some("self-injection only"));
    card(ui, |ui| {
        field_row(ui, "Target DLL", |ui| {
            let path_str = state
                .sideload
                .target_dll
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let avail = ui.available_width() - 110.0;
            input_readonly(ui, &path_str, avail.max(180.0));
            if ghost_button(ui, "Browse…").clicked() {
                if let Some(picked) = rfd::FileDialog::new()
                    .add_filter("DLL", &["dll", "DLL"])
                    .pick_file()
                {
                    state.sideload.target_dll = Some(picked);
                }
            }
        });

        ui.add_space(6.0);
        field_row(ui, "Hijack export", |ui| {
            let avail = ui.available_width();
            ui.add(
                egui::TextEdit::singleline(&mut state.sideload.hijack_export)
                    .desired_width(avail.min(320.0))
                    .hint_text("e.g. DllRegisterServer")
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .text_color(palette::text())
                    .margin(egui::vec2(space::SM, space::XS + 1.0)),
            );
        });

        ui.add_space(6.0);
        field_row(ui, "Mode", |ui| {
            segmented(
                ui,
                &mut state.sideload.mode,
                &[
                    (SideloadMode::Sideload, "SIDELOAD"),
                    (SideloadMode::Proxy, "PROXY"),
                ],
            );
        });

        match state.sideload.mode {
            SideloadMode::Sideload => {
                ui.add_space(6.0);
                description(
                    ui,
                    "Sideload — pure replacement DLL. No original loaded; all \
                     non-hijacked exports are no-op stubs. Drop alongside the \
                     vulnerable host app.",
                );
            }
            SideloadMode::Proxy => {
                ui.add_space(6.0);
                description(
                    ui,
                    "Proxy — non-hijacked exports forward to the original DLL via .def. \
                     Uses dyncvoke (git dep) + obfstr + lazy_static.",
                );
                ui.add_space(6.0);
                field_row(ui, "Path mode", |ui| {
                    ui.checkbox(
                        &mut state.sideload.use_absolute_path,
                        RichText::new("Use absolute target path (no rename needed)")
                            .font(crate::gui::theme::font_sans(11.0)),
                    );
                });
                if !state.sideload.use_absolute_path {
                    ui.add_space(6.0);
                    field_row(ui, "Renamed", |ui| {
                        let avail = ui.available_width();
                        ui.add(
                            egui::TextEdit::singleline(&mut state.sideload.renamed)
                                .desired_width(avail.min(320.0))
                                .hint_text("e.g. Shaping.dll")
                                .font(FontId::new(12.0, FontFamily::Monospace))
                                .text_color(palette::text())
                                .margin(egui::vec2(space::SM, space::XS + 1.0)),
                        );
                    });
                }
            }
        }

        if let Some(target) = &state.sideload.target_dll {
            ui.add_space(6.0);
            draw_exports_preview(ui, target);
        }
    });
}

fn draw_exports_preview(ui: &mut egui::Ui, target_dll: &PathBuf) {
    match crate::pe_parser::parse_exports(target_dll) {
        Ok(exports) => {
            let total = exports.len();
            let named = exports.iter().filter(|e| e.name.is_some()).count();
            meta_line(
                ui,
                &format!("{total} exports parsed ({named} named) from {}", target_dll.display()),
            );
        }
        Err(e) => {
            meta_line(ui, &format!("could not parse exports: {e}"));
        }
    }
}

// ---------------------------------------------------------------- encryption

fn draw_encryption(ui: &mut egui::Ui, state: &mut AppState) {
    use crate::techniques::{self, Category};
    let techniques: Vec<_> = techniques::by_category(Category::Encryption).collect();
    section_header(
        ui,
        "Encryption",
        Some(&format!("{} techniques", techniques.len())),
    );

    card(ui, |ui| {
        field_row(ui, "Method", |ui| {
            let selected_label = techniques
                .iter()
                .find(|t| t.meta().id == state.encryption_id)
                .map(|t| t.meta().display_name)
                .unwrap_or("(none)");
            let avail = ui.available_width();
            egui::ComboBox::from_id_source("encryption_combo")
                .selected_text(
                    RichText::new(selected_label)
                        .font(FontId::new(12.0, FontFamily::Proportional))
                        .color(palette::text()),
                )
                .width(avail - 4.0)
                .show_ui(ui, |ui| {
                    for t in &techniques {
                        ui.selectable_value(
                            &mut state.encryption_id,
                            t.meta().id.to_string(),
                            t.meta().display_name,
                        );
                    }
                });
        });
        if let Some(t) = techniques.iter().find(|t| t.meta().id == state.encryption_id) {
            ui.add_space(6.0);
            description(ui, t.meta().description);
            draw_params_for(ui, state, t.meta());
        }
    });
}

// ---------------------------------------------------------------- injection

#[derive(Clone, Copy, PartialEq, Eq)]
enum InjectionMode { SelfInject, Remote }

fn mode_of(tags: &[&'static str]) -> InjectionMode {
    if tags.iter().any(|t| *t == "self_injection") {
        InjectionMode::SelfInject
    } else {
        InjectionMode::Remote
    }
}

fn draw_injection(ui: &mut egui::Ui, state: &mut AppState) {
    use crate::techniques::{self, Category};
    let all: Vec<_> = techniques::by_category(Category::Injection).collect();

    let current_mode = techniques::find(&state.injection_id)
        .map(|t| mode_of(t.meta().tags))
        .unwrap_or(InjectionMode::Remote);
    let mut next_mode = current_mode;

    let filtered: Vec<_> = all
        .iter()
        .filter(|t| mode_of(t.meta().tags) == current_mode)
        .copied()
        .collect();

    section_header(
        ui,
        "Injection",
        Some(&format!("{} techniques", filtered.len())),
    );

    card(ui, |ui| {
        field_row(ui, "Mode", |ui| {
            segmented(
                ui,
                &mut next_mode,
                &[
                    (InjectionMode::SelfInject, "SELF"),
                    (InjectionMode::Remote, "REMOTE"),
                ],
            );
        });

        if next_mode != current_mode {
            if let Some(first) = all.iter().find(|t| mode_of(t.meta().tags) == next_mode) {
                state.injection_id = first.meta().id.to_string();
            }
        }

        ui.add_space(6.0);
        field_row(ui, "Template", |ui| {
            let selected_label = filtered
                .iter()
                .find(|t| t.meta().id == state.injection_id)
                .map(|t| t.meta().display_name)
                .unwrap_or("(none)");
            let avail = ui.available_width();
            egui::ComboBox::from_id_source("injection_combo")
                .selected_text(
                    RichText::new(selected_label)
                        .font(FontId::new(12.0, FontFamily::Proportional))
                        .color(palette::text()),
                )
                .width(avail - 4.0)
                .show_ui(ui, |ui| {
                    for t in &filtered {
                        ui.selectable_value(
                            &mut state.injection_id,
                            t.meta().id.to_string(),
                            t.meta().display_name,
                        );
                    }
                });
        });

        if let Some(t) = filtered.iter().find(|t| t.meta().id == state.injection_id) {
            // Tag pills, indented under the label column
            let extra_tags: Vec<&&str> = t
                .meta()
                .tags
                .iter()
                .filter(|tag| **tag != "self_injection" && **tag != "remote_injection")
                .collect();
            if !extra_tags.is_empty() {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(82.0); // align with field content column
                    for tag in extra_tags {
                        pill(ui, tag, pill_kind_for_tag(tag));
                        ui.add_space(4.0);
                    }
                });
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_space(82.0);
                description(ui, t.meta().description);
            });

            draw_params_for(ui, state, t.meta());
        }
    });
}

fn pill_kind_for_tag(tag: &str) -> PillKind {
    match tag {
        "remote_injection" => PillKind::Accent,
        "self_injection"   => PillKind::Accent,
        "syscall"          => PillKind::Warn,
        _                  => PillKind::Muted,
    }
}

// ---------------------------------------------------------------- anti-debug

fn draw_anti_debug(ui: &mut egui::Ui, state: &mut AppState) {
    use crate::techniques::{self, Category};
    let all: Vec<_> = techniques::by_category(Category::Evasion)
        .filter(|t| t.meta().tags.iter().any(|tag| *tag == "anti_debug"))
        .collect();
    let active = state.enabled_anti_debug.len();
    section_header(
        ui,
        "Anti-Debug",
        Some(&format!("{} active", active)),
    );
    card(ui, |ui| {
        row_builder(
            ui,
            &mut state.enabled_anti_debug,
            &mut state.params,
            &all,
            "ADD CHECK",
            "anti_debug_add_popup",
            "No anti-debug checks configured.",
        );
    });
}

// ---------------------------------------------------------------- evasion

fn draw_evasion(ui: &mut egui::Ui, state: &mut AppState) {
    use crate::techniques::{self, Category};
    let all: Vec<_> = techniques::by_category(Category::Evasion)
        .filter(|t| !t.meta().tags.iter().any(|tag| *tag == "anti_debug"))
        .collect();
    let active = state.enabled_evasions.len();
    section_header(
        ui,
        "Evasion",
        Some(&format!("{} active", active)),
    );
    card(ui, |ui| {
        row_builder(
            ui,
            &mut state.enabled_evasions,
            &mut state.params,
            &all,
            "ADD EVASION",
            "evasion_add_popup",
            "No evasion techniques configured.",
        );
    });
}

// ---------------------------------------------------------------- row-builder helper

fn row_builder(
    ui: &mut egui::Ui,
    selected: &mut Vec<String>,
    params: &mut std::collections::HashMap<String, String>,
    available: &[&'static dyn crate::techniques::Technique],
    add_label: &str,
    popup_id: &str,
    empty_hint: &str,
) {
    let mut remove_idx: Option<usize> = None;

    if selected.is_empty() {
        description(ui, empty_hint);
    } else {
        for (idx, id) in selected.iter().enumerate() {
            if idx > 0 {
                ui.add_space(8.0);
                let r = ui.max_rect();
                ui.painter().hline(
                    r.x_range(),
                    ui.cursor().top(),
                    egui::Stroke::new(1.0, palette::border()),
                );
                ui.add_space(8.0);
            }
            let Some(t) = available.iter().find(|t| t.meta().id == *id) else { continue; };
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(t.meta().display_name)
                        .font(crate::gui::theme::font_sans(12.5))
                        .color(palette::text())
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ghost_button(ui, "× Remove").clicked() {
                        remove_idx = Some(idx);
                    }
                });
            });
            ui.add_space(2.0);
            description(ui, t.meta().description);
            if !t.meta().params.is_empty() {
                ui.add_space(2.0);
                draw_params_into(ui, params, t.meta());
            }
        }
    }

    if let Some(i) = remove_idx {
        selected.remove(i);
    }

    // + Add button + popup
    ui.add_space(8.0);
    let any_available = available.iter().any(|t| !selected.iter().any(|s| s == t.meta().id));
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = format!("+ {}", add_label);
            let resp = if any_available {
                ghost_button(ui, &label)
            } else {
                // Greyed-out, non-interactive when nothing left to add
                let font = crate::gui::theme::font_sans(11.0);
                let galley = ui.painter().layout_no_wrap(label.clone(), font.clone(), palette::text_muted());
                let pad = egui::vec2(space::SM + 2.0, space::XS + 1.0);
                let size = galley.size() + egui::vec2(pad.x * 2.0, pad.y * 2.0);
                let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::hover());
                ui.painter().rect(
                    rect,
                    crate::gui::theme::radius::INPUT,
                    egui::Color32::TRANSPARENT,
                    egui::Stroke::new(1.0, palette::border()),
                );
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    label,
                    font,
                    palette::text_muted(),
                );
                resp
            };
            let pid = ui.make_persistent_id(popup_id);
            if any_available && resp.clicked() {
                ui.memory_mut(|m| m.toggle_popup(pid));
            }
            egui::popup::popup_below_widget(ui, pid, &resp, |ui| {
                ui.set_min_width(280.0);
                egui::Frame::none()
                    .fill(palette::bg_panel())
                    .stroke(egui::Stroke::new(1.0, palette::border_strong()))
                    .rounding(crate::gui::theme::radius::CARD)
                    .inner_margin(egui::Margin::same(4.0))
                    .show(ui, |ui| {
                        for t in available {
                            if selected.iter().any(|s| s == t.meta().id) { continue; }
                            let item = ui.add(egui::SelectableLabel::new(
                                false,
                                RichText::new(format!("  {}", t.meta().display_name))
                                    .font(crate::gui::theme::font_sans(12.0))
                                    .color(palette::text()),
                            ));
                            if item.clicked() {
                                selected.push(t.meta().id.to_string());
                                ui.memory_mut(|m| m.close_popup());
                            }
                        }
                    });
            });
        });
    });
}

// ---------------------------------------------------------------- shared params

fn draw_params_for(
    ui: &mut egui::Ui,
    state: &mut AppState,
    meta: &crate::techniques::TechniqueMeta,
) {
    draw_params_into(ui, &mut state.params, meta);
}

fn draw_params_into(
    ui: &mut egui::Ui,
    params: &mut std::collections::HashMap<String, String>,
    meta: &crate::techniques::TechniqueMeta,
) {
    use crate::techniques::ParamSpec;
    for spec in meta.params {
        ui.add_space(6.0);
        match spec {
            ParamSpec::Text {
                name,
                label,
                default,
            } => {
                let key = format!("{}.{}", meta.id, name);
                let value = params
                    .entry(key.clone())
                    .or_insert_with(|| default.to_string());
                field_row(ui, label, |ui| {
                    let avail = ui.available_width();
                    ui.add(
                        egui::TextEdit::singleline(value)
                            .desired_width(avail.min(320.0))
                            .font(FontId::new(12.0, FontFamily::Monospace))
                            .text_color(palette::text())
                            .margin(egui::vec2(space::SM, space::XS + 1.0)),
                    );
                });
            }
            ParamSpec::Bool {
                name,
                label,
                default,
            } => {
                let key = format!("{}.{}", meta.id, name);
                let mut on = params
                    .get(&key)
                    .map(|v| v == "true")
                    .unwrap_or(*default);
                if ui.checkbox(&mut on, *label).changed() {
                    params.insert(key, on.to_string());
                }
            }
            ParamSpec::Choice {
                name,
                label,
                options,
            } => {
                let key = format!("{}.{}", meta.id, name);
                let mut current = params
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| {
                        options.first().map(|s| s.to_string()).unwrap_or_default()
                    });
                field_row(ui, label, |ui| {
                    egui::ComboBox::from_id_source(&key)
                        .selected_text(&current)
                        .show_ui(ui, |ui| {
                            for opt in options.iter() {
                                ui.selectable_value(&mut current, opt.to_string(), *opt);
                            }
                        });
                });
                params.insert(key, current);
            }
        }
    }
}

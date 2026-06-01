use crate::gui::state::AppState;
use crate::gui::theme::{self, palette, space};
use crate::gui::widgets::{step_card, StepAccent, StepView};
use crate::techniques;
use eframe::egui::{self, RichText};

struct Step {
    title: String,
    pill: String,
    accent: StepAccent,
}

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            ui.label(
                RichText::new("Runtime execution path")
                    .font(theme::font_sans(16.0))
                    .color(palette::text())
                    .strong(),
            );
            ui.add_space(space::MD);

            for (idx, step) in compute_steps(state).iter().enumerate() {
                step_card(
                    ui,
                    &StepView {
                        idx: idx as u32 + 1,
                        title: &step.title,
                        pill_text: &step.pill,
                        accent: step.accent,
                    },
                );
                ui.add_space(space::XS + 2.0);
            }

            ui.add_space(space::MD);
        });
}

fn compute_steps(state: &AppState) -> Vec<Step> {
    let mut steps = Vec::new();

    steps.push(Step {
        title: "Loader starts".into(),
        pill: "ENTRY".into(),
        accent: StepAccent::Normal,
    });

    // Anti-debug checks run first — bail out before any heavier evasion.
    for id in &state.enabled_anti_debug {
        if let Some(t) = techniques::find(id) {
            steps.push(Step {
                title: t.meta().display_name.into(),
                pill: "ANTI-DEBUG".into(),
                accent: StepAccent::Danger,
            });
        }
    }

    for ev_id in &state.enabled_evasions {
        if let Some(t) = techniques::find(ev_id) {
            steps.push(Step {
                title: t.meta().display_name.into(),
                pill: "EVASION".into(),
                accent: StepAccent::Warn,
            });
        }
    }

    if let Some(enc) = techniques::find(&state.encryption_id) {
        steps.push(Step {
            title: format!("Decrypt via {}", enc.meta().id.to_uppercase()),
            pill: enc.meta().id.to_uppercase(),
            accent: StepAccent::Normal,
        });
    }

    if let Some(inj) = techniques::find(&state.injection_id) {
        let is_remote = inj.meta().tags.iter().any(|t| *t == "remote_injection");
        if is_remote {
            let target = state
                .params
                .get(&format!("{}.target_process", inj.meta().id))
                .cloned()
                .unwrap_or_else(|| "dllhost.exe".into());
            steps.push(Step {
                title: "Open target process".into(),
                pill: target,
                accent: StepAccent::Normal,
            });
        }

        steps.push(Step {
            title: "Allocate RW · Write · Reprotect RX".into(),
            pill: "RW → RX".into(),
            accent: StepAccent::Danger,
        });

        steps.push(Step {
            title: format!("Inject via {}", inj.meta().display_name),
            pill: pill_for_injection(inj.meta().id),
            accent: StepAccent::Normal,
        });
    }

    steps.push(Step {
        title: "Shellcode runs · C2 callback".into(),
        pill: "DETONATE".into(),
        accent: StepAccent::Danger,
    });

    steps
}

/// Long technique ids (e.g. "enum_calendar_info") look ugly when shouted.
/// Map them to a tighter pill label; fall back to the upper-case id.
fn pill_for_injection(id: &str) -> String {
    match id {
        "enum_calendar_info"   => "CALENDAR".into(),
        "enum_desktops"        => "DESKTOPS".into(),
        "enum_window_stations" => "WINSTA".into(),
        "enum_system_geo_id"   => "GEOID".into(),
        "cdef_folder_menu"     => "CDEFMENU".into(),
        "rtl_user_fiber_start" => "RTLFIBER".into(),
        other                  => other.to_uppercase(),
    }
}

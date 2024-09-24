#![deny(clippy::all)]
#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, RichText, Vec2, Window};
use tokio::runtime::Runtime;
use std::sync::{Arc, Mutex};
use std::thread;
use rfd::FileDialog;
use autct::autctactions::request_audit_verify;
use autct::config::AutctConfig;

struct AutctVerifierApp {
    autctcfg: Option<AutctConfig>,
    sigmessage: Option<String>,
    //not option because radio:
    network: String,
    // use mutexguards for these because
    // the file picker runs in a separate
    // thread:
    proof_file: Arc<Mutex<Option<String>>>,
    keyset_file: Arc<Mutex<Option<String>>>,
    show_verif_modal: bool,
    show_conn_modal: bool,
    is_verif_loading: bool,
    verif_result: Arc<Mutex<Option<String>>>,
    verif_runtime: Arc<Runtime>,
}

#[derive(Debug)]
struct CustomError(String);

#[tokio::main]
async fn main() -> eframe::Result {
    let mut myapp: AutctVerifierApp = AutctVerifierApp::default();
    myapp.try_load_autctcfg();
    eframe::run_native(
        "Bitcoin ownership auditor",
        eframe::NativeOptions::default(),
        Box::new(|_cc| Ok(Box::new(myapp))),
    )
}

impl AutctVerifierApp {
    fn try_load_autctcfg(&mut self) {
        match AutctConfig::build() {
            Ok(a) => {
                self.autctcfg = Some(a);
            }
            Err(e) => println!("Warning: failed to load config: {}", e),
        }
    }

    fn check_cfg_data(&self) -> Result<AutctConfig, CustomError> {
        let mut cfg = self.autctcfg
        .clone().ok_or_else(|| CustomError("Failed to load config".to_string()))?;
        cfg.proof_file_str = Some(self.proof_file
        .lock().unwrap().clone().ok_or_else(
            || CustomError("Failed to load proof file location".to_string()))?);
        let keyset_str = self.keyset_file
        .lock().unwrap().clone().ok_or_else(
        || CustomError("Failed to load keyset file location".to_string()))?;
        cfg.keysets = Some("mycontext".to_owned() + ":" + &keyset_str);
        cfg.user_string = Some(self.sigmessage
            .clone().ok_or_else(
            || CustomError("Failed to load signature message".to_string()))?);
        cfg.bc_network = Some(self.network.clone());
        Ok(cfg)
    }

    async fn verify(cfg: AutctConfig) -> String {
        let res = request_audit_verify(cfg).await;
        match res {
            Ok(x) => x,
            Err(e) => {
                println!("Verification attempt failed: {:?}", e);
                "Connection error".to_string()
            }
        }
    }

    fn spawn_verifier(&mut self, result: Arc<Mutex<Option<String>>>) {
        self.is_verif_loading = true;
        let result = Arc::clone(&result);
        let cfgclone = self.autctcfg.clone().unwrap();
        self.verif_runtime.spawn(async move {
            let res = AutctVerifierApp::verify(cfgclone).await;
            *result.lock().unwrap() = Some(res);
        });
    }
}

impl Default for AutctVerifierApp {
    fn default() -> Self {
        Self {
            autctcfg: None,
            sigmessage: None,
            network: "bitcoin".to_string(),
            proof_file: Arc::new(Mutex::new(None)),
            keyset_file: Arc::new(Mutex::new(None)),
            show_verif_modal: false,
            show_conn_modal: false,
            is_verif_loading: false,
            verif_result: Arc::new(Mutex::new(None)),
            verif_runtime: Arc::new(Runtime::new().unwrap()),
        }
    }
}

impl eframe::App for AutctVerifierApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Point of discussion: I think dark mode will work
        // a little better than light:
        //ctx.set_visuals(egui::Visuals::light());
        let available_height = ctx.available_rect().height();

        egui::TopBottomPanel::bottom("actionpanel")
            .min_height(available_height * 0.25)
            .show(ctx, |ui| {
                ui.set_enabled(!(
                    self.show_verif_modal || self.show_conn_modal));
                if ui.add_sized([200.0, 60.0],
                    egui::Button::new(RichText::new(
                        "VERIFY").size(30.0).strong())).clicked() {
                    let newcfg =
                    self.check_cfg_data();
                    if newcfg.is_err() {
                        self.show_verif_modal = true;
                    } else {
                        self.autctcfg = Some(newcfg.unwrap());
                        self.spawn_verifier(Arc::clone(
                            &self.verif_result));
                    }
                }
                let mut guard =
                self.verif_result.lock().unwrap();
                if let Some(ref mut res) = *guard {
                        if res == "Connection error" && !self.show_conn_modal {
                            self.show_conn_modal = true;
                        }
                        else {
                            // successfully received a verification response
                            // (where 'success' includes a failed verification)
                            ui.label(RichText::new(
                                res.clone()).size(24.0).strong());
                        }
                        if self.show_conn_modal {
                            Window::new("Connection error")
                            .collapsible(false)
                            .resizable(false)
                            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO) 
                            .show(ctx, |ui| {
                                ui.label("Failed to connect to the verification server.");
                                ui.add_space(30.0);
                                ui.label("Check the rpc host and port settings\
                                , and wait for the verification server to start up,\
                                which can take a few minutes for very large keyset files.");
                                ui.add_space(15.0);
                                if ui.button("Close").clicked() {
                                    self.show_conn_modal = false;
                                    // This allows us to delete the verification
                                    // result String, so that we don't
                                    // constantly reactivate this modal window
                                    // by detecting it:
                                    *guard = None;
                                }
                            });
                        }
                    }
            });
              egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.set_enabled(!(self.show_verif_modal || self.show_conn_modal));
                ui.label(RichText::new(
                    "Choose keyset (.pks) file:").size(28.0).strong());
                if ui.add_sized([150.0, 40.0],
                     egui::Button::new("Open File")).clicked() {
                    let selected_file = Arc::clone(&self.keyset_file);
                    thread::spawn(move || {
                        if let Some(path) = FileDialog::new().pick_file() {
                            let mut selected_file = selected_file.lock().unwrap();
                            *selected_file = Some(path.display().to_string());
                        }
                    });
                }

                if let Some(file) = &*self.keyset_file.lock().unwrap() {
                    ui.label(format!("Selected file: {}", file));
                }

                ui.label(RichText::new("Enter signature message:").size(28.0).strong());

                let mut temp_message = self.sigmessage.clone().unwrap_or_default();

                ui.add_sized([500.0, 40.0], egui::TextEdit::singleline(
                    &mut temp_message)
                    .hint_text("Enter signature message...")
                    .frame(true)
                    .desired_width(f32::INFINITY));
                    // TODO can't change textbox background but maybe change
                    // window background for contrast?:

                if temp_message.is_empty() {
                    self.sigmessage = None;
                } else {
                    self.sigmessage = Some(temp_message);
                }

                ui.label(RichText::new("Choose network:").size(28.0).strong());

                ui.radio_value(&mut self.network, "bitcoin".to_string(), "Bitcoin");
                ui.radio_value(&mut self.network, "signet".to_string(), "Signet");
                ui.radio_value(&mut self.network, "regtest".to_string(), "Regtest");

                ui.label(format!("Selected network: {:?}", self.network));

                ui.label(RichText::new("Choose proof file:").size(28.0).strong());
                if ui.add_sized([150.0, 40.0], egui::Button::new("Open File")).clicked() {
                    let selected_file = Arc::clone(&self.proof_file);
                    thread::spawn(move || {
                        if let Some(path) = FileDialog::new().pick_file() {
                            let mut selected_file = selected_file.lock().unwrap();
                            *selected_file = Some(path.display().to_string());
                        }
                    });
                }

                if let Some(file) = &*self.proof_file.lock().unwrap() {
                    ui.label(format!("Selected file: {}", file));
                }

                if self.show_verif_modal {
                    Window::new("Missing data")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO) 
                        .show(ctx, |ui| {
                            ui.label(RichText::new("Fill out these fields:").size(22.0).strong());
                            ui.add_space(30.0);
                            if self.sigmessage.is_none() {
                                ui.label("Signature message");
                            }
                            if self.proof_file.lock().unwrap().is_none() {
                                ui.label("Proof file location");
                            }
                            if self.keyset_file.lock().unwrap().is_none() {
                                ui.label("Keyset file location (*.pks)");
                            }
                            ui.add_space(15.0);
                            if ui.button("Close").clicked() {
                                self.show_verif_modal = false;
                            }
                        });
                }
            });
        });
    }
}

#![deny(clippy::all)]
#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, Ui, Pos2, RichText, Vec2, Window};
use tokio::runtime::Runtime;
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::time::Duration;
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
    server_state: Arc<Mutex<ServerState>>,
}

#[derive(Debug)]
struct CustomError(String);

#[derive(PartialEq, Clone, Copy)]
enum ServerState {
    NotStarted,
    Running,
    Ready,
}

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

    /// Starts the verification server in the background
    /// by calling std::process:Command
    fn start_server(&self) {
        let server_state = Arc::clone(
            &self.server_state);
        
        // Spawn a new thread to run the process
        thread::spawn(move || {
            {
                let mut state = server_state.lock().unwrap();
                *state = ServerState::Running;
            }

            // Simulate running the process
            // Replace this with the actual command,
            // `std::process::Command::new(
            // "./autct -k dummycontext:keysetfile -n network")`
            thread::sleep(Duration::from_secs(5));

            // Need some kind of hook to trigger this independently,
            // because the above process is a daemon not a batch process.
            {
                let mut state = server_state.lock().unwrap();
                *state = ServerState::Ready;
            }
        });
    }

    fn update_dot(&mut self, ctx: &egui::Context, dot_pos: &Pos2, dot_radius: f32) {
        // Determine the color of the dot based on the verification
        // server(called in the background)'s state:
        let process_state = *self.server_state.lock().unwrap();
        let dot_color = match process_state {
            ServerState::NotStarted => Color32::BLUE,
            ServerState::Running => Color32::YELLOW,
            ServerState::Ready => Color32::GREEN,
        };
        egui::Area::new("circle_area".into())
        .fixed_pos(*dot_pos)
        .show(ctx, |ui| {
        // Create an interactable area using `ui.allocate_response`
        let response = ui.allocate_response(
            Vec2::splat(dot_radius * 2.0),
            egui::Sense::click(),
        );

        // Draw the circle
        let painter = ui.painter();
        painter.circle_filled(*dot_pos, dot_radius, dot_color);

        // Handle click on the circle
        if response.clicked() && process_state == ServerState::NotStarted {
            println!("Circle clicked! Starting the process...");
            self.start_server();
        }
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
            server_state: Arc::new(Mutex::new(ServerState::NotStarted)),
        }
    }
}

impl eframe::App for AutctVerifierApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Point of discussion: I think dark mode will work
        // a little better than light:
        //ctx.set_visuals(egui::Visuals::light());

        // GUI does not respond to updates unless
        // user acts (e.g. mouse events), by default,
        // so force it:
        ctx.request_repaint();

        // Calculate the correct center and radius
        // for the dot, and its reaction area:
        let screen_rect = ctx.screen_rect();
        let dot_pos = Pos2::new(screen_rect.max.x - 20.0,
             screen_rect.max.y - 20.0);
        // This is very close to the edge?:
        let dot_radius = 15.0;
        self.update_dot(ctx, &dot_pos, dot_radius);

        // bottom section contains verification action and result.
        // use 25% of height:
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

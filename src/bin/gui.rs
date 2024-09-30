#![deny(clippy::all)]
#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, Pos2, RichText, Vec2, Window};
use tokio::runtime::Runtime;
use std::process::Stdio;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use tokio::time::Duration;
use rfd::FileDialog;
use autct::autctactions::{request_audit_verify, request_echo};
use autct::config::AutctConfig;

struct Wrapper {
    wrapped_app: Arc<RwLock<AutctVerifierApp>>,
}


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
    // These three booleans control the showing
    // of popups:
    show_verifres_modal: bool,
    show_conn_modal: bool,
    is_verif_loading: bool,
    // this allows accessing the response
    //from the RPC server across threads:
    verif_result: Arc<Mutex<Option<String>>>,
    // this remembers the last RPC response we saw:
    last_verif_result: Option<String>,
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
    // make a read-only copy of the app for the
    // monitoring thread:
    let mut myapp  = AutctVerifierApp::default();
    myapp.try_load_autctcfg();
    let myapplock = Arc::new(RwLock::new(myapp));
    let shared_myapplock = Arc::clone(&myapplock);

    thread::spawn(move || {
        loop {
            // the rpc requests are async but we
            // want to wait in this thread, so `block_on`:
            let lockres = shared_myapplock.try_read();
            if !lockres.is_err() {
                let app_for_reading = lockres.unwrap();
                // println-s here for now to sanity check the monitoring echo RPC
                // calls are behaving as expected:
                if !app_for_reading.autctcfg.is_none() {
                    println!("autctcfg was not none in the monitoring thread");
                    let rt = Runtime::new().unwrap();
                    let res = rt.block_on(
                        request_echo(&app_for_reading.autctcfg.as_ref().unwrap()));
                    println!("Request echo method returned");
                    match res {
                        Ok(_) => {println!("Echo successful");
                                let mut state = app_for_reading
                                .server_state.lock().unwrap();
                                *state = ServerState::Ready;
                                break;},
                    Err(_) => {println!("Echo call returned an error");}
                    } // end match
                } // end autctcfg none check
                else {
                    println!("in monitoring thread, autctcfg was none");
                }
            } // end check for lock
            // Sleep for 1 second before the next check
            thread::sleep(Duration::from_secs(1));
        } // end loop
    }); // end thread
    let wrapper = Wrapper{ wrapped_app: Arc::clone(&myapplock)};
    eframe::run_native(
        "Bitcoin ownership auditor",
        eframe::NativeOptions::default(),
        Box::new(|_cc| Ok(Box::new(wrapper))),
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
        println!("Starting check cfg data");
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
        println!("Finishing check cfg data ok");
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

    fn spawn_verifier(&mut self) {
        self.is_verif_loading = true;
        let result = Arc::clone(&self.verif_result);
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
        let keyset = self.autctcfg.clone().unwrap().keysets.unwrap();
        let network = self.autctcfg.clone().unwrap().bc_network.unwrap();    
        // Spawn a new thread to run the process
        thread::spawn(move || {

                let mut state = server_state.lock().unwrap();
                *state = ServerState::NotStarted;


            // Expected to take a while
            // TODO: expect just crashes; ideally want to show a prompt
            // that server startup failed with advice on how to fix it:
            std::process::Command::new(
                "./autct").arg("-k").arg(keyset).arg("-n").arg(
                network)
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .spawn().expect("Failed to start autct process in background.");
            // Running means the server is processing the data
            // but not yet serving on the port:
            *state = ServerState::Running;
        });
    }

    fn update_dot(&mut self, ctx: &egui::Context,
        dot_pos: &Pos2, dot_radius: f32) {
        // Determine the color of the dot based on the verification
        // server(called in the background)'s state:
        //println!("Got into update dot");
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
            show_verifres_modal: false,
            is_verif_loading: false,
            verif_result: Arc::new(Mutex::new(None)),
            last_verif_result: None,
            verif_runtime: Arc::new(Runtime::new().unwrap()),
            server_state: Arc::new(Mutex::new(ServerState::NotStarted)),
        }
    }
}

impl eframe::App for Wrapper {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Point of discussion: I think dark mode will work
        // a little better than light:
        //ctx.set_visuals(egui::Visuals::light());

        // GUI does not respond to updates unless
        // user acts (e.g. mouse events), by default,
        // so force it:
        ctx.request_repaint();

        // get handle to the wrapped object (which is the actual "app"):
        let mut state = self.wrapped_app.write().unwrap();
        // Calculate the correct center and radius
        // for the dot, and its reaction area:
        let screen_rect = ctx.screen_rect();
        let dot_pos = Pos2::new(screen_rect.max.x - 20.0,
             screen_rect.max.y - 20.0);
        // This is very close to the edge?:
        let dot_radius = 15.0;

        state.update_dot(ctx, &dot_pos, dot_radius);

        // bottom section of window contains verification action and result.
        let available_height = ctx.available_rect().height();
        egui::TopBottomPanel::bottom("actionpanel")
            .min_height(available_height * 0.25)
            .show(ctx, |ui| {
                ui.set_enabled(!(
                    state.show_verif_modal || state.show_conn_modal || state.show_verifres_modal));
                if ui.add_sized([200.0, 60.0],
                    egui::Button::new(RichText::new(
                        "VERIFY").size(30.0).strong())).clicked() {
                    let newcfg =
                    state.check_cfg_data();
                    if newcfg.is_err() {
                        state.show_verif_modal = true;
                    } else {
                        // if the settings in the GUI passed all
                        // sanity checks, we can update the config
                        // object and then run verification.
                        state.autctcfg = Some(newcfg.unwrap());
                        state.spawn_verifier();
                    }
                }
                // The mut 'guard' variable allows us to read
                // the verif_result string and then figure out if
                // we need to show the Connection error dialog.
                // we limit the scope of this mutable borrow:
                let mut need_conn_modal = false;
                let mut need_verifres_modal = false;
                let mut temp_lastverifres: Option<String> = None;
                {
                let mut guard =
                state.verif_result.lock().unwrap();
                if let Some(ref mut res) = *guard {
                        if res == "Connection error" && !state.show_conn_modal {
                            need_conn_modal = true;
                        }
                        else {
                            need_verifres_modal = true;
                            temp_lastverifres = Some(res.clone());
                        }
                }
                // This allows us to delete the verification
                // result String, so that we don't
                // constantly reactivate the connection error
                // modal window by detecting it:
                *guard = None;
                }
                // update the state with the temp vars
                // created while accessing the lock:
                if !temp_lastverifres.is_none() {
                    state.last_verif_result = temp_lastverifres.clone();
                }
                // these state vars are set to false when
                // the modal dialog "Close" is clicked.
                // We only want a one-way latch to set them 'true'
                // if the above code was executed:
                if need_conn_modal{
                    state.show_conn_modal = true;
                }
                if need_verifres_modal {
                    state.show_verifres_modal = true;
                }
                if state.show_verifres_modal {
                Window::new("Verification result")
                            .collapsible(false)
                            .resizable(false)
                            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO) 
                            .show(ctx, |ui| {
                                ui.label(RichText::new(
                                    state.last_verif_result.clone().unwrap()).size(24.0).strong());
                                ui.add_space(15.0);
                                if ui.button("Close").clicked() {
                                    state.show_verifres_modal = false;
                                }
                            });
                        }
                if state.show_conn_modal {
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
                                state.show_conn_modal = false;
                            }
                        });
                }
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                //println!("Starting the central panel paint");
                ui.set_enabled(!(state.show_verif_modal || state.show_conn_modal || state.show_verifres_modal));
                ui.label(RichText::new(
                    "Choose keyset (.pks) file:").size(28.0).strong());
                if ui.add_sized([150.0, 40.0],
                     egui::Button::new("Open File")).clicked() {
                    let selected_file = Arc::clone(&state.keyset_file);
                    thread::spawn(move || {
                        if let Some(path) = FileDialog::new().pick_file() {
                            let mut selected_file = selected_file.lock().unwrap();
                            *selected_file = Some(path.display().to_string());
                        }
                    });
                }

                if let Some(file) = &*state.keyset_file.lock().unwrap() {
                    ui.label(format!("Selected file: {}", file));
                }

                ui.label(RichText::new("Enter signature message:").size(28.0).strong());

                let mut temp_message = state.sigmessage.clone().unwrap_or_default();

                ui.add_sized([500.0, 40.0], egui::TextEdit::singleline(
                    &mut temp_message)
                    .hint_text("Enter signature message...")
                    .frame(true)
                    .desired_width(f32::INFINITY));
                    // TODO can't change textbox background but maybe change
                    // window background for contrast?:

                if temp_message.is_empty() {
                    state.sigmessage = None;
                } else {
                    state.sigmessage = Some(temp_message);
                }

                ui.label(RichText::new("Choose network:").size(28.0).strong());

                ui.radio_value(&mut state.network, "bitcoin".to_string(), "Bitcoin");
                ui.radio_value(&mut state.network, "signet".to_string(), "Signet");
                ui.radio_value(&mut state.network, "regtest".to_string(), "Regtest");

                ui.label(format!("Selected network: {:?}", state.network));

                ui.label(RichText::new("Choose proof file:").size(28.0).strong());
                if ui.add_sized([150.0, 40.0], egui::Button::new("Open File")).clicked() {
                    let selected_file = Arc::clone(&state.proof_file);
                    thread::spawn(move || {
                        if let Some(path) = FileDialog::new().pick_file() {
                            let mut selected_file = selected_file.lock().unwrap();
                            *selected_file = Some(path.display().to_string());
                        }
                    });
                }

                if let Some(file) = &*state.proof_file.lock().unwrap() {
                    ui.label(format!("Selected file: {}", file));
                }
                if state.show_verif_modal {
                    Window::new("Missing data")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO) 
                        .show(ctx, |ui| {
                            ui.label(RichText::new("Fill out these fields:").size(22.0).strong());
                            ui.add_space(30.0);
                            if state.sigmessage.is_none() {
                                ui.label("Signature message");
                            }
                            if state.proof_file.lock().unwrap().is_none() {
                                ui.label("Proof file location");
                            }
                            if state.keyset_file.lock().unwrap().is_none() {
                                ui.label("Keyset file location (*.pks)");
                            }
                            ui.add_space(15.0);
                            if ui.button("Close").clicked() {
                                state.show_verif_modal = false;
                            }
                        });
                }
            });
        });
    }
}

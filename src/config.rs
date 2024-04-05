use serde_derive::{Serialize, Deserialize};
use crate::utils;
use std::error::Error;
use std::path::PathBuf;
use clap::{Parser, CommandFactory, Command};

// This handles config items with syntax: "a:b, c:d,.."
fn get_params_from_config_string(params: String) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
    let pairs: Vec<String> = params.split(",").map(|s| s.to_string()).collect();
    let mut kss: Vec<String> = vec![];
    let mut cls: Vec<String> = vec![];
    for p in pairs {
        let mut kscl: Vec<String> = p.split(":").map(|s| s.to_string()).collect();
        // TODO this is where we can throw errors based on invalid user input,
        // so handle them:
        kss.push(kscl.pop().unwrap());
        cls.push(kscl.pop().unwrap());
    };
    Ok((cls, kss))
}

/*
The customized approach here is designed to allow:
command line arguments or options first,
OR
config file
OR
defaults.

The idea is to use confy for the serialization
to OS-agnostic config file,
and then clap to allow specification via the command line
(and generate help text).

The recipe for this is taken from:

https://stackoverflow.com/a/75981247
*/

#[derive(Parser, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[command(about, long_about = None, next_line_help = true)]
#[clap(version, about="Anonymous Usage Tokens from Curve Trees")]
pub struct AutctConfig {
    /// The argument `mode` is one of "prove", "serve", "request"
    #[arg(short('M'), long, required=true)]
    #[clap(verbatim_doc_comment)]
    pub mode: Option<String>,
    #[arg(short('V'), long, required=false)]
    pub version: Option<u8>,
    /// Enter a comma separated list, in this format:
    /// context:keysetname,context2:keysetname2,..
    /// Note: each context specifies the application context
    /// over which scarcity is enforced, each should
    /// be different. The keysetname specifies the file from
    /// which the CurveTree will be defined
    #[arg(short('k'), long, required=true)]
    #[clap(verbatim_doc_comment)]
    pub keysets: String,
    /// Intended as a BIP-340-hex encoding of a secp256k1 point,
    /// though anything is allowed:
    #[arg(short('u'), long, required=false)]
    #[clap(verbatim_doc_comment)]
    pub user_string: Option<String>,
    /// The depth of the curve tree, which
    /// must be even. The default 2 is recommended,
    /// but experimenting with 4 or higher is possible.
    #[arg(short('d'), long, required=false)]
    #[clap(verbatim_doc_comment)]
    pub depth: Option<i32>,
    /// Branching factor of the Curve Tree.
    /// Note that only 3 values are currently supported:
    /// 256, 512, 1024
    #[arg(short('b'), long, required=false)]
    #[clap(verbatim_doc_comment)]
    pub branching_factor: Option<i32>,
    // log-size of generator set used in Bulletproofs
    // TODO this can be calculated dynamically
    #[arg(short('g'), long, required=false)]
    pub generators_length_log_2: Option<u8>,
    // next 2 settings are RPC configuration
    #[arg(short('H'), long, required=false)]
    pub rpc_host: Option<String>,
    #[arg(short('p'), long, required=false)]
    pub rpc_port: Option<i32>,
    /// Print additional information in the terminal
    #[arg(short('v'), long, required = false)]
    verbose: Option<bool>,
    /// Only required for prover, destination
    /// file for the binary string which is the proof
    #[arg(short('P'), long, required = false)]
    #[clap(verbatim_doc_comment)]
    pub proof_file_str: Option<String>,
    // File containing hex-encoded 32 byte serialization
    // of private key
    #[arg(short('i'), long, required=false)]
    #[clap(verbatim_doc_comment)]
    pub privkey_file_str: Option<String>,
    /// filename suffix for keyimage files (there is
    /// a different file for every (app domain label,
    /// context label) pair).
    #[arg(long, required=false)]
    #[clap(verbatim_doc_comment)]
    pub keyimage_filename_suffix: Option<String>,
    /// Set this to true to output the proof as a base64
    /// string on stdout.
    #[arg(long, required=false)]
    #[clap(verbatim_doc_comment)]
    pub base64_proof: Option<bool>,
}

impl ::std::default::Default for AutctConfig {
    fn default() -> Self {
    let user_string = Some(std::str::from_utf8(utils::USER_STRING).unwrap().to_string());
    let context_label = std::str::from_utf8(utils::CONTEXT_LABEL).unwrap().to_string(); 
         Self {
    mode: Some("prove".to_string()),
    version: Some(0),
    keysets: context_label + ":default",
    user_string,
    depth: Some(2),
    branching_factor: Some(256), // currently not used, TODO
    generators_length_log_2: Some(11),
    rpc_host: Some("127.0.0.1".to_string()),
    rpc_port: Some(23333),
    verbose: Some(true),
    proof_file_str: Some("default-proof-file".to_string()),
    privkey_file_str: Some("privkey".to_string()),
    keyimage_filename_suffix: Some("keyimages".to_string()),
    base64_proof: Some(false),
 } }
}

impl AutctConfig {

    pub fn build() -> Result<Self, Box<dyn Error>> {
        let app: Command = AutctConfig::command();
        let app_name: &str = app.get_name();
        let args: AutctConfig = AutctConfig::parse()
        .get_config_file(app_name)?
        .set_config_file(app_name)?
        .print_config_file(app_name)?;
        Ok(args)
    }
    /// Get configuration file.
    /// A new configuration file is created with default values if none exists.
    fn get_config_file(mut self, app_name: &str) -> Result<Self, Box<dyn Error>> {

        let config_file: AutctConfig = confy::load(app_name, None)?;
        // derp:
        self.mode = self.mode.or(config_file.mode);
        self.version = self.version.or(config_file.version);
        //self.keysets = self.keysets.or(config_file.keysets);
        self.user_string = self.user_string.or(config_file.user_string);
        self.depth = self.depth.or(config_file.depth);
        self.branching_factor = self.branching_factor.or(config_file.branching_factor);
        self.generators_length_log_2 = self.generators_length_log_2.or(config_file.generators_length_log_2);
        self.rpc_host = self.rpc_host.or(config_file.rpc_host);
        self.rpc_port = self.rpc_port.or(config_file.rpc_port);
        self.proof_file_str = self.proof_file_str.or(config_file.proof_file_str);
        self.privkey_file_str = self.privkey_file_str.or(config_file.privkey_file_str);
        self.keyimage_filename_suffix = self.keyimage_filename_suffix.or(config_file.keyimage_filename_suffix);
        self.base64_proof = self.base64_proof.or(config_file.base64_proof);
        Ok(self)
    }

    /// Save changes made to a configuration object
    fn set_config_file(self, app_name: &str) -> Result<Self, Box<dyn Error>> {
        confy::store(app_name, None, self.clone())?;
        Ok(self)
    }

    /// Print configuration file path and its contents
    fn print_config_file (self, app_name: &str) -> Result<Self, Box<dyn Error>> {

        if self.verbose.unwrap_or(true) {

            let file_path: PathBuf = confy::get_configuration_file_path(app_name, None)?;
            println!("Configuration file: '{}'", file_path.display());

            let toml: String = toml::to_string_pretty(&self)?;
            println!("\t{}", toml.replace('\n', "\n\t"));
        }

        Ok(self)
    }

    pub fn get_context_labels_and_keysets(self) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
        get_params_from_config_string(self.keysets)
    }

}

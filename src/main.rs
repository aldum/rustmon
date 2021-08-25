use std::sync::mpsc::channel;
use std::time::Duration;

use colored::*;
use notify::watcher;

#[macro_use]
mod lib;

use rustmon::app_logic;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = app_logic::init();

    let config = app_logic::Config::from_matches(&matches)?;

    // setup file watching from notify
    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_secs(config.delay)).unwrap();

    // setup watches with above watcher
    app_logic::setup_watches(&mut watcher, &config)?;

    log!("Starting script {}", config.script.blue(); config.log_level > 0);
    Ok(app_logic::app_loop(rx, config)?)
}

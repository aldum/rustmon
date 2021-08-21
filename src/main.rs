use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::mpsc::channel;
use std::time::Duration;

use regex;
use regex::RegexSet;

use clap::{load_yaml, App, ArgMatches};
use colored::*;
use notify::{watcher, DebouncedEvent, RecursiveMode, Watcher};
use std::process;

// Add the blue rustmon prefix to log. Saves some typing and forgetting.
// Also can check whether a message should be logged based on a passed in expression.
macro_rules! log {
    ($($msg:expr),*; $check_level:expr) => {
        {
            if $check_level {
                let log_mess = format!($($msg),*);
                println!("{} {}", "[rustmon]".blue(), log_mess);
            }
        }
    };
    ($($msg:expr),*) => {
        {
            let log_mess = format!($($msg),*);
            println!("{} {}", "[rustmon]".blue(), log_mess);
        }
    };
}

// Format a message for the log without outputting it
macro_rules! log_format {
    ($($x:expr),*) => {
        {
            let log_mess = format!($($x),*);
            format!("{} {}", "[rustmon]".blue(), log_mess).as_str()
        }
    }
}

fn main() {
    // Setup app config from yaml file
    let yaml = load_yaml!("cli.yaml");
    let matches = App::from(yaml).get_matches();

    // Load the args into sensible variables
    let recursive_mode = match matches.is_present("recursive") {
        true => RecursiveMode::Recursive,
        false => RecursiveMode::NonRecursive,
    };
    let script = matches.value_of("SCRIPT").unwrap();
    let delay: u64 = matches.value_of_t("delay").unwrap_or(10);
    let exec = matches.value_of("exec");
    let log_level = matches.occurrences_of("verbose");

    let watches = extract_values_or_empty(&matches, "watch");
    let extensions = extract_values_or_empty(&matches, "extensions");
    let ignore_patterns = extract_values_or_empty(&matches, "ignore_patterns");

    // create a regex set from the provided regular expressions
    let ignore_regex = match RegexSet::new(ignore_patterns) {
        Ok(set) => set,
        Err(e) => match e {
            regex::Error::Syntax(m) => {
                log!("Ignore Patterns Error (below)\n{}", m.as_str().red());
                process::exit(1);
            }
            regex::Error::CompiledTooBig(m) => {
                log!(
                    "Ignore Patterns Error: {} Max size is {}",
                    "Compiled regex set is too big.".red(),
                    m
                );
                process::exit(1);
            }
            _ => {
                log!(
                    "{}: An unknown error has occurred with the regular expressions",
                    "Ignore Patterns Error Error".red()
                );
                process::exit(1);
            }
        },
    };

    // setup file watching from notify
    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_secs(delay)).unwrap();

    // We always want to watch the main script for changes, so that gets added outside of
    // the loop below.
    watcher.watch(script, recursive_mode).expect(
        log_format!(
            "Exiting: {} {}",
            // "[rustmon]".blue(),
            "Failed to watch path".red(),
            script.red()
        ),
    );

    // Watch each path provided by the user
    for watch_path in watches {
        watcher.watch(watch_path, recursive_mode).expect(
            log_format!(
                "Exiting: {} {}",
                "Failed to watch path".red(),
                watch_path.red()
            ),
        )
    }

    log!("Starting script {}", script.blue(); log_level > 0);

    let mut child = run_command(exec, script);

    loop {
        match rx.recv() {
            Ok(event) => match event {
                DebouncedEvent::Create(p)
                | DebouncedEvent::Write(p)
                | DebouncedEvent::Remove(p)
                | DebouncedEvent::Rename(_, p) => {
                    if should_restart_process(&p, script, &extensions, &ignore_regex, log_level) {
                        // Kill the process and run it again.
                        child.kill().expect("Failed to kill process");
                        child = run_command(exec, script);

                        log!(
                            "{} changed, restarting",
                            p.to_str().unwrap().green();
                            log_level > 0
                        );
                    }
                }
                _ => {}
            },
            Err(e) => log!("watch error: {:?}", e),
        }
    }
}

// Run the provided script either using the provided executable binary
// or directly.
fn run_command(exec: Option<&str>, script: &str) -> Child {
    let command = match exec {
        Some(bin) => Command::new(bin).arg(script).spawn(),
        None => Command::new(script).spawn(),
    };
    command.expect(log_format!("Failed to execute command {} {}", exec.unwrap_or(""), script))
}

// Extracts values from arguments that can take multiple values or returns an empty vec.
fn extract_values_or_empty<'a>(matches: &'a ArgMatches, field: &str) -> Vec<&'a str> {
    match matches.values_of(field) {
        Some(values) => values.collect(),
        None => vec![],
    }
}

// Checks all the possibilities to prevent the script from restarting and
// returns a bool.
fn should_restart_process(
    p: &PathBuf,
    script: &str,
    extensions: &Vec<&str>,
    ignore_regex: &RegexSet,
    log_level: u64,
) -> bool {
    // If the path matches the script file, we can skip the extensions and ignore guards.
    if p.file_name().unwrap() == PathBuf::from(script).file_name().unwrap() {
        log!("Restarting for main script change"; log_level > 1);
        return true;
    }

    // Check if the path matches extensions provided by the user (if applicable)
    if !extensions.is_empty() {
        match p.extension() {
            Some(ext) => {
                if !extensions.contains(&ext.to_str().unwrap()) {
                    log!(
                        "Extension did not match on {}, not restarting",
                        p.to_str().unwrap().red();
                        log_level > 2
                    );
                    return false;
                }
            }
            None => {
                log!(
                    "Could not get file extension for {}, not restarting",
                    p.to_str().unwrap().red();
                    log_level > 2
                );
                return false;
            }
        }
    }

    // If a file matches any of our ignore regexes, skip execution of
    // the rest of the script.
    if !ignore_regex.is_empty() {
        if ignore_regex.is_match(p.to_str().unwrap()) {
            log!(
                "{} is ignored, not restarting",
                p.to_str().unwrap().red();
                log_level > 2
            );
            return false;
        }
    }
    log!("File changed in watched path"; log_level > 1);
    true
}

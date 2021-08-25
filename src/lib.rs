/// Add the blue rustmon prefix to log. Saves some typing and forgetting.
/// Also can check whether a message should be logged based on a passed in expression.
#[macro_export]
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

/// Format a message for the log without outputting it
#[macro_export]
macro_rules! log_format {
    ($($x:expr),*) => {
        {
            let log_mess = format!($($x),*);
            format!("{} {}", "[rustmon]".blue(), log_mess).as_str()
        }
    }
}

#[allow(dead_code)]
pub mod app_logic {
    use clap::{load_yaml, App, ArgMatches};
    use colored::*;
    use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
    use regex::RegexSet;
    use std::error::Error;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::sync::mpsc::Receiver;

    /// Basically a wrapper around ArgMatches that makes the values I care about
    /// a little more accessible
    #[derive(Clone, Debug)]
    pub struct Config<'a> {
        pub script: &'a str,
        pub recursive_mode: RecursiveMode,
        pub delay: u64,
        pub exec: Option<&'a str>,
        pub log_level: u64,
        pub watches: Vec<&'a str>,
        pub extensions: Vec<&'a str>,
        pub ignore_regex: RegexSet,
    }

    impl<'a> Config<'a> {
        /// Save the app config by parsing the match arguments from the clap app
        pub fn from_matches(matches: &'a ArgMatches) -> Result<Self, Box<dyn Error>> {
            // Get the ignore patterns first so they can be passed into the regex set
            let ignore_patterns = extract_values_or_empty(&matches, "ignore_patterns");
            let ignore_regex = match RegexSet::new(ignore_patterns) {
                Ok(set) => set,
                Err(e) => {
                    log!("Ignore Patterns Error (below)");
                    return Err(Box::new(e));
                }
            };
            Ok(Self {
                script: matches.value_of("SCRIPT").unwrap(),
                recursive_mode: if matches.is_present("recursive") {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                },
                delay: matches.value_of_t("delay").unwrap_or(10),
                exec: matches.value_of("exec"),
                log_level: matches.occurrences_of("verbose"),
                watches: extract_values_or_empty(&matches, "watches"),
                extensions: extract_values_or_empty(&matches, "extensions"),
                ignore_regex,
            })
        }
    }

    /// Checks all the possibilities to prevent the script from restarting and
    /// returns a bool.
    pub fn should_restart_process(p: &PathBuf, config: &Config) -> bool {
        // If the path matches the script file, we can skip the extensions and ignore guards.
        if p.file_name().unwrap() == PathBuf::from(config.script).file_name().unwrap() {
            log!("Restarting for main script change"; config.log_level > 1);
            return true;
        }

        // Check if the path matches extensions provided by the user (if applicable)
        if !config.extensions.is_empty() {
            match p.extension() {
                Some(ext) => {
                    if !config.extensions.contains(&ext.to_str().unwrap()) {
                        log!(
                            "Extension did not match on {}, not restarting",
                            p.to_str().unwrap().red();
                            config.log_level > 2
                        );
                        return false;
                    }
                }
                None => {
                    log!(
                        "Could not get file extension for {}, not restarting",
                        p.to_str().unwrap().red();
                        config.log_level > 2
                    );
                    return false;
                }
            }
        }

        // If a file matches any of our ignore regexes, skip execution of
        // the rest of the script.
        if !config.ignore_regex.is_empty() {
            if config.ignore_regex.is_match(p.to_str().unwrap()) {
                log!(
                    "{} is ignored, not restarting",
                    p.to_str().unwrap().red();
                    config.log_level > 2
                );
                return false;
            }
        }
        log!("File changed in watched path"; config.log_level > 1);
        true
    }

    /// Extracts values from arguments that can take multiple values or returns an empty vec.
    pub fn extract_values_or_empty<'a>(
        matches: &'a ArgMatches,
        field: &'static str,
    ) -> Vec<&'a str> {
        match matches.values_of(field) {
            Some(values) => values.collect(),
            None => vec![],
        }
    }

    /// Run the provided script either using the provided executable binary
    /// or directly.
    pub fn run_command(config: &Config) -> Result<Child, std::io::Error> {
        match config.exec {
            Some(bin) => Command::new(bin).arg(config.script).spawn(),
            None => Command::new(config.script).spawn(),
        }
    }

    /// Creates the clap app and get arg matches
    pub fn init() -> ArgMatches {
        let yaml = load_yaml!("cli.yaml");
        App::from(yaml).get_matches()
    }

    fn log_and_return_watch_failure(path: &str, e: notify::Error) -> Result<(), notify::Error> {
        log!("Exiting: {} {}", "Failed to watch path".red(), path.red());
        Err(e)
    }

    /// Setup watches from the configuration and return the channel
    pub fn setup_watches(
        app_watcher: &mut RecommendedWatcher,
        config: &Config,
    ) -> Result<(), notify::Error> {
        // We always want to watch the main script for changes, so that gets added outside of
        // the loop below.
        log!("Watching {}", config.script.green(); config.log_level > 2);
        match app_watcher.watch(config.script, config.recursive_mode) {
            Ok(_) => (),
            Err(e) => return log_and_return_watch_failure(config.script, e),
        }
        // Watch each path provided by the user
        for watch_path in config.watches.clone() {
            log!("Watching {}", watch_path.green(); config.log_level > 2);
            match app_watcher.watch(watch_path, config.recursive_mode) {
                Ok(_) => (),
                Err(e) => return log_and_return_watch_failure(watch_path, e),
            }
        }
        Ok(())
    }

    /// This is the main loop for the app. It makes it much easier to test.
    pub fn app_loop(rx: Receiver<DebouncedEvent>, config: Config) -> Result<(), Box<dyn Error>> {
        log!("Starting script {}", config.script.blue(); config.log_level > 0);

        let mut child = match run_command(&config) {
            Ok(c) => c,
            Err(e) => {
                log!(
                    "Failed to execute command {} {}",
                    config.exec.unwrap_or("").red(),
                    config.script.red()
                );
                return Err(Box::new(e));
            }
        };

        loop {
            match rx.recv() {
                Ok(event) => match event {
                    DebouncedEvent::Create(p)
                    | DebouncedEvent::Write(p)
                    | DebouncedEvent::Remove(p)
                    | DebouncedEvent::Rename(_, p) => {
                        if should_restart_process(&p, &config) {
                            // Kill the process and run it again.
                            child.kill().expect("Failed to kill process");
                            child = match run_command(&config) {
                                Ok(c) => c,
                                Err(e) => {
                                    log!(
                                        "Failed to re-execute command {} {}",
                                        config.exec.unwrap_or(""),
                                        config.script
                                    );
                                    return Err(Box::new(e));
                                }
                            };

                            log!(
                                "{} changed, restarting",
                                p.to_str().unwrap().green();
                                config.log_level > 0
                            );
                        }
                    }
                    _ => {}
                },
                Err(e) => {
                    log!("watch error: {:?}", e);
                    return Err(Box::new(e));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::{load_yaml, App, Arg};
    use notify::{watcher, RecursiveMode, Watcher};
    use regex::RegexSet;

    use crate::app_logic::{
        extract_values_or_empty, run_command, setup_watches, should_restart_process, Config,
    };
    use std::error::Error;
    use std::fs::File;
    use std::io::Write;
    use std::sync::mpsc::channel;
    use std::time::Duration;
    use tempfile;

    pub trait Testing {
        fn fake_default() -> Self;
        fn with_script(self, script: &'static str) -> Self;
        fn with_ignores(self, ignore_patterns: &[&str]) -> Self;
        fn with_extensions(self, extensions: &[&'static str]) -> Self;
        fn with_exec(self, exec: &'static str) -> Self;
    }

    impl<'a> Testing for Config<'a> {
        fn fake_default() -> Self {
            Self {
                script: "/tmp/test.py",
                recursive_mode: RecursiveMode::Recursive,
                delay: 1,
                exec: None,
                log_level: 0,
                watches: vec![],
                extensions: vec![],
                ignore_regex: RegexSet::new(Vec::<&str>::new()).unwrap(),
            }
        }
        fn with_script(self, script: &'a str) -> Self {
            Self { script, ..self }
        }
        fn with_ignores(self, ignore_patterns: &[&str]) -> Self {
            Self {
                ignore_regex: RegexSet::new(ignore_patterns).expect("Invalid Regex"),
                ..self
            }
        }
        fn with_extensions(self, extensions: &[&'a str]) -> Self {
            Self {
                extensions: Vec::from(extensions),
                ..self
            }
        }
        fn with_exec(self, exec: &'a str) -> Self {
            Self {
                exec: Some(exec),
                ..self
            }
        }
    }

    #[test]
    fn test_path_is_script() {
        let test_config = Config::fake_default();
        assert!(should_restart_process(
            &PathBuf::from(test_config.script),
            &test_config
        ));
    }

    #[test]
    fn test_script_restarts_even_if_ignore_all() {
        let test_config = Config::fake_default().with_ignores(&[".*"]);
        assert!(should_restart_process(
            &PathBuf::from(test_config.script),
            &test_config
        ));
    }

    #[test]
    fn test_script_restarts_even_unmatched_extension() {
        let test_config = Config::fake_default()
            .with_script("/test/other.js")
            .with_extensions(&["py"]);
        assert!(should_restart_process(
            &PathBuf::from(test_config.script),
            &test_config
        ));
    }

    #[test]
    fn test_restarts_on_any_path_if_no_includes_excludes() {
        let test_config = Config::fake_default();
        assert!(should_restart_process(
            &PathBuf::from("/home/test/hello.html"),
            &test_config
        ));
    }

    #[test]
    fn test_restarts_on_included_extension() {
        let test_config = Config::fake_default().with_extensions(&["py"]);
        assert!(should_restart_process(
            &PathBuf::from("test.py"),
            &test_config
        ));
    }

    #[test]
    fn test_restarts_with_multiple_extensions() {
        let test_config = Config::fake_default().with_extensions(&["py", "html"]);
        assert!(should_restart_process(
            &PathBuf::from("/home/index.html"),
            &test_config
        ));
    }

    #[test]
    fn test_no_restart_on_wrong_extension() {
        let test_config = Config::fake_default().with_extensions(&["py"]);
        assert!(!should_restart_process(
            &PathBuf::from("/test/doesntRestart.html"),
            &test_config
        ));
    }

    #[test]
    fn test_no_restart_on_wrong_extension_multiple_extensions() {
        let test_config = Config::fake_default().with_extensions(&["py", "html"]);
        assert!(!should_restart_process(
            &PathBuf::from("/test/doesntRestart.js"),
            &test_config
        ));
    }

    #[test]
    fn test_no_restart_on_no_extension() {
        let test_config = Config::fake_default().with_extensions(&["py", "html"]);
        assert!(!should_restart_process(
            &PathBuf::from("/test/noExtension"),
            &test_config
        ));
    }

    #[test]
    fn test_ignored_file_no_restart() {
        let test_config = Config::fake_default().with_ignores(&["target/.*"]);
        assert!(!should_restart_process(
            &PathBuf::from("/test/target/release/binary"),
            &test_config
        ));
    }

    #[test]
    fn test_ignored_file_no_restart_multiple() {
        let test_config = Config::fake_default().with_ignores(&["target/.*", ".*~"]);
        assert!(!should_restart_process(
            &PathBuf::from("/test/main.py~"),
            &test_config
        ));
    }

    #[test]
    fn test_extract_with_values() {
        let fake_app = App::new("Fake Program").arg(
            Arg::new("test")
                .short('t')
                .takes_value(true)
                .multiple_values(true),
        );
        // We're sort of testing external functionality here, but we need the ArgMatches
        // and this is teh easiest way to get it.
        let matches = fake_app.get_matches_from(["program", "-t", "test1", "test2", "test3"]);
        let result = extract_values_or_empty(&matches, "test");
        assert_eq!(result, vec!["test1", "test2", "test3"]);
    }

    #[test]
    fn test_extract_with_no_values() {
        let fake_app = App::new("Fake Program").arg(
            Arg::new("test")
                .short('t')
                .takes_value(true)
                .multiple_values(true),
        );
        // We're sort of testing external functionality here, but we need the ArgMatches
        // and this is teh easiest way to get it.
        let matches = fake_app.get_matches_from(["program"]);
        let result = extract_values_or_empty(&matches, "test");
        assert!(result.is_empty());
    }

    #[test]
    fn test_run_valid_command() {
        let test_config = Config::fake_default().with_script("cargo");
        match run_command(&test_config) {
            Ok(mut c) => c.kill().expect("No process to kill"),
            Err(_) => panic!("Should have returned a child"),
        }
    }

    #[test]
    fn test_run_command_with_exec() {
        let test_config = Config::fake_default()
            .with_script("search")
            .with_exec("cargo");
        match run_command(&test_config) {
            Ok(mut c) => c.kill().expect("No process to kill"),
            Err(_) => panic!("Should have returned a child"),
        }
    }

    #[test]
    fn test_run_invalid_script() {
        let test_config = Config::fake_default().with_script("123456");
        match run_command(&test_config) {
            Ok(_) => panic!("Should have returned an error for invalid script"),
            Err(_) => (),
        }
    }

    #[test]
    fn test_run_invalid_exec() {
        let test_config = Config::fake_default().with_exec("123456");
        match run_command(&test_config) {
            Ok(_) => panic!("Should have returned an error for invalid exec"),
            Err(_) => (),
        }
    }

    #[test]
    fn test_config_from_matches_minimal() {
        // Sort of half integration test, half unit test.
        let yaml = load_yaml!("cli.yaml");
        let fake_app = App::from(yaml);
        let fake_matches = fake_app.get_matches_from(["rustmon", "/tmp/test.py"]);
        let test_config = Config::from_matches(&fake_matches).expect("Should produce valid config");

        // This ensures that if I change the default config (intentionally or otherwise),
        // I have to change a test to match. This commend will remind me to update the
        // help and docs!
        assert_eq!(test_config.script, "/tmp/test.py");
        assert_eq!(test_config.recursive_mode, RecursiveMode::NonRecursive);
        assert_eq!(test_config.delay, 10);
        assert!(test_config.exec.is_none());
        assert_eq!(test_config.log_level, 0);
        assert!(test_config.watches.is_empty());
        assert!(test_config.extensions.is_empty());
        assert!(test_config.ignore_regex.patterns().is_empty());
    }

    #[test]
    fn test_config_from_matches_complete() {
        let yaml = load_yaml!("cli.yaml");
        let fake_app = App::from(yaml);
        let fake_matches = fake_app.get_matches_from([
            "rustmon",
            "-e",
            "py",
            "-r",
            "-w",
            "/tmp/test_project",
            "-x",
            "/usr/local/bin/python",
            "-d",
            "15",
            "-i",
            ".*\\.html",
            "-v",
            "/tmp/test_project/main.py",
        ]);

        let test_config = Config::from_matches(&fake_matches).expect("Should be valid config");

        assert_eq!(test_config.script, "/tmp/test_project/main.py");
        assert_eq!(test_config.recursive_mode, RecursiveMode::Recursive);
        assert_eq!(test_config.delay, 15);
        assert_eq!(
            test_config.exec.expect("Should have exec value set"),
            "/usr/local/bin/python"
        );
        assert_eq!(test_config.log_level, 1);
        assert_eq!(test_config.watches.len(), 1);
        assert!(test_config.watches.contains(&"/tmp/test_project"));
        assert_eq!(test_config.extensions.len(), 1);
        assert!(test_config.extensions.contains(&"py"));
        assert_eq!(test_config.ignore_regex.patterns().len(), 1);
        assert!(test_config
            .ignore_regex
            .patterns()
            .contains(&".*\\.html".to_string()));
    }

    #[test]
    fn test_config_sets_log_level_correctly() {
        let yaml = load_yaml!("cli.yaml");
        let fake_app0 = App::from(yaml);
        let fake_app1 = App::from(yaml);
        let fake_app2 = App::from(yaml);
        let fake_app3 = App::from(yaml);

        let matches0 = fake_app0.get_matches_from(["rustmon", "/tmp/test.py"]);
        let matches1 = fake_app1.get_matches_from(["rustmon", "-v", "/tmp/test.py"]);
        let matches2 = fake_app2.get_matches_from(["rustmon", "-vv", "/tmp/test.py"]);
        let matches3 = fake_app3.get_matches_from(["rustmon", "-vvv", "/tmp/test.py"]);

        let test_config0 = Config::from_matches(&matches0).expect("Should have valid config");
        let test_config1 = Config::from_matches(&matches1).expect("Should have valid config");
        let test_config2 = Config::from_matches(&matches2).expect("Should have valid config");
        let test_config3 = Config::from_matches(&matches3).expect("Should have valid config");

        assert_eq!(test_config0.log_level, 0);
        assert_eq!(test_config1.log_level, 1);
        assert_eq!(test_config2.log_level, 2);
        assert_eq!(test_config3.log_level, 3);
    }

    #[test]
    fn test_config_from_multiple_values() {
        let yaml = load_yaml!("cli.yaml");
        let fake_app = App::from(yaml);
        let fake_matches = fake_app.get_matches_from([
            "rustmon",
            "-e",
            "py,html,js",
            "-w",
            "/tmp/test_project,/tmp/test_project_files",
            "-i",
            ".*\\.html,target,build/.*,__pycache__",
            "/tmp/test_project/main.py",
        ]);

        let test_config = Config::from_matches(&fake_matches).expect("Should be valid config");

        assert_eq!(test_config.watches.len(), 2);
        assert!(test_config.watches.contains(&"/tmp/test_project"));
        assert!(test_config.watches.contains(&"/tmp/test_project_files"));

        assert_eq!(test_config.extensions.len(), 3);
        assert!(test_config.extensions.contains(&"py"));
        assert!(test_config.extensions.contains(&"html"));
        assert!(test_config.extensions.contains(&"js"));

        assert_eq!(test_config.ignore_regex.patterns().len(), 4);
        assert!(test_config
            .ignore_regex
            .patterns()
            .contains(&".*\\.html".to_string()));
        assert!(test_config
            .ignore_regex
            .patterns()
            .contains(&"target".to_string()));
        assert!(test_config
            .ignore_regex
            .patterns()
            .contains(&"build/.*".to_string()));
        assert!(test_config
            .ignore_regex
            .patterns()
            .contains(&"__pycache__".to_string()));
    }

    #[test]
    fn test_config_invalid_ignore_patterns() {
        let yaml = load_yaml!("cli.yaml");
        let fake_app = App::from(yaml);
        let fake_matches =
            fake_app.get_matches_from(["rustmon", "-i", "*/test", "/tmp/test_project/main.py"]);
        match Config::from_matches(&fake_matches) {
            Ok(_) => panic!("Should produce an error for invalid regex pattern"),
            Err(_) => (),
        }
    }

    #[test]
    fn test_setup_watches_only_script() -> Result<(), Box<dyn Error>> {
        let watch_dir = tempfile::tempdir()?;
        let script_path = watch_dir.path().join("test.py");
        let mut script_file = File::create(&script_path)?;
        writeln!(script_file, "This is a fake script")?;

        let mut test_config = Config::fake_default();
        test_config.script = script_path.to_str().unwrap();

        let (tx, _rx) = channel();
        let mut test_watcher = watcher(tx, Duration::from_secs(10)).unwrap();
        setup_watches(&mut test_watcher, &test_config)?;
        // If it has correctly watched the path, it should be able to unwatch it. Wish
        // I could check the paths directly, but it's private.
        test_watcher.unwatch(test_config.script)?;
        Ok(())
    }

    #[test]
    fn test_setup_watches_with_watches() -> Result<(), Box<dyn Error>> {
        let watch_dir = tempfile::tempdir()?;
        let watch_dir2 = tempfile::tempdir()?;
        let script_path = watch_dir.path().join("test.py");
        let mut script_file = File::create(&script_path)?;
        writeln!(script_file, "This is a fake script")?;

        let mut test_config = Config::fake_default();
        test_config.script = script_path.to_str().unwrap();
        test_config.watches = vec![
            watch_dir.path().to_str().unwrap(),
            watch_dir2.path().to_str().unwrap(),
        ];

        let (tx, _rx) = channel();
        let mut test_watcher = watcher(tx, Duration::from_secs(10)).unwrap();
        setup_watches(&mut test_watcher, &test_config)?;
        // If it has correctly watched the path, it should be able to unwatch it. Wish
        // I could check the paths directly, but it's private.
        test_watcher.unwatch(test_config.script)?;
        test_watcher.unwatch(watch_dir.path().to_str().unwrap())?;
        test_watcher.unwatch(watch_dir2.path().to_str().unwrap())?;
        Ok(())
    }

    #[test]
    fn test_setup_watches_invalid_script() {
        let test_config = Config::fake_default().with_script("/nonexistent/path/to/nothing.py");

        let (tx, _rx) = channel();
        let mut test_watcher = watcher(tx, Duration::from_secs(10)).unwrap();

        match setup_watches(&mut test_watcher, &test_config) {
            Ok(_) => panic!("This should have failed with an error"),
            Err(_) => (),
        };
    }

    #[test]
    fn test_setup_watches_invalid_watch_path() {
        let mut test_config = Config::fake_default();
        test_config.watches = vec!["/this/path/doesnt/exist"];
        let (tx, _rx) = channel();
        let mut test_watcher = watcher(tx, Duration::from_secs(10)).unwrap();

        match setup_watches(&mut test_watcher, &mut test_config) {
            Ok(_) => panic!("This should have failed with an error"),
            Err(_) => (),
        }
    }

}

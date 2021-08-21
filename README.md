# rustmon
A kinda hacky rust reimplementation of nodemon

## BUT WHY
Basically, I had a docker container that I didn't want to have to restart each time,
but I also didn't want to have to install node in my python docker container so I could
restart it with nodemon. There's a pretty cool project [py-mon](https://github.com/trustedmercury/py-mon)
that does it in python, but I wanted a binary I could just download and run in basically
any environment. And I like rust.

# Help
```
rustmon 0.1.0

Rick Henry <rickhenry@rickhenry.dev>

Automatically restarts a script when files change on a path

USAGE:
    rustmon [FLAGS] [OPTIONS] <SCRIPT>

ARGS:
    <SCRIPT>    The script file to run

FLAGS:
    -h, --help         Print help information
    -r, --recursive    Set whether watches should be recursive or not
    -v, --verbose      More info about events. -v shows file that causes restart, -vv shows why
                       restart occurred, -vvv shows why a restart didn't occur after a file change
    -V, --version      Print version information

OPTIONS:
    -d, --delay <delay>          Delay time in seconds between accepting new events [default: 10]
    -e, --ext <EXTENSIONS>...    Additional file extensions to watch, separated by commas for
                                 multiple
    -i, --ignore <PATTERN>...    Ignore files using regex patterns, separated by commas (you may
                                 want to enclose them in quotes)
    -w, --watch <PATHS>...       Paths to watch, separated by commas for multiple
    -x, --exec <BIN>             Executable to run script, i.e. -x "/usr/bin/python"
```

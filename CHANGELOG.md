# NEXT RELEASE

### 1.3.13
* Set up loggers correctly so pdfalyzer can redirect as needed
* Fix logging of number of vars loaded from `.yaralyzer` file
* Fix logging to file

### 1.3.12
* Handle parsing arguments inside `YaralyzerConfig.parse_args()`

### 1.3.11
* Improve diff output for failed fixture comparisons

### 1.3.7 - 1.3.10
* Make `ONLY_CLI_ARGS` a class variable of `YaralyzerConfig`.
* (pytest) Handle "pdfalyzer.cmd" / "yaralyzer.cmd" in `argv` strings on Windows.

### 1.3.6
* (pytest) Force `box.SQUARE` style in `pytest` context

### 1.3.5
* (pytest) Force UTF-8 mode encoding (required for Windows)

### 1.3.4
* Catch `OSError` when checking `cairosvg` and the python package is installed by the actual `cairo` executable is missing

### 1.3.3
* Avoid `logging.getLevelNamesMapping()` so python 3.10 still works (also it's deprecated / regarded as a mistake)

### 1.3.2
* Use custom validators and exclusive argument groups so `argparse` can handle most validations
* Change shorthand for `--patterns-label` from `-rpl` to `-pl`
* Drop the `yaralyzer_show_color_theme` script in favour of a `--show-colors` debug option

### 1.3.1
* Accomodate Python 3.10 for a little while longer

# 1.3.0
* Add `--export-png` option to render .png images of output
* Add `--suppress-output` option
* Truncate extremely long filenames so they don't exceed system limit

# 1.2.0
* Multi-select command line options (e.g. `--yara-file`, `--rule-dir`) can be set permanently via env vars using comma separated strings
* Add `--env-vars` option to display exactly which command line options can be set by which variables
* Add `--echo-command` option to print the exact command used along with the output
* Strip invalid chars out of exported HTML / SVG / JSON / etc. filenames
* `pytest` now compares output against previously exported results instead of just checking line count
* Move `helpers/` module into `util/`

## 1.1.0
* Add `--no-timestamps` command line option for exported filenames
* Fix type hint for `per_encoding_stats`
* `files_in_dir()` returns `Path`s, prepends `'.` to `with_extname` arg if not provided
* Move environment and console width methods to `environment_helper.py`
* Ensure `args.file_to_scan_path` and `args.output_dir` are valid `Path` objects

### 1.0.14
* Use `@classproperty` decorator to ensure that `YaralyzerConfig.args` exists even when requested outside of a CLI invocation
* Allow relative paths in `YARALYZER_LOG_DIR` env var
* Use 256 color system for logs

### 1.0.13
* `TRACE` option for `--log-level` argument, `log_trace()` method
* Set `omit_repeated_times=False` in log handler
* Add API docs URL to help text

### 1.0.12
* Send logs to `stderr` instead of `stdout`
* Convert `RegexMatchMetrics` to a dataclass

### 1.0.11
* Catch yara internal errors in `yaralyze()` script so they are still raised when `Yaralyzer` used as a library

### 1.0.10
* Better handling and messaging around internal YARA errors
* Make `DecodingTableRow` and `BytesMatch` into dataclasses
* `print_bytes()` takes an `indent` argument

### 1.0.9
* Raise `FileNotFoundError` instead of `ValueError` if provided YARA rules files or dirs don't exist

### 1.0.8
* Bump `python-dotenv` to v1.1.1
* Use `mkdocs` and `lazydocs` to build automatic API documentation at https://michelcrypt4d4mus.github.io/yaralyzer/
* Drop python 3.9 support (required by `mkdocs-awesome-nav` package)

### 1.0.7
* Add `Changelog` to PyPi URLs, add some more PyPi classifiers
* Add `.flake8` config file and fix style errors
* Rename `prefix_with_plain_text_obj()` to `prefix_with_style()`

### 1.0.6
* Add `Environment :: Console` and `Programming Language :: Python` to PyPi classifiers
* Add `LICENSE` to PyPi package

### 1.0.5
* Add `Development Status :: 5 - Production/Stable` to pypi classifiers

### 1.0.4
* Lock `chardet` library to 5.x

### 1.0.3
* Upgrade `rich` to 14.1.0

### 1.0.2
* Upgrade `yara-python` to 4.5.4

### 1.0.1
* Fix iteration of byte offsets during attempted decodes for UTF-16 and UTF-32 (was starting at second byte instead of first)
* Label the byte offset for forced UTF-16 and UTF-32 decodes
* Show helpful message if logs are being sent to files in `YaralyzerConfig.LOG_DIR` instead of being written to stderr/stdout
* Warn if `--debug` and `--log-level` args both provided

# 1.0.0
* Add `--export-json` option

### 0.9.6
* Fix help message

### 0.9.5
* Use all files in a directory specified by `--rule-dir` instead of just those with the extension `.yara`
* Fix bug where `--rule-dir` is prefixed by `./`

### 0.9.4
* Bump `yara-python` to 4.3.0+ and deal with backwards incompatibility

### 0.9.3
* Lock `yara-python` at 4.2.3 bc 4.3.x causes problems

### 0.9.2
* Fix PyPi screenshots
* Raise better error message if yara rules file doesn't exist

### 0.9.1
* Fix PyPi screenshots

# 0.9.0
* All command lines args configurable via environment variables or `.yaralyzer` file
* Improve decoding attempt statistics tracking
* Add suppression notices
* Expose `--min-chardet-table-confidence` option

# 0.8.0
* Add `--log-level` option
* `BytesMatch.is_decodable()` method

### 0.7.1
* Bump deps

# 0.7.0
* Show hex and ascii side by side in decodes table

### 0.6.2
* Remove `cairosvg` dependency

### 0.6.1
* Use `rich_argparse_plus` for help formatting

# 0.6.0
* Add `--max-match-length` and `--yara-stack-size` args
* Increase max returned bytes (was stuck at 512)
* Tweak unprintable char format for ASCII C1 control range, minor style changes
* Show color key for raw YARA match panel

### 0.5.2
* Properly escape bytes previews for rich

### 0.5.1
* Add Pdfalyzer info message when scanning PDFs

# 0.5.0
* Show MD5, SHA1, and SHA256 hashes for each match

# 0.4.0
* Add `--hex-pattern` command line option
* Add `--patterns-label` command line option

### 0.3.3
* Refactor `file_export` and `rich_console`

### 0.3.2
* help screen displays defaults and valid ranges for int types

### 0.3.1
* yara-python compiles files directly

# 0.3.0
* Add `--rule-dir` option for loading all `.yara` files in directories
* Add `--regex_modifier` option

# 0.2.0
* Add `Yaralyzer.for_rules_dir()` constructor to load all `.yara` files in a directory
* Change command line arguments `-y` to `-Y` and `-r` to `-re`
* Respect the `--suppress-decodes` option and min / max decode length options
* Add `highlight_style` argument to `Yaralyzer`
* Expose `Yaralyzer.match_iterator()` that calls back with `BytesMatch` objects

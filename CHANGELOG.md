# NEXT RELEASE

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

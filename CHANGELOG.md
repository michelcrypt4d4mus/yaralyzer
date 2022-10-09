# NEXT RELEASE

# 0.6.1

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

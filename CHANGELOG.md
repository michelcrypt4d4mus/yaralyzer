# 0.2.0
* Add `Yaralyzer.for_rules_dir()` constructor to load all `.yara` files in a directory
* Change command line arguments `-y` to `-Y` and `-r` to `-re`
* Respect the `--suppress-decodes` option and min / max decode length options
* Add `highlight_style` argument to `Yaralyzer`
* Expose `Yaralyzer.match_iterator()` that calls back with `BytesMatch` objects

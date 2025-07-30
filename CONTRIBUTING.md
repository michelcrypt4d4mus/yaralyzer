Contributions are welcome, just make sure that before you open a pull request:

1. [The test suite passes](#Testing)
1. You add tests for your changes to the `pytest` test suite
1. You add a description of your changes to [the changelog](CHANGELOG.md)

# Development Environment Setup
1. `git clone https://github.com/michelcrypt4d4mus/yaralyzer.git`
1. `cd yaralyzer`

After that there's a forking path depending on whether or not you use [poetry](https://python-poetry.org) (which is what we use) to manage your python lifestyle.

Note that the minimum versions for each package were chosen because that's what worked on my machine and not because that version had some critical bug fix or feature so it's entirely possible that using earlier versions than are specified in [pyproject.toml](pyproject.toml) will work just fine. Feel free to experiment if there's some kind of version conflict for you.

### With Python Poetry:
These commands are the `poetry` equivalent of the traditional virtualenv installation followed by `source venv/bin/activate` but there's a lot of ways to run a python script in a virtualenv with `poetry` so you do you if you prefer another approach.

```sh
poetry install
source $(poetry env info --path)/bin/activate
```

### With A Manual `venv`:
```sh
python -m venv .venv              # Create a virtualenv in .venv
. .venv/bin/activate              # Activate the virtualenv
pip install .                     # Install packages
```


# Testing
Test coverage is... decent. The test suite _must_ pass before you open a pull request.

```bash
# Run tests (but not the slow ones):
pytest
```

See [pytest's official docs](https://docs.pytest.org/en/7.1.x/how-to/usage.html) for other `pytest` instantiation options.


# TODO
* For some reason when displaying matches the output to a file iterates over all matches in a different way than just running in the console. Presumably this is related to the `rich` rendering engine in some way. For now the console output is the "more correct" one so it's generally OK. See [`issue_with_output_to_console_correct`](doc/rendered_images/issue_with_output_to_console_correct.png) vs. [`issue_with_output_to_txt_file_incorrect.png`](doc/rendered_images/issue_with_output_to_txt_file_incorrect.png)
* highlight decodes done at `chardet`s behest
* deal with repetitive matches

#### Hashtags
```
#asciiArt #ascii #cybersecurity #detectionengineering #DFIR #FOSS #infosec #KaliLinux #malware #malwareDetection #malwareAnalysis #openSource #pdfalyzer #reverseEngineering #reversing #threathunting #yaralyze #yaralyzer #YARA #YARArule #YARArules
```

from rich.text import Text


# App Strings
YARALYZE = 'yaralyze'
YARALYZER = f"{YARALYZE}r"
YARALYZER_UPPER = YARALYZER.upper()
INVOKED_BY_PYTEST = 'INVOKED_BY_PYTEST'

dotfile_name = lambda app_name: f".{app_name}".lower()

# Numbeers
KILOBYTE = 1024
MEGABYTE = KILOBYTE * KILOBYTE
MAX_FILENAME_LENGTH = 245

# Command line options
ECHO_COMMAND_OPTION = '--echo-command'
ENV_VARS_OPTION = '--env-vars'
NO_TIMESTAMPS_OPTION = '--no-timestamps'
SUPPRESS_OUTPUT_OPTION = '--suppress-output'

EARLY_EXIT_ARGS = [
    '--show-colors',
    ENV_VARS_OPTION,
    '--version',
]

# Default args used when running the command line version in pytest
DEFAULT_PYTEST_CLI_ARGS = [ECHO_COMMAND_OPTION, NO_TIMESTAMPS_OPTION]

# Repos
GITHUB_BASE_URL = 'https://github.com/michelcrypt4d4mus'

repo_url = lambda app_name: f"{GITHUB_BASE_URL}/{app_name.lower()}"
example_dotenv_file_url = lambda app_name: f"{repo_url(app_name)}/blob/master/{dotfile_name(app_name)}.example"

PDFALYZER_REPO_URL = repo_url('pdfalyzer')
YARALYZER_REPO_URL = repo_url(YARALYZER)
YARALYZER_API_DOCS_URL = f"https://michelcrypt4d4mus.github.io/{YARALYZER}"


# Misc URLs etc.
INKSCAPE = 'inkscape'
INKSCAPE_URL = f'https://{INKSCAPE}.org/'


# print(json.dumps(logging.getLevelNamesMapping(), indent=4))
LOG_LEVELS = {
    "CRITICAL": 50,
    "FATAL": 50,
    "ERROR": 40,
    "WARN": 30,
    "WARNING": 30,
    "INFO": 20,
    "DEBUG": 10,
    "NOTSET": 0
}


# User messaging
PDFALYZER_MSG_TXT = Text("\nIf you are analyzing a PDF you may be interested in ", style='bright_white bold') \
                 .append("Pdfalyzer, birthplace of the Yaralyzer:\n ").append('-> ', style='dim') \
                 .append(f'{PDFALYZER_REPO_URL}\n', style='bright_cyan underline')

PNG_EXPORT_WARNING = f"PNG export requires CairoSVG or Inkscape and you have neither.\n" \
                     f"Maybe try pip install {YARALYZER}[img] or {INKSCAPE_URL}"

import logging


# Strings
YARALYZE = 'yaralyze'
YARALYZER = f"{YARALYZE}r"
YARALYZER_UPPER = YARALYZER.upper()
INVOKED_BY_PYTEST = 'INVOKED_BY_PYTEST'

# Numbeers
KILOBYTE = 1024
MEGABYTE = KILOBYTE * KILOBYTE
MAX_FILENAME_LENGTH = 245

# Logging constants
TRACE = 'TRACE'
TRACE_LOG_LEVEL = logging.DEBUG - 1

# Command line options
ECHO_COMMAND_OPTION = '--echo-command'
ENV_VARS_OPTION = '--env-vars'
NO_TIMESTAMPS_OPTION = '--no-timestamps'
SUPPRESS_OUTPUT_OPTION = '--suppress-output'

# Repos
GITHUB_BASE_URL = 'https://github.com/michelcrypt4d4mus'

repo_url = lambda app_name: f"{GITHUB_BASE_URL}/{app_name.lower()}"
example_dotenv_file_url = lambda app_name: f"{repo_url(app_name)}/blob/master/.{app_name.lower()}.example"

PDFALYZER_REPO_URL = repo_url('pdfalyzer')
YARALYZER_REPO_URL = repo_url(YARALYZER)
YARALYZER_API_DOCS_URL = f"https://michelcrypt4d4mus.github.io/{YARALYZER}"


# Misc URLs etc.
INKSCAPE = 'inkscape'
INKSCAPE_URL = f'https://{INKSCAPE}.org/'

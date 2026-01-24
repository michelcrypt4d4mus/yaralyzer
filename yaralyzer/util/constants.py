import logging


YARALYZE = 'yaralyze'
YARALYZER = f"{YARALYZE}r"
YARALYZER_UPPER = YARALYZER.upper()
INVOKED_BY_PYTEST = 'INVOKED_BY_PYTEST'

KILOBYTE = 1024
MEGABYTE = KILOBYTE * KILOBYTE

# Logging constants
TRACE = 'TRACE'
TRACE_LEVEL = logging.DEBUG - 1

# Command line options
ENV_VARS_OPTION = '--env-vars'
NO_TIMESTAMPS_OPTION = '--no-timestamps'
SUPPRESS_OUTPUT_OPTION = '--suppress-output'

# URLs
INKSCAPE_URL = 'https://inkscape.org/'

# Repos
GITHUB_BASE_URL = 'https://github.com/michelcrypt4d4mus'

repo_url = lambda app_name: f"{GITHUB_BASE_URL}/{app_name.lower()}"
example_dotenv_file_url = lambda app_name: f"{repo_url(app_name)}/blob/master/.{app_name.lower()}.example"

PDFALYZER_REPO_URL = repo_url('pdfalyzer')
YARALYZER_REPO_URL = repo_url(YARALYZER)
YARALYZER_API_DOCS_URL = f"https://michelcrypt4d4mus.github.io/{YARALYZER}"

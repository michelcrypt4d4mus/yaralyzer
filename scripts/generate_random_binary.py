from random import randbytes

from tests.conftest import binary_file_path

with open(binary_file_path(), 'wb') as file:
    file.write(randbytes(128 * 1024))

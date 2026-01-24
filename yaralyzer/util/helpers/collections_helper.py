"""
Help with lists and dicts.
"""


def flatten(a: list) -> list:
    """
    Flatten a list that may contain other lists which may also contain lists etc.
    From https://www.geeksforgeeks.org/python/python-flatten-list-to-individual-elements/.
    """
    return_value = []

    for x in a:
        if isinstance(x, list):
            return_value.extend(flatten(x))  # Recursively flatten nested lists
        else:
            return_value.append(x)  # Append individual elements

    return return_value


def get_dict_key_by_value(_dict: dict, value):
    """Inverse of the usual dict operation."""
    return list(_dict.keys())[list(_dict.values()).index(value)]


def listify(obj: object) -> list:
    """Make sure `obj` is a list."""
    return obj if isinstance(obj, list) else [obj]

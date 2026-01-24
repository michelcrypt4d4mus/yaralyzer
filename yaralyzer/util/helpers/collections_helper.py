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


def listify(listlike) -> list:
    """Create a list of 'listlike'. Returns empty list if 'listlike' is None or empty string."""
    if isinstance(listlike, list):
        return listlike
    elif listlike is None:
        return [None]
    elif listlike:
        return [listlike]
    else:
        return []

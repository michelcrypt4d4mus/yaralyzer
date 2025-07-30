"""
Help with lists.
"""

def flatten(a):
    """From https://www.geeksforgeeks.org/python/python-flatten-list-to-individual-elements/"""
    return_value = []

    for x in a:
        if isinstance(x, list):
            return_value.extend(flatten(x))  # Recursively flatten nested lists
        else:
            return_value.append(x)  # Append individual elements

    return return_value

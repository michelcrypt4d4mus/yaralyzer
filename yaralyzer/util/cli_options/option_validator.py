
class OptionValidator:
    """
    Base class for CLI options validators that needs to be in its own file because of circular
    dependency issues.
    """
    def arg_type_str(self) -> str:
        return type(self).__name__.removesuffix('Validator')

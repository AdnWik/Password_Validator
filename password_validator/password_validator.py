"""# TODO: """
from abc import ABC, abstractmethod
from re import findall


class ValidatorError(Exception):
    """# TODO: """


class Validator(ABC):
    """# TODO: """

    @abstractmethod
    def __init__(self, text) -> None:
        pass

    @abstractmethod
    def is_valid(self):
        pass


class HasNumberValidator(Validator):
    """# TODO: """

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        temp_table = findall('[0-9]', self.text)
        if temp_table:
            return True
        else:
            raise ValidatorError("Password must contain a number")


class HasSpecialCharacterValidator(Validator):
    """# TODO: """

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        # TODO:
        pass


class HasUpperCharacterValidator(Validator):
    """# TODO: """

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        # TODO:
        pass


class HasLowerCharacterValidator(Validator):
    """# TODO: """

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        # TODO:
        pass


class LengthValidator(Validator):
    """# TODO: """

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        # TODO:
        pass


class PasswordValidator():
    """# TODO: """

    def __init__(self, password) -> None:
        self.password = password
        self.validators = [
            HasNumberValidator
        ]

    def is_valid(self):
        """# TODO: """
        for class_name in self.validators:
            validator = class_name(self.password)
            print(validator.is_valid())

from abc import ABC, abstractmethod


class Validator(ABC):

    @abstractmethod
    def __init__(self, text) -> None:
        pass

    @abstractmethod
    def is_valid(self):
        pass


class HasNumberValidator(Validator):

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        # TODO:

        if self.text:
            return True
        else:
            return False


class PasswordValidator():

    def __init__(self, password) -> None:
        self.password = password
        self.validators = [
            HasNumberValidator
        ]

    def is_valid(self):
        for class_name in self.validators:
            print(self.password)
            validator = class_name(self.password)
            print(validator.text)
            print(validator.is_valid())

p = PasswordValidator('ABC')
p.is_valid()
print(p.validators)

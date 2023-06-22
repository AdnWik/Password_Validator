"""Password Validators"""
from abc import ABC, abstractmethod
from re import findall
from hashlib import sha1
from requests import get


class ValidatorError(Exception):
    """ValidatorError"""


class Validator(ABC):
    """Validator Abstract"""

    @abstractmethod
    def __init__(self, text) -> None:
        pass

    @abstractmethod
    def is_valid(self):
        pass


class HasNumberValidator(Validator):
    """Check number in password"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        temp_table = findall('[0-9]', self.text)
        if temp_table:
            return True
        else:
            raise ValidatorError("Password must contain a number")


class HasSpecialCharacterValidator(Validator):
    """Check special character in password"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        temp_table = findall('\W', self.text)
        if temp_table:
            return True
        else:
            raise ValidatorError("Password must contain special character")


class HasUpperCharacterValidator(Validator):
    """Check upper character in password"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        temp_table = findall('[A-Z]', self.text)
        if temp_table:
            return True
        else:
            raise ValidatorError("Password must contain upper character")


class HasLowerCharacterValidator(Validator):
    """Check lower character in password"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        temp_table = findall('[a-z]', self.text)
        if temp_table:
            return True
        else:
            raise ValidatorError("Password must contain a lower character")


class LengthValidator(Validator):
    """Check length of password"""

    def __init__(self, text, min_length=8) -> None:
        self.text = text
        self.min_length = min_length

    def is_valid(self):
        if len(self.text) >= self.min_length:
            return True
        else:
            raise ValidatorError(f'Password must contain a '
                                 f'{self.min_length} characters')


class HaveIbennPwndValidator(Validator):
    """Check password in HaveIbeenPwnd.com"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        _hash = sha1(self.text.encode(encoding='UTF-8')).hexdigest().upper()
        _hash_prefix = _hash[:5]
        _hash_suffix = _hash[5:]

        with get(f'https://api.pwnedpasswords.com/range/{_hash_prefix}', timeout= 2) as response:
            content = response.text.splitlines()

            temp_table = [tuple(i.split(':')) for i in content]
            if _hash_suffix in [receive_hash for receive_hash, _ in temp_table]:
                raise ValidatorError('Password pwned')
            else:
                return True


class PasswordValidator():
    """Password validator"""

    def __init__(self, password) -> None:
        self.password = password
        self.validators = [
            HasNumberValidator,
            HasSpecialCharacterValidator,
            HasLowerCharacterValidator,
            HasUpperCharacterValidator,
            LengthValidator,
            HaveIbennPwndValidator
        ]

    def is_valid(self):
        """Check password with validators"""

        for class_name in self.validators:
            validator = class_name(self.password)
            validator.is_valid()
        return True

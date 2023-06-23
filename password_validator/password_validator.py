"""Password Validators"""
from abc import ABC, abstractmethod
from re import findall
import logging
from functools import cache
from hashlib import sha1
from requests import get


class ValidatorError(Exception):
    """Exception for validation error"""


class Validator(ABC):
    """Interface for validators"""

    @abstractmethod
    def __init__(self, text) -> None:
        """Force to implement __init__ method"""

    @abstractmethod
    def is_valid(self):
        """Force to implement is_valid method"""


class HasNumberValidator(Validator):
    """Validator that checks if number appears in text"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        """Check if text is valid

        Raises:
            ValidatorError: text is not valid because there is no number in text

        Returns:
            bool: has number in text
        """
        logging.debug('%s: Start validate', self.__class__.__name__)

        temp_table = findall(r'[0-9]', self.text)
        if temp_table:
            logging.info('%s: OK', self.__class__.__name__)

            return True

        error_message = 'Password must contain a number'
        logging.error('%s: %s', self.__class__.__name__, error_message)

        raise ValidatorError(error_message)


class HasSpecialCharacterValidator(Validator):
    """Check special character in password"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        logging.debug('%s: Start validate', self.__class__.__name__)

        temp_table = findall(r'\W', self.text)
        if temp_table:
            logging.info('%s: OK', self.__class__.__name__)

            return True

        error_message = 'Password must contain special character'
        logging.error('%s: %s', self.__class__.__name__, error_message)

        raise ValidatorError(error_message)


class HasUpperCharacterValidator(Validator):
    """Check upper character in password"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        logging.debug('%s: Start validate', self.__class__.__name__)

        temp_table = findall(r'[A-Z]', self.text)
        if temp_table:
            logging.info('%s: OK', self.__class__.__name__)

            return True

        error_message = 'Password must contain upper character'
        logging.error('%s: %s', self.__class__.__name__, error_message)

        raise ValidatorError(error_message)


class HasLowerCharacterValidator(Validator):
    """Check lower character in password"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        logging.debug('%s: Start validate', self.__class__.__name__)

        temp_table = findall(r'[a-z]', self.text)
        if temp_table:
            logging.info('%s: OK', self.__class__.__name__)

            return True

        error_message = 'Password must contain a lower character'
        logging.error('%s: %s', self.__class__.__name__, error_message)

        raise ValidatorError(error_message)


class LengthValidator(Validator):
    """Check length of password"""

    def __init__(self, text, min_length=8) -> None:
        self.text = text
        self.min_length = min_length

    def is_valid(self):
        logging.debug('%s: Start validate', self.__class__.__name__)

        if len(self.text) >= self.min_length:
            logging.info('%s: OK', self.__class__.__name__)

            return True

        error_message = (f'Password must contain a '
                         f'{self.min_length} characters')
        logging.error('%s: %s', self.__class__.__name__, error_message)

        raise ValidatorError(error_message)


@cache
class HaveIbennPwndValidator(Validator):
    """Check password in HaveIbeenPwnd.com"""

    def __init__(self, text) -> None:
        self.text = text

    def is_valid(self):
        logging.debug('%s: Start validate', self.__class__.__name__)

        password_hash = (sha1(self.text.encode(encoding='UTF-8'))
                         .hexdigest().upper())
        hash_prefix = password_hash[:5]
        hash_suffix = password_hash[5:]
        url = 'https://api.pwnedpasswords.com/range/'

        with get(f'{url}{hash_prefix}', timeout=2) as response:
            content = response.text.splitlines()

            temp_table = [tuple(i.split(':')) for i in content]
            if hash_suffix in [receive_hash for receive_hash, _ in temp_table]:
                error_message = 'Password pwned'
                logging.error('%s: %s', self.__class__.__name__, error_message)

                raise ValidatorError(error_message)

            logging.info('%s: OK', self.__class__.__name__)

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

        logging.info('%s: Validation  "%s"',
                     self.__class__.__name__, self.password)

        for class_name in self.validators:
            validator = class_name(self.password)
            validator.is_valid()

        logging.info('%s: "%s" is validated',
                     self.__class__.__name__, self.password)

        return True

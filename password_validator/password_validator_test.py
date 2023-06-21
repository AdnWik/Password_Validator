"""# TODO: """
from password_validator import (
    HasNumberValidator,
    HasSpecialCharacterValidator,
    HasUpperCharacterValidator,
    HasLowerCharacterValidator,
    LengthValidator,
    HaveIbennPwndValidator,
    ValidatorError)
import pytest
import requests_mock


def test_has_number_validator_positive():
    """# TODO: """

    # given
    validator = HasNumberValidator('Abc1')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_number_validator_negative():
    """# TODO: """

    # given
    validator = HasNumberValidator('Abc')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain a number' in str(error.value)


def test_has_special_character_positive():
    """# TODO: """

    # given
    validator = HasSpecialCharacterValidator('Abc^')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_special_character_negative():
    """# TODO: """

    # given
    validator = HasSpecialCharacterValidator('Abc')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain special character' in str(error.value)


def test_has_upper_character_positive():
    """# TODO: """

    # given
    validator = HasUpperCharacterValidator('Abc')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_upper_character_negative():
    """# TODO: """

    # given
    validator = HasUpperCharacterValidator('abc')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain upper character' in str(error.value)


def test_has_lower_character_positive():
    """# TODO: """

    # given
    validator = HasLowerCharacterValidator('ABc')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_lower_character_negative():
    """# TODO: """

    # given
    validator = HasLowerCharacterValidator('ABC')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain lower character' in str(error.value)


def test_length_validator_positive():
    """# TODO: """

    # given
    validator = LengthValidator('12345678')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_length_validator_negative():
    """# TODO: """

    # given
    min_length = 9
    validator = LengthValidator('12345678', min_length)

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert (f'Password must contain a '
               f'{min_length} characters') in str(error.value)


def test_have_i_benn_pwned_positive():
    """# TODO: """

    # given
    validator = HaveIbennPwndValidator('123^^^abcd!Q')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_have_i_benn_pwned_negative():
    """# TODO: """

    # given
    validator = HaveIbennPwndValidator('ZAQ!2wsxCDE#')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password pwned' in str(error.value)

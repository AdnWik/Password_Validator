"""Password validators tests"""
import pytest
from password_validators.validators import (
    HasNumberValidator,
    HasSpecialCharacterValidator,
    HasUpperCharacterValidator,
    HasLowerCharacterValidator,
    LengthValidator,
    HaveIbennPwndValidator,
    PasswordValidator,
    ValidatorError
    )


def test_has_number_validator_positive():
    """Has number validator positive test"""

    # given
    validator = HasNumberValidator('Abc1')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_number_validator_negative():
    """Has number validator negative test"""

    # given
    validator = HasNumberValidator('Abc')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain a number' in str(error.value)


def test_has_special_character_positive():
    """has special character validator positive test"""

    # given
    validator = HasSpecialCharacterValidator('Abc^')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_special_character_negative():
    """Has special character validator negative test"""

    # given
    validator = HasSpecialCharacterValidator('Abc')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain special character' in str(error.value)


def test_has_upper_character_positive():
    """Has upper character validator positive test"""

    # given
    validator = HasUpperCharacterValidator('Abc')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_upper_character_negative():
    """Has upper character validator negative test"""

    # given
    validator = HasUpperCharacterValidator('abc')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain upper character' in str(error.value)


def test_has_lower_character_positive():
    """Has lower character validator positive test"""

    # given
    validator = HasLowerCharacterValidator('ABc')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_has_lower_character_negative():
    """Has lower character validator negative test"""

    # given
    validator = HasLowerCharacterValidator('ABC')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password must contain lower character' in str(error.value)


def test_length_validator_positive():
    """Length validator positive test"""

    # given
    validator = LengthValidator('12345678')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_length_validator_negative():
    """Length validator negative test"""

    # given
    min_length = 9
    validator = LengthValidator('12345678', min_length)

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert (f'Password must contain a '
               f'{min_length} characters') in str(error.value)


def test_have_i_benn_pwned_positive(requests_mock):
    """Check password leaked positive test"""

    # Password: Admin!2#4
    # Hash: 80A5DDCFF79958F65FE712272C245448E417C045

    # given
    data = ('FFC978EDB996E9ADA72E89B4BBB984C87D6:3\r\n' +
            'FFE5530FE4064199914EB29060C596775AA:1')
    requests_mock.get('https://api.pwnedpasswords.com/range/80A5D', text=data)

    validator = HaveIbennPwndValidator('Admin!2#4')

    # when
    result = validator.is_valid()

    # then
    assert result is True


def test_have_i_benn_pwned_negative(requests_mock):
    """Check password leaked negative test"""

    # Password: Admin!2#4
    # Hash: 80A5DDCFF79958F65FE712272C245448E417C045

    # given
    data = ('FFC978EDB996E9ADA72E89B4BBB984C87D6:3\r\n' +
            'DCFF79958F65FE712272C245448E417C045:1')
    requests_mock.get('https://api.pwnedpasswords.com/range/80A5D', text=data)

    validator = HaveIbennPwndValidator('Admin!2#4')

    # when
    with pytest.raises(ValidatorError) as error:
        validator.is_valid()
        assert 'Password pwned' in str(error.value)


def test_password_validator_positive(requests_mock):
    """Length validator positive test"""

    # Password: Admin!2#4
    # Hash: 80A5DDCFF79958F65FE712272C245448E417C045

    # given
    data = ('FFC978EDB996E9ADA72E89B4BBB984C87D6:3\r\n' +
            'FFE5530FE4064199914EB29060C596775AA:1')
    requests_mock.get('https://api.pwnedpasswords.com/range/80A5D', text=data)
    validator = PasswordValidator('Admin!2#4')

    # when
    assert validator.is_valid() is True


def test_password_validator_negative(requests_mock):
    """Length validator positive test"""

    # Password: Admin!2#4
    # Hash: 80A5DDCFF79958F65FE712272C245448E417C045

    # given
    data = ('FFC978EDB996E9ADA72E89B4BBB984C87D6:3\r\n' +
            'DCFF79958F65FE712272C245448E417C045:1')
    requests_mock.get('https://api.pwnedpasswords.com/range/80A5D', text=data)
    validator = PasswordValidator('A')

    # when
    assert validator.is_valid() is False

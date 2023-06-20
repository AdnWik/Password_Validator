"""# TODO: """
import pytest
from password_validator import (
    HasNumberValidator,
    ValidatorError)


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

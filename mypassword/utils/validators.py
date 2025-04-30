"""Validation utilities for password generation."""

import os
from .exceptions import ValidationError


def validate_password_requirements(
    length: int,
    min_lowercase: int = 0,
    min_uppercase: int = 0,
    min_digits: int = 0,
    min_special: int = 0,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True
) -> None:
    """
    Validate password generation requirements.
    
    Args:
        length: Password length
        min_lowercase: Minimum lowercase letters required
        min_uppercase: Minimum uppercase letters required
        min_digits: Minimum digits required
        min_special: Minimum special characters required
        use_lowercase: Whether lowercase letters are enabled
        use_uppercase: Whether uppercase letters are enabled
        use_digits: Whether digits are enabled
        use_special: Whether special characters are enabled
    
    Raises:
        ValidationError: If requirements are invalid
    """
    if length < 4:
        raise ValidationError("Password length must be at least 4 characters")
    
    # Check if at least one character type is enabled
    if not any([use_lowercase, use_uppercase, use_digits, use_special]):
        raise ValidationError("At least one character type must be enabled")
    
    # Calculate total minimum requirements
    total_required = 0
    if use_lowercase and min_lowercase > 0:
        total_required += min_lowercase
    if use_uppercase and min_uppercase > 0:
        total_required += min_uppercase
    if use_digits and min_digits > 0:
        total_required += min_digits
    if use_special and min_special > 0:
        total_required += min_special
    
    if total_required > length:
        raise ValidationError(
            f"Minimum requirements ({total_required}) exceed password length ({length})"
        )


def validate_store_name(name: str) -> None:
    """
    Validate password store entry name.
    
    Args:
        name: Entry name to validate
        
    Raises:
        ValidationError: If name is invalid
    """
    if not name or not name.strip():
        raise ValidationError("Password name cannot be empty")
    
    if len(name) > 100:
        raise ValidationError("Password name cannot exceed 100 characters")


def validate_master_password(password: str) -> None:
    """
    Validate master password strength.
    
    Args:
        password: Master password to validate
        
    Raises:
        ValidationError: If password is too weak
    """
    if not password:
        raise ValidationError("Master password cannot be empty")
    
    if len(password) < 6:
        raise ValidationError("Master password must be at least 6 characters long")


def validate_file_path(file_path: str, must_exist: bool = False, must_not_exist: bool = False) -> None:
    """
    Validate file path.
    
    Args:
        file_path: File path to validate
        must_exist: If True, file must exist
        must_not_exist: If True, file must not exist
        
    Raises:
        ValidationError: If file path is invalid
    """
    if not file_path or not file_path.strip():
        raise ValidationError("File path cannot be empty")
    
    if must_exist and not os.path.exists(file_path):
        raise ValidationError(f"File does not exist: {file_path}")
    
    if must_not_exist and os.path.exists(file_path):
        raise ValidationError(f"File already exists: {file_path}")
    
    # Check if parent directory exists and is writable
    parent_dir = os.path.dirname(os.path.abspath(file_path))
    if not os.path.exists(parent_dir):
        raise ValidationError(f"Parent directory does not exist: {parent_dir}")
    
    if not os.access(parent_dir, os.W_OK):
        raise ValidationError(f"No write permission for directory: {parent_dir}")


def validate_positive_integer(value: int, name: str, min_value: int = 1) -> None:
    """
    Validate positive integer.
    
    Args:
        value: Integer value to validate
        name: Name of the parameter for error messages
        min_value: Minimum allowed value
        
    Raises:
        ValidationError: If value is invalid
    """
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    
    if value < min_value:
        raise ValidationError(f"{name} must be at least {min_value}")


def validate_string_length(value: str, name: str, max_length: int, min_length: int = 0) -> None:
    """
    Validate string length.
    
    Args:
        value: String value to validate
        name: Name of the parameter for error messages
        max_length: Maximum allowed length
        min_length: Minimum allowed length
        
    Raises:
        ValidationError: If string length is invalid
    """
    if len(value) < min_length:
        raise ValidationError(f"{name} must be at least {min_length} characters long")
    
    if len(value) > max_length:
        raise ValidationError(f"{name} cannot exceed {max_length} characters")
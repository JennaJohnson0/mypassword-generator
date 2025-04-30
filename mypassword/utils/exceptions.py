"""Custom exceptions for the password generator."""


class PasswordError(Exception):
    """Base exception for password-related errors."""
    pass


class StorageError(Exception):
    """Exception for password storage-related errors."""
    pass


class ValidationError(Exception):
    """Exception for validation errors."""
    pass


class CryptographyError(Exception):
    """Exception for cryptography-related errors."""
    pass
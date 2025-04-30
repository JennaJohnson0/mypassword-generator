"""
MyPassword Generator - A secure password generator and manager.

A flexible password generator with customizable options for length,
character sets, security requirements, and encrypted local storage.
"""

__version__ = "1.0.0"
__author__ = "MyPassword Generator"

from .core.generator import PasswordGenerator
from .core.store import PasswordStore

__all__ = ['PasswordGenerator', 'PasswordStore']
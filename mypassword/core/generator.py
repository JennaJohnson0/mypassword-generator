"""Password generation functionality."""

import secrets
import string
import hashlib
from typing import Dict, Any

from ..utils.exceptions import ValidationError
from ..utils.validators import validate_password_requirements


class PasswordGenerator:
    """Secure password generator with customizable options."""
    
    def __init__(self):
        """Initialize the password generator with character sets."""
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous = "0O1lI"
    
    def generate_password(
        self,
        length: int = 12,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
        custom_chars: str = "",
        min_lowercase: int = 0,
        min_uppercase: int = 0,
        min_digits: int = 0,
        min_special: int = 0
    ) -> str:
        """
        Generate a secure random password with specified criteria.
        
        Args:
            length: Password length (minimum 4)
            use_lowercase: Include lowercase letters
            use_uppercase: Include uppercase letters
            use_digits: Include digits
            use_special: Include special characters
            exclude_ambiguous: Exclude ambiguous characters (0, O, 1, l, I)
            custom_chars: Additional custom characters to include
            min_lowercase: Minimum number of lowercase letters
            min_uppercase: Minimum number of uppercase letters
            min_digits: Minimum number of digits
            min_special: Minimum number of special characters
        
        Returns:
            Generated password string
        
        Raises:
            ValidationError: If parameters are invalid
        """
        # Validate requirements
        validate_password_requirements(
            length, min_lowercase, min_uppercase, min_digits, min_special,
            use_lowercase, use_uppercase, use_digits, use_special
        )
        
        # Build character set
        char_set = self._build_character_set(
            use_lowercase, use_uppercase, use_digits, use_special,
            exclude_ambiguous, custom_chars
        )
        
        # Generate password
        password = []
        required_chars = self._get_required_chars(
            min_lowercase, min_uppercase, min_digits, min_special,
            use_lowercase, use_uppercase, use_digits, use_special,
            exclude_ambiguous
        )
        
        # Add required characters
        for char_group in required_chars:
            password.append(secrets.choice(char_group))
        
        # Fill remaining positions
        remaining_length = length - len(password)
        for _ in range(remaining_length):
            password.append(secrets.choice(char_set))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def generate_from_key(
        self,
        key: str,
        length: int = 12,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
        site: str = "",
        counter: int = 1
    ) -> str:
        """
        Generate a deterministic password based on a user key.
        
        Args:
            key: User's master key/password
            length: Password length
            use_lowercase: Include lowercase letters
            use_uppercase: Include uppercase letters
            use_digits: Include digits
            use_special: Include special characters
            exclude_ambiguous: Exclude ambiguous characters
            site: Site name for unique passwords per site
            counter: Counter for generating different passwords with same key
        
        Returns:
            Deterministic password based on the key
        
        Raises:
            ValidationError: If parameters are invalid
        """
        # Validate requirements
        validate_password_requirements(
            length, 0, 0, 0, 0,
            use_lowercase, use_uppercase, use_digits, use_special
        )
        
        # Create unique input for hashing
        input_data = f"{key}:{site}:{counter}".encode('utf-8')
        
        # Use PBKDF2 for key derivation
        derived_key = hashlib.pbkdf2_hmac('sha256', input_data, b'salt', 100000)
        
        # Build character set
        char_set = self._build_character_set(
            use_lowercase, use_uppercase, use_digits, use_special,
            exclude_ambiguous, ""
        )
        
        # Generate password from derived key
        password = []
        for i in range(length):
            byte_val = derived_key[i % len(derived_key)]
            char_index = byte_val % len(char_set)
            password.append(char_set[char_index])
        
        # Ensure character type requirements are met
        password = self._ensure_character_requirements(
            password, use_lowercase, use_uppercase, use_digits, use_special,
            derived_key, length
        )
        
        return ''.join(password)
    
    def generate_passphrase(
        self,
        word_count: int = 4,
        separator: str = "-",
        capitalize: bool = True,
        add_numbers: bool = False
    ) -> str:
        """
        Generate a passphrase using common words.
        
        Args:
            word_count: Number of words to include
            separator: Character(s) to separate words
            capitalize: Capitalize first letter of each word
            add_numbers: Add random numbers to the end
        
        Returns:
            Generated passphrase
        
        Raises:
            ValidationError: If parameters are invalid
        """
        if word_count < 2:
            raise ValidationError("Word count must be at least 2")
        
        # Simple word list for demonstration
        words = [
            "apple", "banana", "cherry", "dragon", "elephant", "forest",
            "garden", "house", "island", "jungle", "kitchen", "mountain",
            "ocean", "planet", "rainbow", "sunset", "travel", "universe",
            "village", "window", "yellow", "zebra", "bridge", "castle",
            "dream", "energy", "flower", "galaxy", "horizon", "journey"
        ]
        
        selected_words = []
        for _ in range(word_count):
            word = secrets.choice(words)
            if capitalize:
                word = word.capitalize()
            selected_words.append(word)
        
        passphrase = separator.join(selected_words)
        
        if add_numbers:
            passphrase += separator + str(secrets.randbelow(1000))
        
        return passphrase
    
    def check_strength(self, password: str) -> Dict[str, Any]:
        """
        Analyze password strength.
        
        Args:
            password: Password to analyze
        
        Returns:
            Dictionary with strength metrics
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Character diversity
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.special for c in password)
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        score += char_types
        
        if char_types < 3:
            feedback.append("Use a mix of lowercase, uppercase, digits, and special characters")
        
        # Common patterns
        if password.lower() in ["password", "123456", "qwerty", "admin"]:
            score -= 3
            feedback.append("Avoid common passwords")
        
        # Sequential characters
        sequential_count = 0
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                sequential_count += 1
        
        if sequential_count > 0:
            score -= 1
            feedback.append("Avoid sequential characters")
        
        # Determine strength level
        if score >= 6:
            strength = "Strong"
        elif score >= 4:
            strength = "Medium"
        else:
            strength = "Weak"
        
        return {
            "score": max(0, score),
            "strength": strength,
            "feedback": feedback,
            "length": len(password),
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_special": has_special
        }
    
    def _build_character_set(
        self,
        use_lowercase: bool,
        use_uppercase: bool,
        use_digits: bool,
        use_special: bool,
        exclude_ambiguous: bool,
        custom_chars: str
    ) -> str:
        """Build character set based on options."""
        char_set = ""
        
        if use_lowercase:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            char_set += chars
        
        if use_uppercase:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            char_set += chars
        
        if use_digits:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            char_set += chars
        
        if use_special:
            char_set += self.special
        
        if custom_chars:
            char_set += custom_chars
        
        return char_set
    
    def _get_required_chars(
        self,
        min_lowercase: int,
        min_uppercase: int,
        min_digits: int,
        min_special: int,
        use_lowercase: bool,
        use_uppercase: bool,
        use_digits: bool,
        use_special: bool,
        exclude_ambiguous: bool
    ) -> list:
        """Get required character groups."""
        required_chars = []
        
        if use_lowercase and min_lowercase > 0:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            required_chars.extend([chars] * min_lowercase)
        
        if use_uppercase and min_uppercase > 0:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            required_chars.extend([chars] * min_uppercase)
        
        if use_digits and min_digits > 0:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            required_chars.extend([chars] * min_digits)
        
        if use_special and min_special > 0:
            required_chars.extend([self.special] * min_special)
        
        return required_chars
    
    def _ensure_character_requirements(
        self,
        password: list,
        use_lowercase: bool,
        use_uppercase: bool,
        use_digits: bool,
        use_special: bool,
        derived_key: bytes,
        length: int
    ) -> list:
        """Ensure password meets character type requirements."""
        has_lower = use_lowercase and any(c in self.lowercase for c in password)
        has_upper = use_uppercase and any(c in self.uppercase for c in password)
        has_digit = use_digits and any(c in self.digits for c in password)
        has_special_char = use_special and any(c in self.special for c in password)
        
        # If requirements not met, force include required character types
        requirements = []
        if use_lowercase and not has_lower:
            requirements.append(self.lowercase)
        if use_uppercase and not has_upper:
            requirements.append(self.uppercase)
        if use_digits and not has_digit:
            requirements.append(self.digits)
        if use_special and not has_special_char:
            requirements.append(self.special)
        
        # Replace characters to meet requirements
        for i, req_chars in enumerate(requirements):
            if i < len(password):
                byte_val = derived_key[(i + length) % len(derived_key)]
                char_index = byte_val % len(req_chars)
                password[i] = req_chars[char_index]
        
        return password
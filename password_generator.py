#!/usr/bin/env python3
"""
Secure Password Generator

A flexible password generator with customizable options for length,
character sets, and security requirements.
"""

import secrets
import string
import argparse
import sys
import hashlib
import base64


class PasswordGenerator:
    def __init__(self):
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
        Generate a secure password with specified criteria.
        
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
            ValueError: If parameters are invalid
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        # Build character set
        char_set = ""
        required_chars = []
        
        if use_lowercase:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            char_set += chars
            required_chars.extend([chars] * min_lowercase)
        
        if use_uppercase:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            char_set += chars
            required_chars.extend([chars] * min_uppercase)
        
        if use_digits:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            char_set += chars
            required_chars.extend([chars] * min_digits)
        
        if use_special:
            char_set += self.special
            required_chars.extend([self.special] * min_special)
        
        if custom_chars:
            char_set += custom_chars
        
        if not char_set:
            raise ValueError("At least one character type must be enabled")
        
        total_required = len(required_chars)
        if total_required > length:
            raise ValueError(f"Minimum requirements ({total_required}) exceed password length ({length})")
        
        # Generate password
        password = []
        
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
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        # Create unique input for hashing
        input_data = f"{key}:{site}:{counter}".encode('utf-8')
        
        # Use PBKDF2 for key derivation
        derived_key = hashlib.pbkdf2_hmac('sha256', input_data, b'salt', 100000)
        
        # Build character set
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
        
        if not char_set:
            raise ValueError("At least one character type must be enabled")
        
        # Generate password from derived key
        password = []
        for i in range(length):
            # Use each byte of the derived key to select characters
            byte_val = derived_key[i % len(derived_key)]
            char_index = byte_val % len(char_set)
            password.append(char_set[char_index])
        
        # Ensure character type requirements are met
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
        """
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
    
    def check_strength(self, password: str) -> dict:
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
            if ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i]) + 2:
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


def main():
    parser = argparse.ArgumentParser(description="Generate secure passwords and passphrases")
    parser.add_argument("-l", "--length", type=int, default=12, help="Password length (default: 12)")
    parser.add_argument("--no-lowercase", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-uppercase", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (0, O, 1, l, I)")
    parser.add_argument("--custom-chars", type=str, default="", help="Additional custom characters")
    parser.add_argument("--min-lowercase", type=int, default=0, help="Minimum lowercase letters")
    parser.add_argument("--min-uppercase", type=int, default=0, help="Minimum uppercase letters")
    parser.add_argument("--min-digits", type=int, default=0, help="Minimum digits")
    parser.add_argument("--min-special", type=int, default=0, help="Minimum special characters")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of passwords to generate")
    parser.add_argument("--passphrase", action="store_true", help="Generate passphrase instead of password")
    parser.add_argument("--words", type=int, default=4, help="Number of words in passphrase (default: 4)")
    parser.add_argument("--separator", type=str, default="-", help="Passphrase word separator (default: -)")
    parser.add_argument("--no-capitalize", action="store_true", help="Don't capitalize passphrase words")
    parser.add_argument("--add-numbers", action="store_true", help="Add numbers to passphrase")
    parser.add_argument("--check", type=str, help="Check strength of provided password")
    parser.add_argument("--key", type=str, help="Generate deterministic password from key")
    parser.add_argument("--site", type=str, default="", help="Site name for unique passwords per site")
    parser.add_argument("--counter", type=int, default=1, help="Counter for different passwords with same key")
    
    args = parser.parse_args()
    
    generator = PasswordGenerator()
    
    try:
        if args.check:
            strength = generator.check_strength(args.check)
            print(f"Password: {args.check}")
            print(f"Strength: {strength['strength']} (Score: {strength['score']})")
            print(f"Length: {strength['length']}")
            print(f"Contains: ", end="")
            components = []
            if strength['has_lowercase']: components.append("lowercase")
            if strength['has_uppercase']: components.append("uppercase")
            if strength['has_digits']: components.append("digits")
            if strength['has_special']: components.append("special")
            print(", ".join(components) if components else "none")
            
            if strength['feedback']:
                print("\nSuggestions:")
                for suggestion in strength['feedback']:
                    print(f"  • {suggestion}")
            
        elif args.key:
            for i in range(args.count):
                password = generator.generate_from_key(
                    key=args.key,
                    length=args.length,
                    use_lowercase=not args.no_lowercase,
                    use_uppercase=not args.no_uppercase,
                    use_digits=not args.no_digits,
                    use_special=not args.no_special,
                    exclude_ambiguous=args.exclude_ambiguous,
                    site=args.site,
                    counter=args.counter + i
                )
                print(password)
        
        elif args.passphrase:
            for _ in range(args.count):
                passphrase = generator.generate_passphrase(
                    word_count=args.words,
                    separator=args.separator,
                    capitalize=not args.no_capitalize,
                    add_numbers=args.add_numbers
                )
                print(passphrase)
        
        else:
            for _ in range(args.count):
                password = generator.generate_password(
                    length=args.length,
                    use_lowercase=not args.no_lowercase,
                    use_uppercase=not args.no_uppercase,
                    use_digits=not args.no_digits,
                    use_special=not args.no_special,
                    exclude_ambiguous=args.exclude_ambiguous,
                    custom_chars=args.custom_chars,
                    min_lowercase=args.min_lowercase,
                    min_uppercase=args.min_uppercase,
                    min_digits=args.min_digits,
                    min_special=args.min_special
                )
                print(password)
    
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
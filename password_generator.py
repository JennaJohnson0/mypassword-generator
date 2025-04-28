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
import json
import os
import getpass
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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


class PasswordStore:
    def __init__(self, store_file: str = None):
        """Initialize password store with encrypted local storage."""
        if store_file is None:
            home_dir = os.path.expanduser("~")
            self.store_file = os.path.join(home_dir, ".password_store.enc")
        else:
            self.store_file = store_file
        
        self.master_password = None
        self.cipher_suite = None
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_master_password(self) -> str:
        """Get master password from user."""
        if self.master_password is None:
            try:
                self.master_password = getpass.getpass("Enter master password: ")
            except (EOFError, KeyboardInterrupt):
                print("\nPassword input cancelled.", file=sys.stderr)
                sys.exit(1)
            except Exception:
                # Fallback for non-interactive environments
                print("Enter master password: ", end="", flush=True)
                self.master_password = input()
        return self.master_password
    
    def _init_cipher(self, password: str, salt: bytes = None) -> tuple:
        """Initialize cipher suite with master password."""
        if salt is None:
            salt = os.urandom(16)
        
        key = self._derive_key(password, salt)
        cipher_suite = Fernet(key)
        return cipher_suite, salt
    
    def _load_store(self) -> dict:
        """Load and decrypt password store."""
        if not os.path.exists(self.store_file):
            return {"entries": {}, "metadata": {"created": datetime.now().isoformat()}}
        
        try:
            with open(self.store_file, 'rb') as f:
                data = f.read()
            
            if len(data) < 16:
                return {"entries": {}, "metadata": {"created": datetime.now().isoformat()}}
            
            # Extract salt and encrypted data
            salt = data[:16]
            encrypted_data = data[16:]
            
            # Initialize cipher
            master_password = self._get_master_password()
            cipher_suite, _ = self._init_cipher(master_password, salt)
            
            # Decrypt and load JSON
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt password store. Wrong master password? Error: {e}")
    
    def _save_store(self, data: dict):
        """Encrypt and save password store."""
        master_password = self._get_master_password()
        cipher_suite, salt = self._init_cipher(master_password)
        
        # Serialize and encrypt
        json_data = json.dumps(data, indent=2).encode()
        encrypted_data = cipher_suite.encrypt(json_data)
        
        # Save with salt prefix
        with open(self.store_file, 'wb') as f:
            f.write(salt + encrypted_data)
        
        # Set restrictive permissions
        os.chmod(self.store_file, 0o600)
    
    def store_password(self, name: str, password: str, site: str = "", username: str = "", notes: str = ""):
        """Store a password entry."""
        data = self._load_store()
        
        entry = {
            "password": password,
            "site": site,
            "username": username,
            "notes": notes,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat()
        }
        
        if name in data["entries"]:
            entry["created"] = data["entries"][name]["created"]
        
        data["entries"][name] = entry
        data["metadata"]["modified"] = datetime.now().isoformat()
        
        self._save_store(data)
        print(f"Password '{name}' stored successfully.")
    
    def retrieve_password(self, name: str) -> dict:
        """Retrieve a password entry."""
        data = self._load_store()
        
        if name not in data["entries"]:
            raise ValueError(f"Password entry '{name}' not found.")
        
        return data["entries"][name]
    
    def list_passwords(self) -> list:
        """List all password entries."""
        data = self._load_store()
        entries = []
        
        for name, entry in data["entries"].items():
            entries.append({
                "name": name,
                "site": entry.get("site", ""),
                "username": entry.get("username", ""),
                "created": entry.get("created", ""),
                "modified": entry.get("modified", "")
            })
        
        return sorted(entries, key=lambda x: x["name"])
    
    def delete_password(self, name: str):
        """Delete a password entry."""
        data = self._load_store()
        
        if name not in data["entries"]:
            raise ValueError(f"Password entry '{name}' not found.")
        
        del data["entries"][name]
        data["metadata"]["modified"] = datetime.now().isoformat()
        
        self._save_store(data)
        print(f"Password '{name}' deleted successfully.")
    
    def search_passwords(self, query: str) -> list:
        """Search password entries by name or site."""
        entries = self.list_passwords()
        query_lower = query.lower()
        
        results = []
        for entry in entries:
            if (query_lower in entry["name"].lower() or 
                query_lower in entry["site"].lower() or
                query_lower in entry["username"].lower()):
                results.append(entry)
        
        return results
    
    def export_passwords(self, output_file: str):
        """Export passwords to JSON file (unencrypted - use carefully)."""
        data = self._load_store()
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Passwords exported to {output_file}")
        print("WARNING: Exported file is unencrypted. Handle with care.")
    
    def import_passwords(self, input_file: str):
        """Import passwords from JSON file."""
        with open(input_file, 'r') as f:
            import_data = json.load(f)
        
        data = self._load_store()
        
        imported_count = 0
        for name, entry in import_data.get("entries", {}).items():
            data["entries"][name] = entry
            imported_count += 1
        
        data["metadata"]["modified"] = datetime.now().isoformat()
        self._save_store(data)
        
        print(f"Imported {imported_count} password entries.")


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
    
    # Storage commands
    parser.add_argument("--store", type=str, help="Store password with given name")
    parser.add_argument("--retrieve", type=str, help="Retrieve password by name")
    parser.add_argument("--list", action="store_true", help="List all stored passwords")
    parser.add_argument("--delete", type=str, help="Delete stored password by name")
    parser.add_argument("--search", type=str, help="Search stored passwords")
    parser.add_argument("--export", type=str, help="Export passwords to file")
    parser.add_argument("--import", type=str, dest="import_file", help="Import passwords from file")
    
    # Storage metadata
    parser.add_argument("--username", type=str, default="", help="Username for stored password")
    parser.add_argument("--notes", type=str, default="", help="Notes for stored password")
    parser.add_argument("--store-file", type=str, help="Custom password store file location")
    parser.add_argument("--master-password", type=str, help="Master password for storage (for testing only - not secure!)")
    
    args = parser.parse_args()
    
    generator = PasswordGenerator()
    store = None
    if any([args.store, args.retrieve, args.list, args.delete, args.search, args.export, args.import_file]):
        store = PasswordStore(args.store_file)
        if args.master_password:
            store.master_password = args.master_password
    
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
        
        elif args.store:
            if not store:
                store = PasswordStore(args.store_file)
            
            # Generate password if not provided via stdin
            if args.key:
                password = generator.generate_from_key(
                    key=args.key,
                    length=args.length,
                    use_lowercase=not args.no_lowercase,
                    use_uppercase=not args.no_uppercase,
                    use_digits=not args.no_digits,
                    use_special=not args.no_special,
                    exclude_ambiguous=args.exclude_ambiguous,
                    site=args.site,
                    counter=args.counter
                )
            else:
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
            
            store.store_password(args.store, password, args.site, args.username, args.notes)
            print(f"Generated password: {password}")
        
        elif args.retrieve:
            entry = store.retrieve_password(args.retrieve)
            print(f"Name: {args.retrieve}")
            print(f"Password: {entry['password']}")
            if entry.get('site'):
                print(f"Site: {entry['site']}")
            if entry.get('username'):
                print(f"Username: {entry['username']}")
            if entry.get('notes'):
                print(f"Notes: {entry['notes']}")
            print(f"Created: {entry.get('created', 'Unknown')}")
            print(f"Modified: {entry.get('modified', 'Unknown')}")
        
        elif args.list:
            entries = store.list_passwords()
            if not entries:
                print("No passwords stored.")
            else:
                print(f"{'Name':<20} {'Site':<25} {'Username':<20} {'Modified':<20}")
                print("-" * 85)
                for entry in entries:
                    modified = entry['modified'][:10] if entry['modified'] else 'Unknown'
                    print(f"{entry['name']:<20} {entry['site']:<25} {entry['username']:<20} {modified:<20}")
        
        elif args.delete:
            store.delete_password(args.delete)
        
        elif args.search:
            results = store.search_passwords(args.search)
            if not results:
                print(f"No passwords found matching '{args.search}'.")
            else:
                print(f"Found {len(results)} matching entries:")
                print(f"{'Name':<20} {'Site':<25} {'Username':<20} {'Modified':<20}")
                print("-" * 85)
                for entry in results:
                    modified = entry['modified'][:10] if entry['modified'] else 'Unknown'
                    print(f"{entry['name']:<20} {entry['site']:<25} {entry['username']:<20} {modified:<20}")
        
        elif args.export:
            store.export_passwords(args.export)
        
        elif args.import_file:
            store.import_passwords(args.import_file)
            
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
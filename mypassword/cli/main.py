"""Command-line interface for the password generator."""

import argparse
import sys
from typing import Optional

from ..core.generator import PasswordGenerator
from ..core.store import PasswordStore
from ..utils.exceptions import ValidationError, StorageError, CryptographyError


class PasswordCLI:
    """Command-line interface for password operations."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.generator = PasswordGenerator()
        self.store: Optional[PasswordStore] = None
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create and configure argument parser."""
        parser = argparse.ArgumentParser(
            description="Generate secure passwords and manage password storage",
            epilog="Examples:\n"
                   "  %(prog)s -l 16                    # Generate 16-char password\n"
                   "  %(prog)s --key mykey --site github.com  # Generate from key\n"
                   "  %(prog)s --store gmail --key mykey      # Store generated password\n"
                   "  %(prog)s --list                         # List stored passwords",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Password generation options
        gen_group = parser.add_argument_group('Password Generation')
        gen_group.add_argument("-l", "--length", type=int, default=12,
                              help="Password length (default: 12)")
        gen_group.add_argument("--no-lowercase", action="store_true",
                              help="Exclude lowercase letters")
        gen_group.add_argument("--no-uppercase", action="store_true",
                              help="Exclude uppercase letters")
        gen_group.add_argument("--no-digits", action="store_true",
                              help="Exclude digits")
        gen_group.add_argument("--no-special", action="store_true",
                              help="Exclude special characters")
        gen_group.add_argument("--exclude-ambiguous", action="store_true",
                              help="Exclude ambiguous characters (0, O, 1, l, I)")
        gen_group.add_argument("--custom-chars", type=str, default="",
                              help="Additional custom characters")
        gen_group.add_argument("--min-lowercase", type=int, default=0,
                              help="Minimum lowercase letters")
        gen_group.add_argument("--min-uppercase", type=int, default=0,
                              help="Minimum uppercase letters")
        gen_group.add_argument("--min-digits", type=int, default=0,
                              help="Minimum digits")
        gen_group.add_argument("--min-special", type=int, default=0,
                              help="Minimum special characters")
        gen_group.add_argument("-c", "--count", type=int, default=1,
                              help="Number of passwords to generate")
        
        # Key-based generation
        key_group = parser.add_argument_group('Key-based Generation')
        key_group.add_argument("--key", type=str,
                              help="Generate deterministic password from key")
        key_group.add_argument("--site", type=str, default="",
                              help="Site name for unique passwords per site")
        key_group.add_argument("--counter", type=int, default=1,
                              help="Counter for different passwords with same key")
        
        # Passphrase generation
        phrase_group = parser.add_argument_group('Passphrase Generation')
        phrase_group.add_argument("--passphrase", action="store_true",
                                 help="Generate passphrase instead of password")
        phrase_group.add_argument("--words", type=int, default=4,
                                 help="Number of words in passphrase (default: 4)")
        phrase_group.add_argument("--separator", type=str, default="-",
                                 help="Passphrase word separator (default: -)")
        phrase_group.add_argument("--no-capitalize", action="store_true",
                                 help="Don't capitalize passphrase words")
        phrase_group.add_argument("--add-numbers", action="store_true",
                                 help="Add numbers to passphrase")
        
        # Password analysis
        analysis_group = parser.add_argument_group('Password Analysis')
        analysis_group.add_argument("--check", type=str,
                                   help="Check strength of provided password")
        
        # Storage operations
        store_group = parser.add_argument_group('Password Storage')
        store_group.add_argument("--store", type=str,
                                help="Store password with given name")
        store_group.add_argument("--retrieve", type=str,
                                help="Retrieve password by name")
        store_group.add_argument("--list", action="store_true",
                                help="List all stored passwords")
        store_group.add_argument("--delete", type=str,
                                help="Delete stored password by name")
        store_group.add_argument("--search", type=str,
                                help="Search stored passwords")
        store_group.add_argument("--export", type=str,
                                help="Export passwords to file")
        store_group.add_argument("--import", type=str, dest="import_file",
                                help="Import passwords from file")
        
        # Storage metadata
        meta_group = parser.add_argument_group('Storage Metadata')
        meta_group.add_argument("--username", type=str, default="",
                               help="Username for stored password")
        meta_group.add_argument("--notes", type=str, default="",
                               help="Notes for stored password")
        meta_group.add_argument("--store-file", type=str,
                               help="Custom password store file location")
        meta_group.add_argument("--master-password", type=str,
                               help="Master password for storage (for testing only - not secure!)")
        
        return parser
    
    def init_store_if_needed(self, args) -> None:
        """Initialize password store if needed for storage operations."""
        if any([args.store, args.retrieve, args.list, args.delete, 
               args.search, args.export, args.import_file]):
            self.store = PasswordStore(args.store_file)
            if args.master_password:
                self.store.master_password = args.master_password
    
    def handle_password_check(self, password: str) -> None:
        """Handle password strength checking."""
        strength = self.generator.check_strength(password)
        print(f"Password: {password}")
        print(f"Strength: {strength['strength']} (Score: {strength['score']})")
        print(f"Length: {strength['length']}")
        
        components = []
        if strength['has_lowercase']:
            components.append("lowercase")
        if strength['has_uppercase']:
            components.append("uppercase")
        if strength['has_digits']:
            components.append("digits")
        if strength['has_special']:
            components.append("special")
        print(f"Contains: {', '.join(components) if components else 'none'}")
        
        if strength['feedback']:
            print("\\nSuggestions:")
            for suggestion in strength['feedback']:
                print(f"  • {suggestion}")
    
    def handle_password_storage(self, args) -> None:
        """Handle password storage operations."""
        if not self.store:
            self.store = PasswordStore(args.store_file)
        
        # Generate password
        if args.key:
            password = self.generator.generate_from_key(
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
            password = self.generator.generate_password(
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
        
        self.store.store_password(args.store, password, args.site, args.username, args.notes)
        print(f"Password '{args.store}' stored successfully.")
        print(f"Generated password: {password}")
    
    def handle_password_retrieval(self, name: str) -> None:
        """Handle password retrieval."""
        entry = self.store.retrieve_password(name)
        print(f"Name: {name}")
        print(f"Password: {entry['password']}")
        
        if entry.get('site'):
            print(f"Site: {entry['site']}")
        if entry.get('username'):
            print(f"Username: {entry['username']}")
        if entry.get('notes'):
            print(f"Notes: {entry['notes']}")
        
        print(f"Created: {entry.get('created', 'Unknown')}")
        print(f"Modified: {entry.get('modified', 'Unknown')}")
    
    def handle_password_listing(self) -> None:
        """Handle password listing."""
        entries = self.store.list_passwords()
        if not entries:
            print("No passwords stored.")
        else:
            print(f"{'Name':<20} {'Site':<25} {'Username':<20} {'Modified':<20}")
            print("-" * 85)
            for entry in entries:
                modified = entry['modified'][:10] if entry['modified'] else 'Unknown'
                print(f"{entry['name']:<20} {entry['site']:<25} "
                      f"{entry['username']:<20} {modified:<20}")
    
    def handle_password_deletion(self, name: str) -> None:
        """Handle password deletion."""
        self.store.delete_password(name)
        print(f"Password '{name}' deleted successfully.")
    
    def handle_password_search(self, query: str) -> None:
        """Handle password searching."""
        results = self.store.search_passwords(query)
        if not results:
            print(f"No passwords found matching '{query}'.")
        else:
            print(f"Found {len(results)} matching entries:")
            print(f"{'Name':<20} {'Site':<25} {'Username':<20} {'Modified':<20}")
            print("-" * 85)
            for entry in results:
                modified = entry['modified'][:10] if entry['modified'] else 'Unknown'
                print(f"{entry['name']:<20} {entry['site']:<25} "
                      f"{entry['username']:<20} {modified:<20}")
    
    def handle_password_export(self, output_file: str) -> None:
        """Handle password export."""
        self.store.export_passwords(output_file)
        print(f"Passwords exported to {output_file}")
        print("WARNING: Exported file is unencrypted. Handle with care.")
    
    def handle_password_import(self, input_file: str) -> None:
        """Handle password import."""
        count = self.store.import_passwords(input_file)
        print(f"Imported {count} password entries.")
    
    def handle_key_generation(self, args) -> None:
        """Handle key-based password generation."""
        for i in range(args.count):
            password = self.generator.generate_from_key(
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
    
    def handle_passphrase_generation(self, args) -> None:
        """Handle passphrase generation."""
        for _ in range(args.count):
            passphrase = self.generator.generate_passphrase(
                word_count=args.words,
                separator=args.separator,
                capitalize=not args.no_capitalize,
                add_numbers=args.add_numbers
            )
            print(passphrase)
    
    def handle_standard_generation(self, args) -> None:
        """Handle standard password generation."""
        for _ in range(args.count):
            password = self.generator.generate_password(
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
    
    def run(self, args=None) -> None:
        """Run the CLI application."""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        try:
            self.init_store_if_needed(parsed_args)
            
            # Handle different operations
            if parsed_args.check:
                self.handle_password_check(parsed_args.check)
            
            elif parsed_args.store:
                self.handle_password_storage(parsed_args)
            
            elif parsed_args.retrieve:
                self.handle_password_retrieval(parsed_args.retrieve)
            
            elif parsed_args.list:
                self.handle_password_listing()
            
            elif parsed_args.delete:
                self.handle_password_deletion(parsed_args.delete)
            
            elif parsed_args.search:
                self.handle_password_search(parsed_args.search)
            
            elif parsed_args.export:
                self.handle_password_export(parsed_args.export)
            
            elif parsed_args.import_file:
                self.handle_password_import(parsed_args.import_file)
            
            elif parsed_args.key:
                self.handle_key_generation(parsed_args)
            
            elif parsed_args.passphrase:
                self.handle_passphrase_generation(parsed_args)
            
            else:
                self.handle_standard_generation(parsed_args)
        
        except ValidationError as e:
            print(f"Validation Error: {e}", file=sys.stderr)
            sys.exit(1)
        except StorageError as e:
            print(f"Storage Error: {e}", file=sys.stderr)
            sys.exit(1)
        except CryptographyError as e:
            print(f"Encryption Error: {e}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\\nOperation cancelled.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    """Entry point for the CLI application."""
    cli = PasswordCLI()
    cli.run()
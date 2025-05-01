# MyPassword Generator

A secure password generator and manager with encrypted local storage.

## Features

- **Secure Password Generation**: Generate cryptographically secure passwords with customizable options
- **Key-Based Generation**: Generate deterministic passwords from a master key for different sites
- **Passphrase Generation**: Create memorable word-based passphrases
- **Encrypted Storage**: Store passwords locally with AES encryption and master password protection
- **Password Analysis**: Check password strength and get improvement suggestions
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

### From Source
```bash
git clone https://github.com/edge9/mypassword-generator.git
cd mypassword-generator
pip install -r requirements.txt
python main.py --help
```

### Using pip (if published)
```bash
pip install mypassword-generator
mypassword --help
```

## Quick Start

### Generate a Random Password
```bash
python main.py -l 16                    # 16-character password
python main.py -c 3                     # Generate 3 passwords
python main.py --exclude-ambiguous      # Exclude ambiguous characters
```

### Generate Key-Based Passwords
```bash
python main.py --key "mykey123"         # Generate from key
python main.py --key "mykey123" --site "github.com"  # Site-specific password
python main.py --key "mykey123" --counter 2          # Alternative password
```

### Generate Passphrases
```bash
python main.py --passphrase             # 4-word passphrase
python main.py --passphrase --words 6   # 6-word passphrase
python main.py --passphrase --add-numbers  # Add numbers
```

### Password Storage
```bash
# Store a generated password
python main.py --store "github" --key "mykey" --site "github.com" --username "myuser"

# List stored passwords
python main.py --list

# Retrieve a password
python main.py --retrieve "github"

# Search passwords
python main.py --search "git"

# Delete a password
python main.py --delete "github"
```

### Password Analysis
```bash
python main.py --check "mypassword123"
```

## Command Line Options

### Password Generation
- `-l, --length`: Password length (default: 12)
- `--no-lowercase`: Exclude lowercase letters
- `--no-uppercase`: Exclude uppercase letters
- `--no-digits`: Exclude digits
- `--no-special`: Exclude special characters
- `--exclude-ambiguous`: Exclude ambiguous characters (0, O, 1, l, I)
- `--custom-chars`: Additional custom characters
- `--min-*`: Minimum character requirements
- `-c, --count`: Number of passwords to generate

### Key-Based Generation
- `--key`: Master key for deterministic generation
- `--site`: Site name for unique passwords
- `--counter`: Counter for multiple passwords from same key

### Passphrase Options
- `--passphrase`: Generate passphrase instead of password
- `--words`: Number of words (default: 4)
- `--separator`: Word separator (default: -)
- `--no-capitalize`: Don't capitalize words
- `--add-numbers`: Add random numbers

### Storage Operations
- `--store`: Store password with given name
- `--retrieve`: Retrieve password by name
- `--list`: List all stored passwords
- `--delete`: Delete stored password
- `--search`: Search stored passwords
- `--export`: Export to JSON file
- `--import`: Import from JSON file

### Storage Metadata
- `--username`: Username for stored password
- `--site`: Site/service name
- `--notes`: Additional notes
- `--store-file`: Custom storage file location

## Security Features

- **Cryptographically Secure**: Uses Python's `secrets` module for random generation
- **Key Derivation**: PBKDF2 with 100,000 iterations for key-based generation
- **Encrypted Storage**: AES encryption via Fernet (symmetric encryption)
- **Master Password**: Required for accessing stored passwords
- **File Permissions**: Storage file created with 600 permissions (owner read/write only)
- **No Plaintext**: Passwords never stored in plaintext

## Storage Format

Passwords are stored in an encrypted file (`~/.password_store.enc` by default) with the following structure:
- Salt (16 bytes) + Encrypted JSON data
- Each entry contains: password, site, username, notes, timestamps
- Master password required for decryption

## Examples

### Basic Usage
```bash
# Generate a secure 20-character password
python main.py -l 20

# Generate password excluding ambiguous characters
python main.py --exclude-ambiguous -l 16

# Generate 5 passwords at once
python main.py -c 5
```

### Site-Specific Passwords
```bash
# Generate password for GitHub
python main.py --key "mykey123" --site "github.com"

# Generate password for Gmail  
python main.py --key "mykey123" --site "gmail.com"

# Same key, different sites = different passwords
```

### Password Management
```bash
# Store GitHub password
python main.py --store "github" --key "mykey" --site "github.com" --username "johndoe"

# Store with notes
python main.py --store "work-email" --notes "Work email account" --username "john@company.com"

# List all passwords
python main.py --list

# Find GitHub-related passwords
python main.py --search "github"
```

## Security Best Practices

1. **Use a strong master password** for storage encryption
2. **Use unique keys** for different password generation contexts
3. **Keep your storage file backed up** (it's encrypted)
4. **Don't share your master key** or storage file
5. **Use the export feature carefully** (exports are unencrypted)

## Dependencies

- Python 3.6+
- cryptography >= 45.0.0

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
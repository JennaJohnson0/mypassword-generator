"""Password storage functionality with encryption."""

import json
import os
import sys
import getpass
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..utils.exceptions import StorageError, CryptographyError, ValidationError
from ..utils.validators import validate_store_name, validate_master_password


class PasswordStore:
    """Encrypted password storage manager."""
    
    def __init__(self, store_file: Optional[str] = None):
        """
        Initialize password store with encrypted local storage.
        
        Args:
            store_file: Custom path for storage file, defaults to ~/.password_store.enc
        """
        if store_file is None:
            home_dir = os.path.expanduser("~")
            self.store_file = os.path.join(home_dir, ".password_store.enc")
        else:
            self.store_file = store_file
        
        self.master_password: Optional[str] = None
        self._cipher_suite = None
    
    def store_password(
        self,
        name: str,
        password: str,
        site: str = "",
        username: str = "",
        notes: str = ""
    ) -> None:
        """
        Store a password entry.
        
        Args:
            name: Unique name for the password entry
            password: The password to store
            site: Associated website or service
            username: Associated username
            notes: Additional notes
            
        Raises:
            ValidationError: If name is invalid
            StorageError: If storage operation fails
        """
        validate_store_name(name)
        
        try:
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
            
        except Exception as e:
            raise StorageError(f"Failed to store password: {e}")
    
    def retrieve_password(self, name: str) -> Dict[str, Any]:
        """
        Retrieve a password entry.
        
        Args:
            name: Name of the password entry
            
        Returns:
            Dictionary containing password entry data
            
        Raises:
            StorageError: If entry not found or retrieval fails
        """
        try:
            data = self._load_store()
            
            if name not in data["entries"]:
                raise StorageError(f"Password entry '{name}' not found")
            
            return data["entries"][name]
            
        except StorageError:
            raise
        except Exception as e:
            raise StorageError(f"Failed to retrieve password: {e}")
    
    def list_passwords(self) -> List[Dict[str, str]]:
        """
        List all password entries.
        
        Returns:
            List of dictionaries with entry metadata
            
        Raises:
            StorageError: If listing fails
        """
        try:
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
            
        except Exception as e:
            raise StorageError(f"Failed to list passwords: {e}")
    
    def delete_password(self, name: str) -> None:
        """
        Delete a password entry.
        
        Args:
            name: Name of the password entry to delete
            
        Raises:
            StorageError: If entry not found or deletion fails
        """
        try:
            data = self._load_store()
            
            if name not in data["entries"]:
                raise StorageError(f"Password entry '{name}' not found")
            
            del data["entries"][name]
            data["metadata"]["modified"] = datetime.now().isoformat()
            
            self._save_store(data)
            
        except StorageError:
            raise
        except Exception as e:
            raise StorageError(f"Failed to delete password: {e}")
    
    def search_passwords(self, query: str) -> List[Dict[str, str]]:
        """
        Search password entries by name, site, or username.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching password entries
            
        Raises:
            StorageError: If search fails
        """
        try:
            entries = self.list_passwords()
            query_lower = query.lower()
            
            results = []
            for entry in entries:
                if (query_lower in entry["name"].lower() or 
                    query_lower in entry["site"].lower() or
                    query_lower in entry["username"].lower()):
                    results.append(entry)
            
            return results
            
        except Exception as e:
            raise StorageError(f"Failed to search passwords: {e}")
    
    def export_passwords(self, output_file: str) -> None:
        """
        Export passwords to JSON file (unencrypted).
        
        Args:
            output_file: Path to output file
            
        Raises:
            StorageError: If export fails
        """
        try:
            data = self._load_store()
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            raise StorageError(f"Failed to export passwords: {e}")
    
    def import_passwords(self, input_file: str) -> int:
        """
        Import passwords from JSON file.
        
        Args:
            input_file: Path to input file
            
        Returns:
            Number of passwords imported
            
        Raises:
            StorageError: If import fails
        """
        try:
            with open(input_file, 'r') as f:
                import_data = json.load(f)
            
            data = self._load_store()
            
            imported_count = 0
            for name, entry in import_data.get("entries", {}).items():
                data["entries"][name] = entry
                imported_count += 1
            
            data["metadata"]["modified"] = datetime.now().isoformat()
            self._save_store(data)
            
            return imported_count
            
        except Exception as e:
            raise StorageError(f"Failed to import passwords: {e}")
    
    def _get_master_password(self) -> str:
        """
        Get master password from user.
        
        Returns:
            Master password string
            
        Raises:
            StorageError: If password input fails
        """
        if self.master_password is None:
            try:
                self.master_password = getpass.getpass("Enter master password: ")
            except (EOFError, KeyboardInterrupt):
                raise StorageError("Password input cancelled")
            except Exception:
                # Fallback for non-interactive environments
                print("Enter master password: ", end="", flush=True)
                try:
                    self.master_password = input()
                except (EOFError, KeyboardInterrupt):
                    raise StorageError("Password input cancelled")
        
        validate_master_password(self.master_password)
        return self.master_password
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from master password.
        
        Args:
            password: Master password
            salt: Salt for key derivation
            
        Returns:
            Derived key bytes
            
        Raises:
            CryptographyError: If key derivation fails
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key
        except Exception as e:
            raise CryptographyError(f"Key derivation failed: {e}")
    
    def _init_cipher(self, password: str, salt: Optional[bytes] = None) -> tuple:
        """
        Initialize cipher suite with master password.
        
        Args:
            password: Master password
            salt: Optional salt, generates new if None
            
        Returns:
            Tuple of (cipher_suite, salt)
            
        Raises:
            CryptographyError: If cipher initialization fails
        """
        try:
            if salt is None:
                salt = os.urandom(16)
            
            key = self._derive_key(password, salt)
            cipher_suite = Fernet(key)
            return cipher_suite, salt
        except Exception as e:
            raise CryptographyError(f"Cipher initialization failed: {e}")
    
    def _load_store(self) -> Dict[str, Any]:
        """
        Load and decrypt password store.
        
        Returns:
            Dictionary containing store data
            
        Raises:
            StorageError: If loading fails
            CryptographyError: If decryption fails
        """
        if not os.path.exists(self.store_file):
            return {
                "entries": {},
                "metadata": {"created": datetime.now().isoformat()}
            }
        
        try:
            with open(self.store_file, 'rb') as f:
                data = f.read()
            
            if len(data) < 16:
                return {
                    "entries": {},
                    "metadata": {"created": datetime.now().isoformat()}
                }
            
            # Extract salt and encrypted data
            salt = data[:16]
            encrypted_data = data[16:]
            
            # Initialize cipher
            master_password = self._get_master_password()
            cipher_suite, _ = self._init_cipher(master_password, salt)
            
            # Decrypt and load JSON
            try:
                decrypted_data = cipher_suite.decrypt(encrypted_data)
                return json.loads(decrypted_data.decode())
            except Exception:
                raise CryptographyError("Failed to decrypt password store. Wrong master password?")
                
        except (StorageError, CryptographyError):
            raise
        except Exception as e:
            raise StorageError(f"Failed to load password store: {e}")
    
    def _save_store(self, data: Dict[str, Any]) -> None:
        """
        Encrypt and save password store.
        
        Args:
            data: Store data to save
            
        Raises:
            StorageError: If saving fails
            CryptographyError: If encryption fails
        """
        try:
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
            
        except (StorageError, CryptographyError):
            raise
        except Exception as e:
            raise StorageError(f"Failed to save password store: {e}")
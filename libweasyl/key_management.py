"""
Enhanced key management with rotation support.
from pyfed: https://dev.funkwhale.audio/funkwhale/pyfed

"""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
import asyncio
import sys
from pathlib import Path

from weasyl import define
from weasyl.error import WeasylError


class KeyRotation:
    """Key rotation configuration."""

    def __init__(self,
                 rotation_interval: int = 30,  # days
                 key_overlap: int = 2,  # days
                 key_size: int = 2048):
        self.rotation_interval = rotation_interval
        self.key_overlap = key_overlap
        self.key_size = key_size


class KeyPair:
    """Key pair with metadata."""

    def __init__(self,
                 private_key: RSAPrivateKey,
                 public_key: RSAPublicKey,
                 created_at: datetime,
                 expires_at: datetime,
                 key_id: str):
        self.private_key = private_key
        self.public_key = public_key
        self.created_at = created_at
        self.expires_at = expires_at
        self.key_id = key_id


class KeyManager:
    """Enhanced key management with rotation."""

    def __init__(
            self,
            domain: str,
            keys_path: str,
            rotation_config: Optional[Dict[str, Any]] = None
    ):
        """Initialize key manager."""
        self.domain = domain
        self.keys_path = Path(keys_path)
        self.rotation_config = rotation_config or KeyRotation()
        self.active_keys: Dict[str, KeyPair] = {}
        self._rotation_task = None

    async def initialize(self) -> None:
        """Initialize key manager."""
        try:
            define.append_to_log(__name__, level="info",
                                 message=f"Initializing key manager with path: {self.keys_path}")

            # Create keys directory
            self.keys_path.mkdir(parents=True, exist_ok=True)
            define.append_to_log(__name__, level="info", message="Created keys directory")

            # Load existing keys
            await self._load_existing_keys()
            define.append_to_log(__name__, level="info", message=f"Loaded {len(self.active_keys)} existing keys")

            # Generate initial keys if none exist
            if not self.active_keys:
                define.append_to_log(__name__, level="info", message="No active keys found, generating new key pair")
                await self.generate_key_pair()
                define.append_to_log(__name__, level="info",
                                     message=f"Generated new key pair, total active keys: {len(self.active_keys)}")

            # Start rotation task
            self._rotation_task = asyncio.create_task(self._key_rotation_loop())
            define.append_to_log(__name__, level="info", message="Started key rotation task")

        except Exception as e:
            define.append_to_log(__name__, level="error", message=f"Failed to initialize key manager: {e}")
            raise WeasylError(f"Key manager initialization failed: {e}")

    async def generate_key_pair(self) -> KeyPair:
        """Generate new key pair."""
        try:
            define.append_to_log(__name__, level="info", message="Generating new key pair")
            # Generate keys
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.rotation_config.key_size
            )
            public_key = private_key.public_key()

            # Set validity period
            created_at = datetime.utcnow()
            expires_at = created_at + timedelta(days=self.rotation_config.rotation_interval)

            # Generate key ID (for HTTP use)
            timestamp = int(created_at.timestamp())
            key_id = f"https://{self.domain}/keys/{timestamp}"

            define.append_to_log(__name__, level="debug", message=f"Key ID generated: {key_id}")

            # Generate safe file path (for storage)
            safe_timestamp = str(int(created_at.timestamp()))
            safe_domain = self.domain.replace(':', '_').replace('/', '_').replace('.', '_')
            safe_path = f"{safe_domain}_{safe_timestamp}"

            define.append_to_log(__name__, level="info", message=f"Generated key ID: {key_id}")
            define.append_to_log(__name__, level="info", message=f"Safe path: {safe_path}")

            # Create key pair
            key_pair = KeyPair(
                private_key=private_key,
                public_key=public_key,
                created_at=created_at,
                expires_at=expires_at,
                key_id=key_id
            )

            # Save keys with safe path
            await self._save_key_pair(key_pair, safe_path)
            define.append_to_log(__name__, level="info", message="Saved key pair to disk")

            # Add to active keys
            self.active_keys[key_id] = key_pair
            define.append_to_log(__name__, level="info",
                                 message=f"Added key pair to active keys. Total active keys: {len(self.active_keys)}")

            return key_pair

        except Exception as e:
            define.append_to_log(__name__, level="error", message=f"Failed to generate key pair: {e}")
            raise WeasylError(f"Key generation failed: {e}")

    async def rotate_keys(self) -> None:
        """Perform key rotation."""
        try:
            define.append_to_log(__name__, level="info", message="Starting key rotation")

            # Generate new key pair
            new_pair = await self.generate_key_pair()
            define.append_to_log(__name__, level="info", message=f"Generated new key pair: {new_pair.key_id}")

            # Remove expired keys
            now = datetime.utcnow()
            expired = [
                key_id for key_id, pair in self.active_keys.items()
                if pair.expires_at < now - timedelta(days=self.rotation_config.key_overlap)
            ]

            for key_id in expired:
                await self._archive_key_pair(self.active_keys[key_id])
                del self.active_keys[key_id]
                define.append_to_log(__name__, level="info", message=f"Archived expired key: {key_id}")

            # Announce new key to federation
            await self._announce_key_rotation(new_pair)

        except Exception as e:
            define.append_to_log(__name__, level="error", message=f"Key rotation failed: {e}")
            raise WeasylError(f"Key rotation failed: {e}")

    async def get_active_key(self) -> KeyPair:
        """Get the most recent active key."""
        if not self.active_keys:
            raise WeasylError("No active keys available")

        # Return most recently created key
        return max(
            self.active_keys.values(),
            key=lambda k: k.created_at
        )

    async def get_public_key_pem(self, username: str) -> str:
        """Get the public key in PEM format for a user."""
        active_key = await self.get_active_key()
        return active_key.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    async def verify_key(self, key_id: str, domain: str) -> bool:
        """Verify a key's validity."""
        try:
            # Check if key is one of our active keys
            if key_id in self.active_keys:
                key_pair = self.active_keys[key_id]
                return datetime.now(timezone.utc) <= key_pair.expires_at

            # For external keys, verify with their server
            # Implementation for external key verification
            return False

        except Exception as e:
            define.append_to_log(__name__, level="error", message=f"Key verification failed: {e}")
            return False

    async def _load_existing_keys(self) -> None:
        """Load existing keys from disk."""
        try:
            # Recursively search for all json files
            for key_file in self.keys_path.rglob("*.json"):
                define.append_to_log(__name__, level="info", message=f"Found key metadata file: {key_file}")
                with open(key_file, 'r') as f:
                    metadata = json.loads(f.read())

                # Get the private key path from the same directory as the metadata
                private_key_path = key_file.parent / f"{key_file.stem}_private.pem"
                define.append_to_log(__name__, level="info", message=f"Looking for private key at: {private_key_path}")

                if not private_key_path.exists():
                    define.append_to_log(__name__, level="warning", message=f"Private key not found at {private_key_path}")
                    continue

                with open(private_key_path, 'rb') as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )

                # Create key pair
                key_pair = KeyPair(
                    private_key=private_key,
                    public_key=private_key.public_key(),
                    created_at=datetime.fromisoformat(metadata['created_at']),
                    expires_at=datetime.fromisoformat(metadata['expires_at']),
                    key_id=metadata['key_id']
                )

                # Add to active keys if not expired
                if datetime.now(timezone.utc) <= key_pair.expires_at:
                    self.active_keys[key_pair.key_id] = key_pair
                    define.append_to_log(__name__, level="info", message=f"Loaded active key: {key_pair.key_id}")
                else:
                    define.append_to_log(__name__, level="info", message=f"Skipping expired key: {key_pair.key_id}")

        except Exception as e:
            define.append_to_log(__name__, level="error", message=f"Failed to load existing keys: {e}")
            raise WeasylError(f"Failed to load existing keys: {e}")

    async def _save_key_pair(self, key_pair: KeyPair, safe_path: str) -> None:
        """Save key pair to disk."""
        try:
            # Save private key
            private_key_path = self.keys_path / f"{safe_path}_private.pem"
            private_pem = key_pair.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)

            # Save public key
            public_key_path = self.keys_path / f"{safe_path}_public.pem"
            public_pem = key_pair.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)

            # Save metadata
            metadata = {
                'key_id': key_pair.key_id,
                'created_at': key_pair.created_at.isoformat(),
                'expires_at': key_pair.expires_at.isoformat(),
                'safe_path': safe_path
            }
            metadata_path = self.keys_path / f"{safe_path}.json"
            with open(metadata_path, 'w') as f:
                f.write(json.dumps(metadata))

        except Exception as e:
            define.append_to_log(__name__, level="error", message=f"Failed to save key pair: {e}")
            raise WeasylError(f"Failed to save key pair: {e}")

    async def _archive_key_pair(self, key_pair: KeyPair) -> None:
        """Archive an expired key pair."""
        try:
            archive_dir = self.keys_path / "archive"
            archive_dir.mkdir(exist_ok=True)

            # Move key files to archive
            for ext in ['_private.pem', '_public.pem', '.json']:
                src = self.keys_path / f"{key_pair.key_id}{ext}"
                dst = archive_dir / f"{key_pair.key_id}{ext}"
                if src.exists():
                    src.rename(dst)

        except Exception as e:
            define.append_to_log(__name__, level="error", message=f"Failed to archive key pair: {e}")
            raise WeasylError(f"Failed to archive key pair: {e}")

    async def _announce_key_rotation(self, key_pair: KeyPair) -> None:
        """Announce new key to federation."""
        # Implementation for announcing key rotation to federation
        pass

    async def _key_rotation_loop(self) -> None:
        """Background task for key rotation."""
        while True:
            try:
                # Check for keys needing rotation
                now = datetime.utcnow()
                for key_pair in self.active_keys.values():
                    if key_pair.expires_at <= now + timedelta(days=1):
                        await self.rotate_keys()
                        break

                # Sleep for a day
                await asyncio.sleep(86400)

            except Exception as e:
                define.append_to_log(__name__, level="error", message=f"Key rotation loop error: {e}")
                await asyncio.sleep(3600)  # Retry in an hour

    async def close(self) -> None:
        """Clean up resources."""
        if self._rotation_task:
            self._rotation_task.cancel()
            try:
                await self._rotation_task
            except asyncio.CancelledError:
                pass

    async def get_active_private_key(self) -> RSAPrivateKey:
        """Get the most recent active private key."""
        if not self.active_keys:
            raise WeasylError("No active keys available")

        # Return the private key of the most recently created key
        most_recent_key = max(
            self.active_keys.values(),
            key=lambda k: k.created_at
        )
        return most_recent_key.private_key

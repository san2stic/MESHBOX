"""MeshBox Crypto Module — Node identity and cryptographic primitives."""

from meshbox.crypto.node_identity import NodeIdentity

# Re-export legacy classes so existing code (cli.py, daemon.py, etc.) keeps working.
# The old meshbox/crypto.py is shadowed by this package.
import importlib.util as _ilu
import os as _os

_legacy = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "crypto.py")
if _os.path.isfile(_legacy):
    _spec = _ilu.spec_from_file_location("meshbox._crypto_legacy", _legacy)
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    Identity = _mod.Identity
    CryptoEngine = _mod.CryptoEngine
else:
    Identity = None  # type: ignore[assignment]
    CryptoEngine = None  # type: ignore[assignment]

__all__ = ["NodeIdentity", "Identity", "CryptoEngine"]

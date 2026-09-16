try:
    from s0_core.config import CONFIG
    __version__ = CONFIG.get("version", "2.2.1")
except ImportError:
    __version__ = "2.2.1"

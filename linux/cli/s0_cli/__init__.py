try:
    from s0_core.config import CONFIG
    __version__ = CONFIG.get("version", "2.4.0")
except ImportError:
    __version__ = "2.4.0"

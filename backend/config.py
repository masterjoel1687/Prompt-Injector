import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration."""

    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))

    MAX_TIMEOUT = int(os.getenv("MAX_TIMEOUT", "30"))
    MAX_CONCURRENT_TESTS = int(os.getenv("MAX_CONCURRENT_TESTS", "5"))

    DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "demo-model")

    # AI Security Judge / Adaptive Red Team
    AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"
    AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama")
    AI_MODEL = os.getenv("AI_MODEL", "gemma3")
    AI_BASE_URL = os.getenv(
        "AI_BASE_URL",
        "http://127.0.0.1:11434"
    )

    ADAPTIVE_ROUNDS = int(os.getenv("ADAPTIVE_ROUNDS", "2"))
    ADAPTIVE_VARIANTS = int(os.getenv("ADAPTIVE_VARIANTS", "3"))

    # Demo mode
    DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
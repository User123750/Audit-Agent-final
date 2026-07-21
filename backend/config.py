"""
Application configuration.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:

    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

    OLLAMA_HOST = os.getenv(
        "OLLAMA_HOST",
        "http://localhost:11434"
    )

    PROJECT_NAME = "OddNet"

    PROJECT_VERSION = "1.0"

    LOG_LEVEL = "INFO"


settings = Settings()
# Fixed: all credentials loaded from environment variables
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///testdb.db")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
APP_ENV = os.getenv("APP_ENV", "production")

# Credentials are now loaded from environment — no hardcoded values
password = os.getenv("APP_PASSWORD")
api_key = os.getenv("API_KEY")
secret_key = os.getenv("SECRET_KEY")

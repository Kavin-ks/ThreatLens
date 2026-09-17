# =============================================================================
# INTENTIONALLY VULNERABLE - END-TO-END TEST FIXTURE ONLY
# DO NOT USE IN PRODUCTION - THESE ARE FAKE TEST CREDENTIALS
# =============================================================================
# This file deliberately contains hardcoded credentials to verify that
# ThreatLens's secrets scanner (secrets.hardcoded_credentials) detects them.
# The values below are completely fabricated and have never been used anywhere.
# =============================================================================

DATABASE_URL = "sqlite:///testdb.db"
DEBUG = True
APP_ENV = "development"

# Fake hardcoded password — triggers hardcoded_password pattern (CWE-798)
password = "Fake_Password_Value_ForTesting_XR9a"  # noqa: S105

# Fake API key — triggers generic_api_key pattern (CWE-798)
api_key = "fake_api_key_threatlens_e2etest_xyz123456789"  # noqa: S106

# Fake secret key — triggers hardcoded_secret_key pattern (CWE-798)
secret_key = "fake_secret_key_threatlens_e2etest_abc789"  # noqa: S105

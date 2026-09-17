INTENTIONALLY VULNERABLE APPLICATION - FOR TESTING ONLY
=========================================================

This application is part of ThreatLens's end-to-end test suite.
It contains deliberately introduced security vulnerabilities to
verify that ThreatLens scanners detect them correctly.

DO NOT:
  - Deploy this application in any environment
  - Use these credentials for anything real
  - Connect this application to any real database or service

The credentials in config.py are completely fake and have never
been used for any real service. They exist solely to trigger
ThreatLens's hardcoded-secrets scanner in automated tests.

The SQL injection vulnerability in app.py is intentional and
demonstrates error-based injection using an in-memory SQLite
database with no persistent state.

This directory is part of ThreatLens's Phase 8 E2E validation.

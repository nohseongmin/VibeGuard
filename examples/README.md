# Vulnerable example app

`vibe_coded_app` contains intentionally insecure Python and JavaScript examples to demonstrate VibeGuard. All key values are fake. Do not copy this code into a real application.

## Scanning

```bash
python -m vibeguard scan examples/vibe_coded_app
python -m vibeguard scan examples/vibe_coded_app --offline
```

The offline command skips registry lookups.

## Included issues

| File | Examples |
|---|---|
| `app.py` | Hardcoded OpenAI and AWS keys and database password (VG-SECRET-001/003/009); f-string SQL (VG-SQLI-001); user input in shell commands (VG-EXEC-003); disabled TLS verification (VG-WEB-003); pickle deserialization (VG-EXEC-004); MD5 passwords (VG-CRYPTO-001); random tokens (VG-CRYPTO-003); debug mode and public binding (VG-WEB-001/006). |
| `server.js` | Hardcoded JWT secret (VG-SECRET-009); unrestricted CORS (VG-WEB-002); template-string SQL (VG-SQLI-003); Math.random tokens (VG-CRYPTO-004); child_process.exec interpolation (VG-EXEC-007); eval (VG-EXEC-006); rejectUnauthorized:false (VG-WEB-004). |
| Dependency files | Nonexistent packages `flask-easy-auth` and `react-hook-form-validator-pro` (VG-SLOP-001); possible typos `reqeusts` and `expres` (VG-SLOP-002). |

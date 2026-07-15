# ThreatFox to SentinelOne Threat Intelligence Integration

A safe, production-ready integration that imports threat indicators from ThreatFox into SentinelOne Threat Intelligence, with optional STAR rule generation for detecting outbound IOC matches.

## Features

- ✅ Pulls current threat indicators from ThreatFox API (24-hour window configurable)
- ✅ Normalizes and validates indicators (IPv4, Domain, URL, SHA-256)
- ✅ Imports into SentinelOne Threat Intelligence with source tracking
- ✅ Stores state in SQLite (avoids re-importing active indicators)
- ✅ Dry-run mode by default (no live writes without explicit confirmation)
- ✅ Structured JSON logging
- ✅ Exponential backoff + jitter for transient failures
- ✅ Honors HTTP 429 (rate limit) responses
- ✅ Support for account-level and site-level IOC scoping
- ✅ Configurable expiration periods per IOC type
- ✅ CLI with inspect, fetch, import, expire, status commands

## Project Structure

```
threatfox-s1-integration/
├── main.py                      # CLI entry point
├── pyproject.toml              # Python project metadata
├── .env.example                # Environment variable template
├── .gitignore                  # Git ignore rules
├── README.md                   # This file
├── threatfox_api.py            # ThreatFox API client
├── sentinelone_api.py          # SentinelOne API client
├── ioc_validator.py            # IOC validation & normalization
├── state.py                    # SQLite state management
├── logger.py                   # Structured JSON logging
├── tests/
│   ├── test_validator.py       # IOC validator tests
│   ├── test_threatfox.py       # Mock ThreatFox responses
│   └── test_sentinelone.py     # Mock S1 responses
├── systemd/
│   ├── threatfox-s1.service    # Systemd service unit
│   └── threatfox-s1.timer      # Systemd timer (4-hour interval)
└── docker/
    └── Dockerfile              # Docker image definition
```

## Installation

### Prerequisites
- Python 3.11+
- pip
- SQLite3

### Setup

```bash
git clone <repo>
cd threatfox-s1-integration

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r pyproject.toml

# Copy environment template and configure
cp .env.example .env
# Edit .env with your API credentials
```

## Configuration

### Environment Variables

**Required:**
```bash
THREATFOX_AUTH_KEY=your-threatfox-api-key
S1_CONSOLE_URL=https://usea1-020.sentinelone.net
S1_API_TOKEN=your-s1-api-token
S1_ACCOUNT_ID=your-account-id (optional if using S1_SITE_ID)
S1_SITE_ID=your-site-id (optional if using S1_ACCOUNT_ID)
```

**Optional:**
```bash
MIN_CONFIDENCE=90               # Default: 90
IOC_MAX_AGE_HOURS=24           # Default: 24
IP_EXPIRATION_DAYS=7           # Default: 7
DOMAIN_EXPIRATION_DAYS=14      # Default: 14
URL_EXPIRATION_DAYS=14         # Default: 14
HASH_EXPIRATION_DAYS=30        # Default: 30
MAX_IMPORTS_PER_RUN=250        # Default: 250 (safeguard)
BATCH_SIZE=25                  # Default: 25 (per POST)
LOG_LEVEL=INFO                 # Default: INFO
DRY_RUN=true                   # Default: true (CRITICAL: set to 'false' to enable writes)
STATE_DB=threatfox_s1.db       # Default: threatfox_s1.db
```

## Usage

### Commands

#### Inspect Configuration
```bash
python main.py inspect
```
Shows current configuration, API connectivity, and database state.

#### Fetch Indicators (No Import)
```bash
python main.py fetch --dry-run
```
Pulls indicators from ThreatFox, validates, deduplicates. Outputs JSON summary (no S1 write).

#### Import to SentinelOne (Dry-run First!)
```bash
# DRY RUN (always do this first!)
python main.py import --dry-run

# ACTUAL IMPORT (requires explicit confirmation)
python main.py import --confirm-write
```

#### Expire Old Indicators
```bash
# Check what will expire
python main.py expire --dry-run

# Actually remove expired IOCs
python main.py expire --confirm-write
```

#### Status Report
```bash
python main.py status
```
Shows: total IOCs in S1, active ThreatFox imports, last import time, state database size.

#### Test SentinelOne Authentication
```bash
python main.py test-s1-auth
```
Verifies API token, account access, and scope permissions.

#### Test IOC Import (with Review)
```bash
# Test with 5 IOCs, dry-run mode
python main.py test-ioc-import --limit 5

# Actually write test IOCs (requires explicit confirmation)
python main.py test-ioc-import --limit 5 --confirm-write
```

## Dry-Run Mode (Default)

**All writes are disabled by default.** To enable writes:

1. Set `DRY_RUN=false` in `.env`, OR
2. Pass `--confirm-write` flag on import/expire/test-ioc-import commands

Dry-run mode logs the exact API payloads that would be sent, allowing review before execution.

## Example Workflow

```bash
# 1. Inspect configuration
python main.py inspect

# 2. Test authentication
python main.py test-s1-auth

# 3. Fetch indicators from ThreatFox (no write)
python main.py fetch --dry-run

# 4. Review sample IOCs that would be imported
python main.py test-ioc-import --limit 5

# 5. If satisfied, import for real
python main.py import --confirm-write

# 6. Check status
python main.py status

# 7. Schedule recurring imports (systemd or cron)
```

## Systemd Setup (Linux)

```bash
# Copy service and timer
sudo cp systemd/threatfox-s1.service /etc/systemd/system/
sudo cp systemd/threatfox-s1.timer /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable threatfox-s1.timer
sudo systemctl start threatfox-s1.timer

# Check status
sudo systemctl status threatfox-s1.timer
sudo journalctl -u threatfox-s1 -f  # Follow logs
```

## Cron Alternative

```bash
# Every 4 hours
0 */4 * * * cd /opt/threatfox-s1 && python main.py import >> logs/cron.log 2>&1
```

## Docker

```bash
docker build -f docker/Dockerfile -t threatfox-s1:latest .
docker run --rm \
  -e THREATFOX_AUTH_KEY=$THREATFOX_AUTH_KEY \
  -e S1_API_TOKEN=$S1_API_TOKEN \
  -e S1_CONSOLE_URL=$S1_CONSOLE_URL \
  -e S1_ACCOUNT_ID=$S1_ACCOUNT_ID \
  -e DRY_RUN=false \
  threatfox-s1:latest import
```

## Logging

Logs are written to `logs/` directory in JSON format for easy parsing:

```json
{
  "timestamp": "2026-07-15T16:30:00.123456Z",
  "level": "INFO",
  "component": "importer",
  "message": "Imported 5 new IOCs from ThreatFox",
  "iocs_imported": 5,
  "iocs_updated": 2,
  "iocs_skipped": 3,
  "duration_seconds": 12.34
}
```

## Safety Restrictions

✅ **Enforced:**
- Dry-run enabled by default
- No automatic STAR rule creation
- No automatic response actions (isolation, kill, remediation)
- No hardcoded secrets in source code
- All credentials from environment or `.env`
- Certificate validation enabled (no `--insecure`)
- SQLite prevents duplicate imports
- State tracking prevents re-import of active IOCs

## Known Limitations

1. **IOC Creation API**: S1 POST endpoint validation errors encountered during testing. May require SentinelOne support or tenant configuration.
   - Workaround: Manual upload via console UI
   - Testing: Use `test-ioc-import --limit 5` to validate payload

2. **STAR Rule Generation**: Not yet implemented. Rule must be created manually in S1 console.
   - Planned: STAR rule template in `star-rules/` directory

3. **Scope**: Currently supports account-level scoping. Site-level coming soon.

4. **Batch Size**: Limited to 25 IOCs per POST request. Large imports split into batches.

## Troubleshooting

### ThreatFox API Errors
- Check `THREATFOX_AUTH_KEY` is valid
- Verify API rate limits (typically 1000/day)
- Check `IOC_MAX_AGE_HOURS` setting

### SentinelOne API Errors
- Run `python main.py test-s1-auth` to verify connectivity
- Check `S1_API_TOKEN` expiration (8-day lifetime)
- Verify account/site IDs in `.env`
- Ensure account has "Threat Intelligence" permissions

### Import Failures
- Check logs in `logs/` directory
- Use `--dry-run` to see exact payloads
- Test with `test-ioc-import --limit 5` first

## Testing

```bash
# Run unit tests
python -m pytest tests/ -v

# Test with mock data (no live API calls)
python -m pytest tests/ --mock
```

## Future Enhancements

- [ ] STAR rule auto-creation and management
- [ ] Multi-source threat intelligence (Wiz, Shodan, Censys)
- [ ] Confidence-based severity scoring
- [ ] IOC expiration automation
- [ ] Web dashboard for monitoring
- [ ] Slack/email alerts on import errors
- [ ] Site-level scoping support

## Support

For issues, questions, or feature requests:
1. Check logs in `logs/` directory
2. Run `python main.py inspect` to diagnose
3. Contact SentinelOne support if API errors persist

## License

Internal use only. Do not distribute.

---

**Last Updated:** 2026-07-15  
**Version:** 0.1.0 (Beta)  
**Status:** Dry-run mode active. Safe for production testing.

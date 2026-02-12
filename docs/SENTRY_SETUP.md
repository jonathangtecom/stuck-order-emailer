# Sentry Error Tracking Setup

This guide explains how to set up Sentry error tracking for stuck-order-emailer.

## Prerequisites

- Sentry account (free tier: https://sentry.io/signup/)
- 5,000 errors/month limit on free tier

## Setup Steps

### 1. Create Sentry Project

1. Log in to https://sentry.io
2. Click "Create Project"
3. Select platform: **Python + Flask**
4. Name: `stuck-order-emailer`
5. Copy the DSN (looks like: `https://abc123@o123456.ingest.sentry.io/7654321`)

### 2. Configure Environment Variables

Add to `.env`:
```bash
SENTRY_DSN=https://your-actual-dsn@o123456.ingest.sentry.io/7654321
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.0
```

**Environment values:**
- `production` - Live deployment
- `staging` - Staging/test server
- `development` - Local development

### 3. Deploy with Docker

Build with git commit tracking:
```bash
export GIT_COMMIT=$(git rev-parse --short HEAD)
docker-compose build
docker-compose up -d
```

### 4. Verify Integration

Run the test script:
```bash
python3 test_sentry_manual.py
```

Check Sentry dashboard:
1. Go to https://sentry.io
2. Select your project
3. You should see the test error within 1-2 minutes

### 5. Monitor Errors

**Dashboard:** https://sentry.io/organizations/your-org/issues/

**Useful filters:**
- By store: `store_name:my-store`
- By environment: `environment:production`
- By error type: `ValueError`, `RequestException`, etc.

## What Gets Tracked

### Automatic Tracking
- All unhandled exceptions in Flask routes
- Background job failures (APScheduler)
- API request failures (Shopify, ParcelPanel, SendGrid)
- Template rendering errors
- Database errors

### Context Included
- Store ID and name (for processor errors)
- Order number (when applicable)
- Request URL and method
- User authentication status (not email/name)
- Git commit hash (release tracking)
- Sequence of API calls (breadcrumbs)

### Filtered Data (Never Sent)
- API keys (Shopify, ParcelPanel, SendGrid)
- Admin password
- Customer emails (in request data)
- Session cookies
- Any variable named `*password*`, `*api_key*`, `*token*`

## Free Tier Management

**Current limit:** 5,000 errors/month

**Estimated usage:**
- Normal operation: 0-10 errors/month
- API outage (1 hour): ~50-100 errors
- Critical bug: 100-500 errors

**If you hit the limit:**
1. Sentry will stop accepting new errors but won't break the app
2. Fix the recurring error causing the spike
3. Consider upgrading or filtering noisy errors

## Troubleshooting

### No errors appearing in Sentry

1. Check SENTRY_DSN is set correctly in `.env`
2. Look for log line: `Sentry initialized: environment=production`
3. Run manual test: `python3 test_sentry_manual.py`
4. Check Sentry project settings for quota limits

### Too many errors

1. Identify the recurring error in Sentry dashboard
2. Fix the root cause
3. Consider adding error sampling or ignoring specific errors

### Sensitive data leaked

1. Check `_sentry_before_send()` function in [app.py](../app.py)
2. Add new sensitive field names to filters
3. Redeploy and verify with test

## Setting Up Alerts

1. Go to your Sentry project settings
2. Navigate to **Alerts** → **Create Alert**
3. Recommended alerts:
   - **New Issue Alert**: Get notified when a new type of error appears
   - **High Volume Alert**: Get notified if errors spike above normal
4. Configure notification channels:
   - Email (default)
   - Slack (recommended for team)
   - PagerDuty (for critical production issues)

## Support

- Sentry docs: https://docs.sentry.io/platforms/python/guides/flask/
- Project issues: https://github.com/your-org/stuck-order-emailer/issues

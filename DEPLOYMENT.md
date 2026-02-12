# Deployment Guide

## Docker Deployment with Sentry

### Prerequisites

- Docker and Docker Compose installed
- `.env` file configured with required variables
- Sentry project created (optional, see [docs/SENTRY_SETUP.md](docs/SENTRY_SETUP.md))

### Environment Setup

Required environment variables in `.env`:

```bash
# Core Configuration
ADMIN_PASSWORD=your-secure-password
SENDGRID_API_KEY=SG.your-sendgrid-api-key
SECRET_KEY=your-random-secret-key
RUN_TOKEN=your-random-run-token
SCHEDULE_HOUR=9
SCHEDULE_MINUTE=0

# Sentry (optional - leave blank to disable)
SENTRY_DSN=https://your-dsn@sentry.io/project-id
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.0
```

### Building

Build with git commit for release tracking:

```bash
export GIT_COMMIT=$(git rev-parse --short HEAD)
docker-compose build
```

**Note:** If you don't set `GIT_COMMIT`, the release will be tagged as `unknown` in Sentry.

### Deploy

```bash
docker-compose up -d
```

### Verify Deployment

Check logs:
```bash
docker logs stuck-order-emailer
```

Look for these key messages:
```
Sentry initialized: environment=production
App starting — DB: /app/data/app.db, Templates: /app/data/templates
Scheduler started — daily run at 09:00
```

If Sentry is disabled (empty `SENTRY_DSN`):
```
Sentry disabled (no SENTRY_DSN configured)
```

### Verify Sentry Integration (Optional)

If you configured Sentry, verify errors are being captured:

1. Check the Sentry initialization log message
2. Trigger a test error (see [docs/SENTRY_SETUP.md](docs/SENTRY_SETUP.md))
3. Visit your Sentry dashboard to confirm the error appears

### Updating Deployment

To update with a new version:

```bash
# Pull latest code
git pull

# Rebuild with new git commit
export GIT_COMMIT=$(git rev-parse --short HEAD)
docker-compose build

# Restart container
docker-compose down
docker-compose up -d

# Verify
docker logs stuck-order-emailer
```

### Monitor Errors

**Application Logs:**
```bash
# View logs
docker logs -f stuck-order-emailer

# View logs from last hour
docker logs --since 1h stuck-order-emailer
```

**Sentry Dashboard:**
- Visit https://sentry.io
- View errors with full context, stack traces, and breadcrumbs
- Set up alerts for new errors or error spikes

### Volume Mounts and File Persistence

**CRITICAL**: The application requires proper Docker volume mounts to persist data (database and templates) to the host machine's disk. Without proper volume configuration, files will be lost when containers restart.

#### Verifying Volume Mounts

Before deployment, ensure the `data/` directory exists on the host:

```bash
# Create data directory if it doesn't exist
mkdir -p data/templates

# Set proper permissions
chmod 755 data
chmod 755 data/templates

# Verify directory exists
ls -la data/
```

The `docker-compose.yml` file includes this volume mount:
```yaml
volumes:
  - ./data:/app/data
```

This maps the host's `./data` directory to `/app/data` inside the container.

#### Testing File Persistence

After deployment, verify files persist correctly:

```bash
# 1. Access the web UI and create a test template
# 2. Save it with some content

# 3. Verify file exists in container
docker-compose exec app cat /app/data/templates/test.html

# 4. Verify file exists on host
cat data/templates/test.html

# 5. Restart container
docker-compose restart app

# 6. Verify file still exists
docker-compose exec app cat /app/data/templates/test.html

# 7. Reload the template in web UI - content should be intact
```

#### Diagnostic Endpoint

The application includes a diagnostic endpoint to verify volume mounts:

```bash
# Access diagnostics (must be logged in)
curl https://your-server.com/api/system/diagnostics

# Expected output:
{
  "templates_path": "data/templates",
  "database_path": "data/app.db",
  "templates_path_absolute": "/app/data/templates",
  "database_path_absolute": "/app/data/app.db",
  "templates_dir_exists": true,
  "templates_dir_writable": true,
  "database_exists": true,
  "current_user": "root",
  "working_directory": "/app",
  "template_files": ["example.html"],
  "template_files_count": 1
}
```

**If `templates_dir_exists` is false or `templates_dir_writable` is false:**
- Stop the container
- Create/fix the data directory
- Restart the container

```bash
docker-compose down
mkdir -p data/templates
chmod -R 755 data
docker-compose up -d
```

### Troubleshooting

#### Templates disappear after saving

**Symptoms:**
- You save a template and see "Saved successfully"
- When you reload the page or reopen the file, content is gone
- File is empty or doesn't exist

**Root Cause:**
- The `data/` directory doesn't exist on the host machine
- Files are being written to the container's ephemeral storage
- Container restart or recreation loses the files

**Solution:**
```bash
# Stop container
docker-compose down

# Ensure data directory exists with proper structure
mkdir -p data/templates
chmod 755 data data/templates

# Restart
docker-compose up -d

# Verify volume mount is working
docker-compose exec app ls -la /app/data/
docker-compose exec app ls -la /app/data/templates/

# Check diagnostic endpoint
curl https://your-server.com/api/system/diagnostics
```

#### Autosave shows error (✗ Error)

**Symptoms:**
- Save status indicator shows red "✗ Error"
- Autosave doesn't work, but manual save might
- Browser console shows HTTP errors

**Check:**
1. Open browser DevTools (F12) → Console tab for JavaScript errors
2. Check Network tab for failed POST requests to `/api/templates/`
3. Check server logs: `docker-compose logs -f app`
4. Access diagnostic endpoint to verify file permissions

**Common Causes:**
- Volume mount not working (files can't be written)
- Permission issues with data directory
- Network connectivity issues

**Solution:**
- Verify volume mounts as described above
- Check file permissions
- Review server logs for specific errors

#### Container won't start

```bash
# Check container status
docker ps -a

# View full logs
docker logs stuck-order-emailer

# Check environment variables
docker exec stuck-order-emailer env | grep SENTRY
```

#### Sentry not capturing errors

1. Verify `SENTRY_DSN` is set: `docker exec stuck-order-emailer env | grep SENTRY_DSN`
2. Check logs for "Sentry initialized" message
3. Run manual test from host: `python3 test_sentry_manual.py`
4. Check Sentry dashboard quota limits

#### Database issues

```bash
# Check database file exists
docker exec stuck-order-emailer ls -lh /app/data/app.db

# Backup database
docker cp stuck-order-emailer:/app/data/app.db ./backup-$(date +%Y%m%d).db
```

### Production Checklist

Before deploying to production:

- [ ] `.env` file configured with secure passwords
- [ ] `SENTRY_DSN` configured for error tracking
- [ ] `SENTRY_ENVIRONMENT` set to `production`
- [ ] Scheduled time (`SCHEDULE_HOUR`, `SCHEDULE_MINUTE`) configured
- [ ] Caddy reverse proxy configured (if using)
- [ ] Database backup strategy in place
- [ ] Sentry alerts configured (email/Slack)
- [ ] Test manual run: `curl -X POST http://localhost:8080/api/run?dry_run=1 -H "Authorization: Bearer $RUN_TOKEN"`
- [ ] Verify logs are accessible

### Backup Strategy

**Database:**
```bash
# Backup before updates
docker cp stuck-order-emailer:/app/data/app.db ./backups/app-$(date +%Y%m%d-%H%M%S).db

# Automated daily backup (add to cron)
0 2 * * * docker cp stuck-order-emailer:/app/data/app.db /path/to/backups/app-$(date +\%Y\%m\%d).db
```

**Templates:**
```bash
# Backup templates directory
docker cp stuck-order-emailer:/app/data/templates ./backups/templates-$(date +%Y%m%d)
```

### Rollback Procedure

If a deployment causes issues:

```bash
# Stop current container
docker-compose down

# Restore database backup
cp ./backups/app-20260212.db ./data/app.db

# Checkout previous git commit
git checkout HEAD~1

# Rebuild and deploy
export GIT_COMMIT=$(git rev-parse --short HEAD)
docker-compose build
docker-compose up -d

# Verify
docker logs stuck-order-emailer
```

### Security Considerations

- Never commit `.env` file to git
- Rotate `SECRET_KEY` and `RUN_TOKEN` periodically
- Keep SendGrid API key secure
- Review Sentry data filters regularly
- Use HTTPS with Caddy reverse proxy
- Limit access to Docker host

### Performance Monitoring

**Sentry (if configured):**
- View error trends over time
- Track which stores/orders have most errors
- Monitor API failure rates

**Docker Stats:**
```bash
# View resource usage
docker stats stuck-order-emailer

# Check disk usage
docker exec stuck-order-emailer du -sh /app/data
```

### Support

For issues:
1. Check application logs: `docker logs stuck-order-emailer`
2. Check Sentry dashboard (if configured)
3. Review [docs/SENTRY_SETUP.md](docs/SENTRY_SETUP.md) for Sentry-specific issues
4. Open an issue with logs and error details

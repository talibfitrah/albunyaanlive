# Streaming Channels - User Manual

A simple guide to managing your HLS streaming channels.

---

## Quick Reference

| Task | Command |
|------|---------|
| Start all channels | `./restart.sh` |
| Stop all channels | `./stop_all.sh` |
| Check channel status | `./channel_status.sh` |
| Restart one channel | `./graceful_restart.sh basmah` |
| Start one channel | `./channel_basmah_revised.sh` |

---

## Starting Channels

### Start All Channels

```bash
cd /home/msa/Development/scripts/albunyaan/channels
./restart.sh
```

This will:
1. Stop all running channels
2. Start all enabled channels
3. Run in the background

### Start a Single Channel

```bash
cd /home/msa/Development/scripts/albunyaan/channels
./channel_basmah_revised.sh
```

Replace `basmah` with any channel name (e.g., `channel_zaad_revised.sh`).

---

## Stopping Channels

### Stop All Channels

```bash
cd /home/msa/Development/scripts/albunyaan/channels
./stop_all.sh
```

This will:
- Stop all streaming processes
- Clear all HLS segment files

### Stop a Single Channel

To stop just one channel (e.g., `basmah`):

```bash
# Find the process ID
./channel_status.sh

# Then kill it (replace 12345 with actual PID from status)
kill 12345
```

---

## Checking Status

### View All Channel Status

```bash
./channel_status.sh
```

This shows a table with:
- **Channel** - Channel name
- **Status** - RUNNING (green), STOPPED (red), or STALE (yellow)
- **Uptime** - How long it has been running
- **Last Segment** - How fresh the stream is
- **URL** - Primary or Backup1/Backup2
- **Restarts** - Number of restarts in the last hour
- **PID** - Process ID

Example output:
```
Channel              | Status   | Uptime   | Last Segment | URL      | Restarts | PID
==========================================================================================
basmah               | RUNNING  | 2h 15m   | 3s           | Primary  | 0        | 12345
zaad                 | RUNNING  | 1h 30m   | 2s           | Backup1  | 1        | 12346
almajd-news          | STOPPED  | -        | 45s          | -        | 0        | -
```

### Get Status as JSON (for scripts)

```bash
./channel_status.sh --json
```

---

## Restarting Channels

### Graceful Restart (Recommended)

Restarts a channel with minimal viewer interruption:

```bash
./graceful_restart.sh basmah
```

This:
1. Starts a new stream in a temporary location
2. Waits for it to be healthy
3. Swaps to the new stream
4. Viewers experience almost no interruption

### Quick Restart (All Channels)

```bash
./restart.sh
```

---

## Channel Configuration

Each channel has its own configuration file. For example, `channel_basmah_revised.sh`:

```bash
# Primary stream URL
stream_url="http://example.com/stream/1234"

# Backup URLs (used when primary fails)
stream_url_backup1="https://backup1.example.com/stream.m3u8"
stream_url_backup2="https://backup2.example.com/stream.m3u8"

# Output location
rtmp_url="/var/www/html/stream/hls/basmah/master.m3u8"

# Quality setting (see below)
scale=3
```

### Editing a Channel

1. Open the channel file:
   ```bash
   nano channel_basmah_revised.sh
   ```

2. Change the URLs or settings

3. Save the file (Ctrl+X, then Y, then Enter)

4. Restart the channel:
   ```bash
   ./graceful_restart.sh basmah
   ```

**Note:** Backup URL changes are picked up automatically every 60 seconds (no restart needed).

**New:** Primary auto-fallback
- If a channel is currently running on a backup URL, it checks every 5 minutes whether the primary URL is healthy again.
- When the primary returns (HTTP 2xx), the stream switches back automatically and resets failure counters.

**Hot-reload format**
- You can update backups either by editing `stream_url_backup1/stream_url_backup2` or by setting a single `BACKUP_URLS` variable:
  ```bash
  BACKUP_URLS="http://backup1.example.com/stream.m3u8|http://backup2.example.com/stream.m3u8"
  ```

**Important:** HTTPS sources
- Your `ffmpeg` build must support `https` input to use `https://...` stream URLs. If not, the manager logs `UNSUPPORTED_PROTOCOL` and skips those URLs.

### Scale Settings (Quality)

| Scale | Description | When to Use |
|-------|-------------|-------------|
| 0 | Copy stream as-is | Best quality, low CPU |
| 2 | Copy with threads | Same as 0, slightly better handling |
| 3 | GPU encoding (NVIDIA) | High quality, uses GPU |
| 4 | GPU + resize to 1080p | When source is higher than 1080p |
| 5 | CPU encoding | When GPU is not available |
| 6 | CPU + resize to 1080p | CPU fallback with resize |
| 7 | Copy with extended buffer | For unstable sources |
| 8 | CUDA passthrough | Direct GPU passthrough |

---

## Enabling/Disabling Channels

Channels are managed in `run_all_channels.sh`.

### To Disable a Channel

1. Open the file:
   ```bash
   nano run_all_channels.sh
   ```

2. Add `#` at the start of the channel line:
   ```bash
   # This channel is now disabled:
   #./channel_arrahmah.sh

   # This channel is still enabled:
   ./channel_basmah_revised.sh
   ```

3. Save and restart:
   ```bash
   ./restart.sh
   ```

### To Enable a Channel

Remove the `#` from the start of the line and restart.

---

## Automatic Health Monitoring

The system can automatically restart channels that stop working.

### Enable Auto-Restart

Add this to your crontab:

```bash
crontab -e
```

**Setup Prerequisites:**
1. Create the log directory: `mkdir -p /tmp/albunyaan-logs`
2. Ensure the directory is writable by your user

Add these lines:
```
*/2 * * * * /home/msa/Development/scripts/albunyaan/channels/health_monitor.sh >> /tmp/albunyaan-logs/health_cron.log 2>&1
0 */2 * * * find /tmp/albunyaan-logs -name "ffmpeg_error_*.log" -mmin +120 -delete 2>/dev/null
0 0 * * * truncate -s 10M /tmp/albunyaan-logs/health_cron.log 2>/dev/null
```

**Notes:**
- The second line permanently deletes ffmpeg error log files older than 120 minutes from the app directory.
- The third line caps the cron log file at 10MB daily to prevent unbounded growth.
- Consider running `find /tmp/albunyaan-logs -name "ffmpeg_error_*.log" -mmin +120` first (without `-delete`) to preview which files would be removed.

This checks all channels every 2 minutes and:
- Restarts stopped channels
- Restarts channels with stale segments (not updated in 15+ seconds)
- Limits to 5 automatic restarts per hour per channel

---

## Backup URL System

When the primary stream fails, the system automatically:

1. Tries the primary URL 3 times (with increasing wait times)
2. Switches to Backup 1
3. If Backup 1 fails, switches to Backup 2
4. Cycles through all URLs up to 5 times
5. Waits 2 minutes, then tries again

### Primary Recovery

While running on a backup, the system checks the primary every 5 minutes. When the primary comes back online, it automatically switches back.

**If primary is down for hours:** The stream stays on the backup until primary recovers. No manual action needed.

---

## Log Files

Logs are stored in the `logs` folder:

| File | Contents |
|------|----------|
| `logs/basmah.log` | Channel activity and URL switches |
| `logs/basmah.error.log` | Errors only |
| `logs/health_monitor.log` | Auto-restart activity |
| `logs/graceful_restart.log` | Graceful restart details |

### View Live Logs

```bash
# Watch a specific channel
tail -f logs/basmah.log

# Watch health monitor
tail -f logs/health_monitor.log
```

Logs are automatically rotated when they reach 50MB.

---

## Troubleshooting

### Channel Shows "STOPPED"

```bash
# Try starting it manually
./channel_basmah_revised.sh

# Check the log for errors
tail -50 logs/basmah.log
```

### Channel Shows "STALE"

The stream is running but not producing new segments:

```bash
# Graceful restart
./graceful_restart.sh basmah

# Check if source URL is working
curl -I "http://your-source-url"
```

### All Channels Stopped

```bash
./restart.sh
```

### Stream Keeps Switching to Backup

The primary source may be unstable. Check:

1. Is the primary URL correct?
2. Is the source server working?
3. Is there a network issue?

View the log to see what's happening:
```bash
tail -100 logs/basmah.log | grep -E "URL_SWITCH|4XX|PRIMARY"
```

### Can't Find a Channel Script

Channel scripts follow this naming pattern:
- `channel_CHANNELNAME_revised.sh` (newer format)
- `channel_CHANNELNAME.sh` (older format)

List all channel scripts:
```bash
ls -la channel_*.sh
```

---

## File Locations

| Path | Description |
|------|-------------|
| `/home/msa/Development/scripts/albunyaan/channels/` | All scripts |
| `/var/www/html/stream/hls/` | HLS output files |
| `/var/www/html/stream/hls/basmah/master.m3u8` | Channel playlist |
| `/tmp/stream_basmah.pid` | Process ID file |
| `/tmp/stream_basmah.lock` | Lock directory |

---

## Summary of Commands

```bash
# Go to the channels folder
cd /home/msa/Development/scripts/albunyaan/channels

# Start all channels
./restart.sh

# Stop all channels
./stop_all.sh

# Check status
./channel_status.sh

# Restart one channel gracefully
./graceful_restart.sh CHANNEL_NAME

# Start one channel
./channel_CHANNELNAME_revised.sh

# View logs
tail -f logs/CHANNELNAME.log

# Edit a channel
nano channel_CHANNELNAME_revised.sh
```

---

*Last updated: January 2026*

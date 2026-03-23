# VPN Detection Database

A free, self-hosted VPN / proxy detection database that updates automatically every day via GitHub Actions.

Covers commercial VPNs, Tor exit nodes, datacenter IPs, and open proxies — no API key, no rate limits.

---

## Files

| File | Purpose |
|---|---|
| `build_db.py` | Downloads all sources and builds `vpn_detection.db` |
| `.github/workflows/update-vpn-db.yml` | Runs `build_db.py` daily and publishes the DB as a GitHub Release |
| `VpnDetector.php` | WordPress plugin class — downloads the DB and queries it offline |

---

## Setup (5 steps)

### 1. Create a new GitHub repository
Push all files in this folder to it.

### 2. Enable Actions write permission
Go to **Settings → Actions → General → Workflow permissions** and select **Read and write permissions**.

### 3. Run the workflow once manually
Go to **Actions → Update VPN Detection Database → Run workflow**.  
After it completes, a `latest` release will appear with `vpn_detection.db` attached.

### 4. Edit `VpnDetector.php`
Replace the placeholder in `DB_URL` with your actual repo URL:

```php
const DB_URL = 'https://github.com/YOUR_USERNAME/YOUR_REPO/releases/latest/download/vpn_detection.db';
```

### 5. Integrate into SpamShield Pro

```php
// In your main plugin file:
require_once plugin_dir_path(__FILE__) . 'includes/class-vpn-detector.php';

// On activation:
register_activation_hook(__FILE__, function() {
    VpnDetector::register_cron();
});

// On deactivation:
register_deactivation_hook(__FILE__, function() {
    wp_clear_scheduled_hook('spamshield_update_vpn_db');
});

// In your spam scoring logic:
add_filter('spamshield_score', function($score, $submission) {
    $ip      = sanitize_text_field($_SERVER['REMOTE_ADDR']);
    $result  = VpnDetector::getInstance()->check($ip);

    if ($result['is_vpn']) {
        $penalty = match($result['type']) {
            'tor'        => 60,
            'vpn'        => 40,
            'proxy'      => 35,
            'datacenter' => 20,
            default      => 25,
        };
        $score += $penalty;
    }
    return $score;
}, 10, 2);
```

---

## Data sources

| Source | Type | URL |
|---|---|---|
| X4BNet | Commercial VPN ranges | github.com/X4BNet/lists_vpn |
| Tor Project | Tor exit nodes | check.torproject.org/torbulkexitlist |
| Firehol | Datacenter / hosting IPs | github.com/firehol/blocklist-ipsets |
| Stamparm ipsum (level 3) | Open proxies (high confidence) | github.com/stamparm/ipsum |

---

## How the DB is queried

IPs are stored as 32-bit integers. A range lookup is:

```sql
SELECT type, source FROM ip_ranges
WHERE ip_start <= {ip_int} AND ip_end >= {ip_int}
LIMIT 1
```

Both columns are indexed, so each lookup is a fast index-range scan even on shared hosting.
# vpn-detection
# vpn-detect
# vpn-detect

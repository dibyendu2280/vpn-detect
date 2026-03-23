<?php
/**
 * VPN / Proxy Detector for SpamShield Pro
 *
<<<<<<< HEAD
 * Two-layer offline detection — no API key, no rate limits, no external calls
 * at detection time.
 *
 * Layer 1 — IP range match  : vpn_detection.db  (built daily from X4BNet, Tor, Firehol, Stamparm)
 * Layer 2 — ASN match       : GeoLite2-ASN.mmdb + asn_blocklist table in vpn_detection.db
 *
 * Both databases download from YOUR GitHub Release and stay up-to-date via WP-Cron.
 *
 * ── Quick start ──────────────────────────────────────────────────────────────
 *
 *   require_once plugin_dir_path(__FILE__) . 'includes/class-vpn-detector.php';
 *
 *   register_activation_hook(__FILE__,   ['VpnDetector', 'register_cron']);
 *   register_deactivation_hook(__FILE__, function () {
 *       wp_clear_scheduled_hook('spamshield_update_vpn_db');
 *       wp_clear_scheduled_hook('spamshield_update_asn_mmdb');
 *   });
 *
 *   // In spam scoring:
 *   $result = VpnDetector::getInstance()->check($_SERVER['REMOTE_ADDR']);
 *   // ['is_vpn' => true,  'type' => 'vpn',        'source' => 'x4bnet_vpn']
 *   // ['is_vpn' => true,  'type' => 'datacenter',  'source' => 'asn', 'asn' => 'AS14061', 'org' => 'DigitalOcean']
 *   // ['is_vpn' => false]
 */
class VpnDetector {

    // ── Configuration — replace YOUR_USERNAME/YOUR_REPO ───────────────────────

    /** Stable URL for vpn_detection.db (IP ranges + ASN blocklist table). */
    const VPN_DB_URL = 'https://github.com/dibyendu2280/vpn-detection/releases/latest/download/vpn_detection.db';

    /** Stable URL for GeoLite2-ASN.mmdb (published by update-asn-db.yml workflow). */
    const ASN_MMDB_URL = 'https://github.com/dibyendu2280/vpn-detection/releases/latest/download/GeoLite2-ASN.mmdb';

    /** Re-download vpn_detection.db after this many days. */
    const VPN_DB_UPDATE_DAYS = 1;

    /** Re-download GeoLite2-ASN.mmdb after this many days (MaxMind updates weekly). */
    const ASN_MMDB_UPDATE_DAYS = 7;
=======
 * Downloads the self-hosted VPN detection SQLite database from GitHub Releases
 * and queries it offline — no API key, no rate limits, no external calls at
 * detection time.
 *
 * Drop this file into your plugin and include it:
 *
 *   require_once plugin_dir_path(__FILE__) . 'includes/class-vpn-detector.php';
 *
 * Basic usage:
 *
 *   $detector = VpnDetector::getInstance();
 *
 *   // Full result array
 *   $result = $detector->check('1.2.3.4');
 *   // ['is_vpn' => true,  'type' => 'vpn',  'source' => 'x4bnet_vpn']
 *   // ['is_vpn' => false]
 *
 *   // Boolean shorthand
 *   if ( $detector->isVpn( $_SERVER['REMOTE_ADDR'] ) ) { ... }
 *
 * Register WP-Cron for background updates (call once on plugin activation):
 *
 *   VpnDetector::register_cron();
 */
class VpnDetector {

    // ── Configuration — edit these two lines ─────────────────────────────────

    /** @var string Stable download URL (never changes, always points to latest build). */
    const DB_URL = 'https://github.com/YOUR_USERNAME/YOUR_REPO/releases/latest/download/vpn_detection.db';

    /** @var int Re-download the database after this many days. */
    const UPDATE_DAYS = 1;
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed

    // ─────────────────────────────────────────────────────────────────────────

    private static ?VpnDetector $instance = null;
<<<<<<< HEAD

    private ?\SQLite3     $db         = null;   // vpn_detection.db connection
    private ?\SQLite3Stmt $ip_stmt    = null;   // prepared: IP range lookup
    private ?\SQLite3Stmt $asn_stmt   = null;   // prepared: ASN blocklist lookup
    private mixed         $asn_reader = null;   // GeoIp2\Database\Reader

    private string $data_dir;
    private string $vpn_db_path;
    private string $asn_mmdb_path;

    private function __construct() {
        $this->data_dir      = WP_CONTENT_DIR . '/plugins/spamshield-pro';
        $this->vpn_db_path   = $this->data_dir . '/vpn_detection.db';
        $this->asn_mmdb_path = $this->data_dir . '/GeoLite2-ASN.mmdb';

        $this->ensure_dir();
        $this->init_vpn_db();
        $this->init_asn_mmdb();
    }

    public static function getInstance(): self {
        if (self::$instance === null) {
=======
    private ?\SQLite3            $db       = null;
    private string               $db_path;
    private ?\SQLite3Stmt        $stmt     = null;   // prepared statement cache

    private function __construct() {
        $this->db_path = WP_CONTENT_DIR . '/uploads/spamshield/vpn_detection.db';
        $this->init();
    }

    /** Singleton — use this to get the shared instance. */
    public static function getInstance(): self {
        if ( self::$instance === null ) {
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed
            self::$instance = new self();
        }
        return self::$instance;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
<<<<<<< HEAD
     * Check whether an IPv4 address is a VPN, Tor exit, datacenter, or proxy.
     *
     * @param  string $ip  IPv4 address (e.g. '1.2.3.4')
     * @return array{is_vpn: bool, type?: string, source?: string, asn?: string, org?: string}
     */
    public function check(string $ip): array {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ['is_vpn' => false];
        }

        if ($this->is_private($ip)) {
            return ['is_vpn' => false];
        }

        // Layer 1 — direct IP range match in vpn_detection.db
        $result = $this->check_ip_range($ip);
        if ($result['is_vpn']) {
            return $result;
        }

        // Layer 2 — ASN lookup via GeoLite2-ASN.mmdb + asn_blocklist table
        return $this->check_asn($ip);
    }

    /** Boolean shorthand. */
    public function isVpn(string $ip): bool {
        return $this->check($ip)['is_vpn'];
    }

    /**
     * Return metadata from the SQLite database (built_at, total_ranges, total_asns).
     *
     * @return array<string, string>
     */
    public function getMeta(): array {
        if (!$this->db) {
            return [];
        }
        $result = $this->db->query('SELECT key, value FROM meta');
        $meta   = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $meta[$row['key']] = $row['value'];
        }
        return $meta;
    }

    // ── Layer 1 : IP range ────────────────────────────────────────────────────

    private function check_ip_range(string $ip): array {
        if (!$this->db) {
            return ['is_vpn' => false];
        }

        $ip_int = ip2long($ip);
        if ($ip_int === false) {
            return ['is_vpn' => false];
        }

        if (!$this->ip_stmt) {
            $this->ip_stmt = $this->db->prepare(
=======
     * Check whether an IPv4 address is a known VPN, Tor, datacenter, or proxy.
     *
     * @param  string $ip  IPv4 address string (e.g. '1.2.3.4')
     * @return array{is_vpn: bool, type?: string, source?: string}
     */
    public function check( string $ip ): array {
        if ( ! $this->db ) {
            return [ 'is_vpn' => false ];
        }

        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return [ 'is_vpn' => false ];
        }

        // Skip private / reserved ranges — no point checking them
        if ( $this->is_private( $ip ) ) {
            return [ 'is_vpn' => false ];
        }

        $ip_int = ip2long( $ip );
        if ( $ip_int === false ) {
            return [ 'is_vpn' => false ];
        }

        // Lazy-prepare the statement once and reuse it
        if ( ! $this->stmt ) {
            $this->stmt = $this->db->prepare(
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed
                'SELECT type, source
                   FROM ip_ranges
                  WHERE ip_start <= :ip
                    AND ip_end   >= :ip
                  LIMIT 1'
            );
        }

<<<<<<< HEAD
        $this->ip_stmt->bindValue(':ip', $ip_int, SQLITE3_INTEGER);
        $res = $this->ip_stmt->execute();

        if ($res) {
            $row = $res->fetchArray(SQLITE3_ASSOC);
            $res->finalize();
            if ($row) {
=======
        $this->stmt->bindValue( ':ip', $ip_int, SQLITE3_INTEGER );
        $result = $this->stmt->execute();

        if ( $result ) {
            $row = $result->fetchArray( SQLITE3_ASSOC );
            $result->finalize();

            if ( $row ) {
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed
                return [
                    'is_vpn' => true,
                    'type'   => $row['type'],
                    'source' => $row['source'],
                ];
            }
        }

<<<<<<< HEAD
        return ['is_vpn' => false];
    }

    // ── Layer 2 : ASN ─────────────────────────────────────────────────────────

    private function check_asn(string $ip): array {
        if (!$this->asn_reader || !$this->db) {
            return ['is_vpn' => false];
        }

        // Step A — get ASN from GeoLite2-ASN.mmdb
        try {
            $record = $this->asn_reader->asn($ip);
            $asn    = 'AS' . $record->autonomousSystemNumber;   // e.g. 'AS9009'
            $org    = $record->autonomousSystemOrganization;    // e.g. 'M247 Ltd'
        } catch (\Exception $e) {
            return ['is_vpn' => false];   // IP not in ASN DB — not unusual
        }

        // Step B — check ASN against asn_blocklist table in vpn_detection.db
        if (!$this->asn_stmt) {
            $this->asn_stmt = $this->db->prepare(
                'SELECT type, org
                   FROM asn_blocklist
                  WHERE asn = :asn
                  LIMIT 1'
            );
        }

        $this->asn_stmt->bindValue(':asn', strtoupper($asn), SQLITE3_TEXT);
        $res = $this->asn_stmt->execute();

        if ($res) {
            $row = $res->fetchArray(SQLITE3_ASSOC);
            $res->finalize();
            if ($row) {
                return [
                    'is_vpn' => true,
                    'type'   => $row['type'],
                    'source' => 'asn',
                    'asn'    => $asn,
                    'org'    => $org ?: $row['org'],
                ];
            }
        }

        return ['is_vpn' => false];
=======
        return [ 'is_vpn' => false ];
    }

    /**
     * Convenience wrapper — returns true/false only.
     *
     * @param  string $ip  IPv4 address string
     * @return bool
     */
    public function isVpn( string $ip ): bool {
        return $this->check( $ip )['is_vpn'];
    }

    /**
     * Return metadata stored in the database (built_at date, total ranges, etc.)
     *
     * @return array<string, string>
     */
    public function getMeta(): array {
        if ( ! $this->db ) {
            return [];
        }
        $result = $this->db->query( 'SELECT key, value FROM meta' );
        $meta   = [];
        while ( $row = $result->fetchArray( SQLITE3_ASSOC ) ) {
            $meta[ $row['key'] ] = $row['value'];
        }
        return $meta;
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed
    }

    // ── Initialisation ────────────────────────────────────────────────────────

<<<<<<< HEAD
    private function init_vpn_db(): void {
        if ($this->needs_update($this->vpn_db_path, self::VPN_DB_UPDATE_DAYS)) {
            // 'SQLite format 3' is the literal header of every valid SQLite file
            $this->download_file(
                self::VPN_DB_URL,
                $this->vpn_db_path,
                'vpn_detection.db',
                'SQLite format 3'
            );
        }
        $this->open_sqlite();
    }

    private function init_asn_mmdb(): void {
        if ($this->needs_update($this->asn_mmdb_path, self::ASN_MMDB_UPDATE_DAYS)) {
            // MaxMind .mmdb magic: 0xABCDEF + "MaxMind.com"
            $this->download_file(
                self::ASN_MMDB_URL,
                $this->asn_mmdb_path,
                'GeoLite2-ASN.mmdb',
                "\xab\xcd\xef"
            );
        }
        $this->open_asn_reader();
    }

    private function open_sqlite(): void {
        if (!file_exists($this->vpn_db_path)) {
            return;
        }
        try {
            $this->db = new \SQLite3($this->vpn_db_path, SQLITE3_OPEN_READONLY);
            $this->db->busyTimeout(2000);
            $this->db->exec('PRAGMA cache_size = 4000;');
            $this->db->exec('PRAGMA temp_store = MEMORY;');
        } catch (\Exception $e) {
            error_log('[VpnDetector] Cannot open vpn_detection.db: ' . $e->getMessage());
=======
    private function init(): void {
        $this->ensure_dir();

        if ( $this->needs_update() ) {
            $this->download_db();
        }

        $this->open_db();
    }

    private function ensure_dir(): void {
        $dir = dirname( $this->db_path );
        if ( ! is_dir( $dir ) ) {
            wp_mkdir_p( $dir );
            // Block direct browser access to the data directory
            file_put_contents( $dir . '/.htaccess', "Deny from all\n" );
            file_put_contents( $dir . '/index.php', "<?php // silence\n" );
        }
    }

    private function needs_update(): bool {
        if ( ! file_exists( $this->db_path ) ) {
            return true;
        }
        $age_seconds = time() - filemtime( $this->db_path );
        return $age_seconds >= ( self::UPDATE_DAYS * DAY_IN_SECONDS );
    }

    private function open_db(): void {
        if ( ! file_exists( $this->db_path ) ) {
            return;
        }
        try {
            $this->db = new \SQLite3( $this->db_path, SQLITE3_OPEN_READONLY );
            $this->db->busyTimeout( 2000 );
            // Speed up reads
            $this->db->exec( 'PRAGMA cache_size = 4000;' );
            $this->db->exec( 'PRAGMA temp_store = MEMORY;' );
        } catch ( \Exception $e ) {
            error_log( '[VpnDetector] Cannot open database: ' . $e->getMessage() );
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed
            $this->db = null;
        }
    }

<<<<<<< HEAD
    private function open_asn_reader(): void {
        if (!file_exists($this->asn_mmdb_path)) {
            return;
        }
        // Requires the same composer package used for GeoLite2-Country:
        //   composer require geoip2/geoip2
        if (!class_exists('\GeoIp2\Database\Reader')) {
            error_log('[VpnDetector] GeoIp2 library missing. Run: composer require geoip2/geoip2');
            return;
        }
        try {
            $this->asn_reader = new \GeoIp2\Database\Reader($this->asn_mmdb_path);
        } catch (\Exception $e) {
            error_log('[VpnDetector] Cannot open GeoLite2-ASN.mmdb: ' . $e->getMessage());
            $this->asn_reader = null;
        }
    }

    // ── Download helper ───────────────────────────────────────────────────────

    private function download_file(
        string $url,
        string $dest_path,
        string $label,
        string $magic
    ): void {
        $tmp = $dest_path . '.tmp';

        error_log("[VpnDetector] Downloading {$label} …");

        $response = wp_remote_get($url, [
            'timeout'   => 120,    // large files need time
            'stream'    => true,   // stream to disk, not RAM
            'filename'  => $tmp,
            'sslverify' => true,
        ]);

        if (is_wp_error($response)) {
            error_log("[VpnDetector] {$label} download error: " . $response->get_error_message());
            @unlink($tmp);
            return;
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            error_log("[VpnDetector] {$label} download returned HTTP {$code}");
            @unlink($tmp);
            return;
        }

        // Validate magic bytes before replacing the live file
        $handle = @fopen($tmp, 'rb');
        if (!$handle) {
            @unlink($tmp);
            return;
        }
        $header = fread($handle, strlen($magic));
        fclose($handle);

        if (strpos($header, $magic) !== 0) {
            error_log("[VpnDetector] {$label} failed magic-byte check — corrupt download");
            @unlink($tmp);
            return;
        }

        // Close open connections before swapping the file
        if ($dest_path === $this->vpn_db_path && $this->db) {
            $this->ip_stmt  && $this->ip_stmt->close();
            $this->asn_stmt && $this->asn_stmt->close();
            $this->ip_stmt  = null;
            $this->asn_stmt = null;
            $this->db->close();
            $this->db = null;
        }
        if ($dest_path === $this->asn_mmdb_path && $this->asn_reader) {
            $this->asn_reader->close();
            $this->asn_reader = null;
        }

        rename($tmp, $dest_path);
        error_log("[VpnDetector] {$label} updated ✓");
    }

    // ── WP-Cron ───────────────────────────────────────────────────────────────

    /**
     * Register WP-Cron events. Call from plugin activation hook.
     *
     *   register_activation_hook(__FILE__, ['VpnDetector', 'register_cron']);
     */
    public static function register_cron(): void {
        if (!wp_next_scheduled('spamshield_update_vpn_db')) {
            wp_schedule_event(time(), 'daily', 'spamshield_update_vpn_db');
        }
        add_action('spamshield_update_vpn_db', function () {
            VpnDetector::getInstance()->force_update_vpn_db();
        });

        // 'weekly' schedule — add it if not registered (WP doesn't include it by default)
        add_filter('cron_schedules', function ($schedules) {
            if (!isset($schedules['weekly'])) {
                $schedules['weekly'] = [
                    'interval' => WEEK_IN_SECONDS,
                    'display'  => __('Once Weekly'),
                ];
            }
            return $schedules;
        });

        if (!wp_next_scheduled('spamshield_update_asn_mmdb')) {
            wp_schedule_event(time(), 'weekly', 'spamshield_update_asn_mmdb');
        }
        add_action('spamshield_update_asn_mmdb', function () {
            VpnDetector::getInstance()->force_update_asn_mmdb();
        });
    }

    public function force_update_vpn_db(): void {
        @touch($this->vpn_db_path, 0);
        $this->init_vpn_db();
    }

    public function force_update_asn_mmdb(): void {
        @touch($this->asn_mmdb_path, 0);
        $this->init_asn_mmdb();
=======
    // ── Download ──────────────────────────────────────────────────────────────

    private function download_db(): void {
        $tmp = $this->db_path . '.tmp';

        error_log( '[VpnDetector] Downloading updated database …' );

        $response = wp_remote_get( self::DB_URL, [
            'timeout'   => 90,       // DB can be a few MB
            'stream'    => true,     // stream to disk instead of RAM
            'filename'  => $tmp,
            'sslverify' => true,
        ] );

        if ( is_wp_error( $response ) ) {
            error_log( '[VpnDetector] Download error: ' . $response->get_error_message() );
            @unlink( $tmp );
            return;
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( $code !== 200 ) {
            error_log( "[VpnDetector] Download returned HTTP {$code}" );
            @unlink( $tmp );
            return;
        }

        // Sanity-check: valid SQLite3 file starts with "SQLite format 3"
        $handle = @fopen( $tmp, 'rb' );
        if ( ! $handle ) {
            error_log( '[VpnDetector] Cannot open temp file for verification' );
            @unlink( $tmp );
            return;
        }
        $magic = fread( $handle, 15 );
        fclose( $handle );

        if ( strpos( $magic, 'SQLite format 3' ) !== 0 ) {
            error_log( '[VpnDetector] Downloaded file is not a valid SQLite database' );
            @unlink( $tmp );
            return;
        }

        // Close existing connection before swapping the file
        if ( $this->db ) {
            if ( $this->stmt ) {
                $this->stmt->close();
                $this->stmt = null;
            }
            $this->db->close();
            $this->db = null;
        }

        rename( $tmp, $this->db_path );
        error_log( '[VpnDetector] Database updated successfully' );
    }

    // ── WP-Cron integration ───────────────────────────────────────────────────

    /**
     * Register a daily WP-Cron event for background database updates.
     * Call this once from your plugin's activation hook.
     *
     * Example (in your main plugin file):
     *
     *   register_activation_hook( __FILE__, function() {
     *       VpnDetector::register_cron();
     *   } );
     *
     *   register_deactivation_hook( __FILE__, function() {
     *       wp_clear_scheduled_hook( 'spamshield_update_vpn_db' );
     *   } );
     */
    public static function register_cron(): void {
        if ( ! wp_next_scheduled( 'spamshield_update_vpn_db' ) ) {
            wp_schedule_event( time(), 'daily', 'spamshield_update_vpn_db' );
        }

        add_action( 'spamshield_update_vpn_db', function () {
            $detector = VpnDetector::getInstance();
            $detector->force_update();
        } );
    }

    /** Force an immediate re-download regardless of file age. */
    public function force_update(): void {
        if ( file_exists( $this->db_path ) ) {
            // Set mtime to epoch so needs_update() returns true
            @touch( $this->db_path, 0 );
        }
        $this->download_db();
        $this->open_db();
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

<<<<<<< HEAD
    private function needs_update(string $path, int $days): bool {
        if (!file_exists($path)) {
            return true;
        }
        return (time() - filemtime($path)) >= ($days * DAY_IN_SECONDS);
    }

    private function ensure_dir(): void {
        if (!is_dir($this->data_dir)) {
            wp_mkdir_p($this->data_dir);
            file_put_contents($this->data_dir . '/.htaccess', "Deny from all\n");
            file_put_contents($this->data_dir . '/index.php', "<?php // silence\n");
        }
    }

    /** Returns false for public IPs (we want to check those), true for private/reserved. */
    private function is_private(string $ip): bool {
=======
    /**
     * Quick check for RFC-1918 / loopback / link-local addresses.
     * These should never appear in the blocklist, so skip the DB lookup.
     */
    private function is_private( string $ip ): bool {
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
<<<<<<< HEAD
}
=======
}
>>>>>>> 13ad68784df96e885fbe356d666e72056e3534ed

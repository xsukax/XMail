<?php
/**
 * XMail — Federated Encrypted Mail System
 *
 * @author  xsukax
 * @version 3.4.0
 * @license GPL-3.0-or-later
 *
 * Changes in v3.4.0:
 *   9. EML export  — decrypted messages (body + attachments) can be exported
 *      as RFC 2822 / MIME .eml files, openable in Thunderbird, Apple Mail, etc.
 *      Export button is only rendered after the thread is successfully decrypted.
 *      Handler: ?dl_eml=<mail_id>  (session thread key required)
 *
 * Security fixes (all prior versions):
 *   1. Host Header Injection  — BASE_URL constant
 *   2. SSRF via redirects     — follow_location disabled; manual validation
 *   3. Token replay attack    — token bound to (token, to_user)
 *   4. Missing CSRF on reg    — CSRF required on register + setup
 *   5. Secure session cookies — Secure, HttpOnly, SameSite=Lax
 *   6. IP spoofing rate-limit — REMOTE_ADDR only
 *   7. CSP nonce              — inline script/style protected by nonce
 *   8. Local-sender spoofing  — ?api=receive always performs handshake
 *      (no bypass for same-server from_addr)
 *   +  CRLF injection         — Content-Disposition uses filename* only
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v3 or later.
 */

// ══════════════════════════════ BOOT ══════════════════════════════════════════
foreach (['pdo_sqlite', 'openssl'] as $ext)
    if (!extension_loaded($ext))
        die("<h2>XMail requires the <code>$ext</code> PHP extension.</h2>");

$_isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'domain' => '',
    'secure'   => $_isHttps, 'httponly' => true, 'samesite' => 'Lax',
]);
session_start();

if (!defined('BASE_URL')) {
    $__proto = $_isHttps ? 'https' : 'http';
    $__host  = preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
    $__path  = $_SERVER['SCRIPT_NAME'] ?? '/xmail.php';
    define('BASE_URL', $__proto . '://' . $__host . $__path);
}

define('APP_NAME',    'XMail');
define('APP_VER',     '3.4.0');
define('DB_PATH',     __DIR__ . '/xmail.db');
define('UPLOAD_DIR',  __DIR__ . '/attachments/');
define('MAX_ATTACH',  10485760);   // 10 MB
define('PPP',         25);
define('FED_TIMEOUT', 30);
define('TOKEN_TTL',   3600);
define('RATE_WINDOW', 900);
define('RATE_LIMIT',  10);

$CSP_NONCE = base64_encode(random_bytes(18));

// ════════════════════════ SECURITY HEADERS ════════════════════════════════════
function sendSecurityHeaders(): void {
    global $CSP_NONCE;
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'nonce-{$CSP_NONCE}'; script-src 'self' 'nonce-{$CSP_NONCE}'");
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
}
sendSecurityHeaders();

// ═══════════════════════════════ DATABASE ═════════════════════════════════════
function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
    return $pdo;
}

function initDB(): void {
    db()->exec("
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '', is_admin INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS mails (
            id INTEGER PRIMARY KEY, uid TEXT UNIQUE NOT NULL,
            thread_uid TEXT NOT NULL DEFAULT '', reply_to_uid TEXT DEFAULT NULL,
            from_addr TEXT NOT NULL, to_addr TEXT NOT NULL DEFAULT '',
            cc_addr TEXT NOT NULL DEFAULT '', bcc_addr TEXT NOT NULL DEFAULT '',
            subject TEXT NOT NULL DEFAULT '', body_enc TEXT NOT NULL DEFAULT '',
            owner_id INTEGER NOT NULL REFERENCES users(id),
            folder TEXT NOT NULL DEFAULT 'inbox',
            is_read INTEGER NOT NULL DEFAULT 0, has_attach INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY, mail_uid TEXT NOT NULL, filename TEXT NOT NULL,
            stored_name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL,
            is_encrypted INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS outbound_tokens (
            id INTEGER PRIMARY KEY, token TEXT NOT NULL,
            from_addr TEXT NOT NULL, to_user TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            UNIQUE(token, to_user)
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0,
            last_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            blocked_until INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO settings(key,value) VALUES('registration','open');
        CREATE INDEX IF NOT EXISTS idx_mails_owner  ON mails(owner_id, folder, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_mails_thread ON mails(thread_uid);
        CREATE INDEX IF NOT EXISTS idx_attach_uid   ON attachments(mail_uid);
        CREATE INDEX IF NOT EXISTS idx_tokens_token ON outbound_tokens(token);
    ");
    foreach ([
        "ALTER TABLE mails ADD COLUMN thread_uid TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mails ADD COLUMN reply_to_uid TEXT DEFAULT NULL",
        "ALTER TABLE mails ADD COLUMN cc_addr TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mails ADD COLUMN bcc_addr TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mails ADD COLUMN subject TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE attachments ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0",
    ] as $sql) { try { db()->exec($sql); } catch (Exception $e) {} }
    db()->exec("DELETE FROM outbound_tokens WHERE created_at < " . (time() - TOKEN_TTL));
}

function getSetting(string $k): string {
    static $c = [];
    if (array_key_exists($k, $c)) return $c[$k];
    $s = db()->prepare("SELECT value FROM settings WHERE key=?"); $s->execute([$k]);
    return $c[$k] = (string)($s->fetchColumn() ?: '');
}
function setSetting(string $k, string $v): void {
    db()->prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)")->execute([$k, $v]);
}

// ════════════════════════════════ CRYPTO ══════════════════════════════════════
function deriveKey(string $password, string $salt): string {
    return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
}
function encrypt(string $pt, string $pass): string {
    $salt = random_bytes(16); $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($pt, 'aes-256-gcm', deriveKey($pass, $salt), OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new RuntimeException('Encryption failed');
    return base64_encode($salt . $iv . $tag . $ct);
}
function decrypt(string $blob, string $pass): string {
    $raw = base64_decode($blob, true);
    if ($raw === false || strlen($raw) < 44) throw new RuntimeException('Invalid ciphertext');
    $pt = openssl_decrypt(substr($raw, 44), 'aes-256-gcm',
          deriveKey($pass, substr($raw, 0, 16)), OPENSSL_RAW_DATA, substr($raw, 16, 12), substr($raw, 28, 16));
    if ($pt === false) throw new RuntimeException('Wrong password or corrupted data');
    return $pt;
}

// ════════════════════════════════ HELPERS ═════════════════════════════════════
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
function baseURL(): string { return BASE_URL; }
function jsonOut(array $d, int $c = 200): void {
    http_response_code($c); header('Content-Type: application/json; charset=utf-8');
    echo json_encode($d, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); exit;
}
function redir(string $u): void { header("Location: $u"); exit; }
function csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(24));
    return $_SESSION['csrf'];
}
function checkCsrf(): bool {
    return !empty($_SESSION['csrf']) && !empty($_POST['_csrf'])
        && hash_equals($_SESSION['csrf'], $_POST['_csrf']);
}
function ago(int $ts): string {
    $d = max(0, time() - $ts);
    if ($d < 60)     return $d . 's ago';
    if ($d < 3600)   return floor($d / 60) . 'm ago';
    if ($d < 86400)  return floor($d / 3600) . 'h ago';
    if ($d < 604800) return floor($d / 86400) . 'd ago';
    return date('M j, Y', $ts);
}
function timeEl(int $ts): string {
    return '<time datetime="' . date('c', $ts) . '" title="' . date('F j, Y g:i a', $ts) . '">' . h(ago($ts)) . '</time>';
}
function fmtBytes(int $b): string {
    if ($b < 1024)    return $b . ' B';
    if ($b < 1048576) return round($b / 1024, 1) . ' KB';
    return round($b / 1048576, 1) . ' MB';
}
function uid(): string { return bin2hex(random_bytes(16)); }

// ═══════════════════════════ SECURITY FUNCTIONS ═══════════════════════════════
function isPrivateHost(string $host): bool {
    $h = strtolower(preg_replace('/:\d+$/', '', trim($host)));
    if (in_array($h, ['localhost', '::1', '0.0.0.0'], true)) return true;
    if (preg_match('/^\[?::1\]?$/', $h)) return true;
    $ip = filter_var($h, FILTER_VALIDATE_IP) ? $h : @gethostbyname($h);
    if ($ip === $h && !filter_var($ip, FILTER_VALIDATE_IP)) return true;
    if (strpos($ip, '127.') === 0) return true;
    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
function isSafeRedirect(string $url, string $base): bool {
    if ($url === '') return false;
    if ($url[0] === '/' && ($url[1] ?? '') !== '/') return true;
    return strpos($url, $base) === 0;
}
function clientIp(): string { return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; }

function checkLoginRateLimit(string $ip): bool {
    $s = db()->prepare("SELECT count, last_at, blocked_until FROM login_attempts WHERE ip=?");
    $s->execute([$ip]); $r = $s->fetch();
    if (!$r) return true;
    if ((int)$r['blocked_until'] > time()) return false;
    if (time() - (int)$r['last_at'] > RATE_WINDOW) {
        db()->prepare("DELETE FROM login_attempts WHERE ip=?")->execute([$ip]); return true;
    }
    return (int)$r['count'] < RATE_LIMIT;
}
function recordLoginAttempt(string $ip, bool $success): void {
    if ($success) { db()->prepare("DELETE FROM login_attempts WHERE ip=?")->execute([$ip]); return; }
    $s = db()->prepare("SELECT count FROM login_attempts WHERE ip=?"); $s->execute([$ip]); $r = $s->fetch();
    $count   = $r ? (int)$r['count'] + 1 : 1;
    $blocked = $count >= RATE_LIMIT ? time() + RATE_WINDOW : 0;
    db()->prepare("INSERT OR REPLACE INTO login_attempts(ip,count,last_at,blocked_until) VALUES(?,?,?,?)")
        ->execute([$ip, $count, time(), $blocked]);
}

// ═════════════════════════════ USER HELPERS ═══════════════════════════════════
function currentUser(bool $fresh = false): ?array {
    static $cache = null;
    if (!isset($_SESSION['uid'])) return null;
    if ($fresh || $cache === null) {
        $s = db()->prepare("SELECT * FROM users WHERE id=?"); $s->execute([$_SESSION['uid']]);
        $cache = $s->fetch() ?: null;
    }
    return $cache;
}
function isLoggedIn(): bool { return isset($_SESSION['uid']); }
function isAdmin(): bool { $u = currentUser(); return (bool)($u['is_admin'] ?? 0); }
function mailAddress(?array $user = null): string {
    $user = $user ?? currentUser(); if (!$user) return '';
    return $user['username'] . '@' . (parse_url(baseURL(), PHP_URL_HOST) ?? 'localhost')
         . (parse_url(baseURL(), PHP_URL_PATH) ?? '/xmail.php');
}
function parseAddress(string $addr): ?array {
    if (!preg_match('/^([^@\s]+)@([^\s\/]+)(\/\S*)?$/', trim($addr), $m)) return null;
    if (isPrivateHost($m[2])) return null;
    return ['username'   => $m[1],
            'base_https' => 'https://' . $m[2] . ($m[3] ?? '/xmail.php'),
            'base_http'  => 'http://'  . $m[2] . ($m[3] ?? '/xmail.php')];
}
function isLocalAddress(string $base, array $p): bool {
    return $p['base_https'] === $base || $p['base_http'] === str_replace('https://', 'http://', $base);
}

// ══════════════════════════════ FILE HELPERS ══════════════════════════════════
function ensureUploads(): void {
    if (!is_dir(UPLOAD_DIR)) @mkdir(UPLOAD_DIR, 0750, true);
    $ht = UPLOAD_DIR . '.htaccess';
    if (!file_exists($ht)) @file_put_contents($ht, "Deny from all\nOptions -Indexes\n<FilesMatch \"\\.php$\">\nDeny from all\n</FilesMatch>\n");
    $dht = __DIR__ . '/.htaccess';
    if (!file_exists($dht)) @file_put_contents($dht, "<FilesMatch \"\\.(db|sqlite|sqlite3)$\">\nDeny from all\n</FilesMatch>\n");
}

$ALLOWED_MIME = ['image/jpeg','image/png','image/gif','image/webp','application/pdf',
    'text/plain','text/csv','application/zip','application/x-zip-compressed',
    'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];

function safeUpload(array $file, string $msgPass): ?array {
    global $ALLOWED_MIME;
    if ($file['error'] !== UPLOAD_ERR_OK || $file['size'] > MAX_ATTACH || $file['size'] === 0) return null;
    if (!is_uploaded_file($file['tmp_name'])) return null;
    $mime = mime_content_type($file['tmp_name']);
    if (!in_array($mime, $ALLOWED_MIME, true)) return null;
    $ext  = strtolower(preg_replace('/[^a-z0-9]/', '', pathinfo($file['name'], PATHINFO_EXTENSION)));
    $name = bin2hex(random_bytes(16)) . ($ext ? '.' . $ext : '');
    $raw  = file_get_contents($file['tmp_name']);
    if ($raw === false) return null;
    try { $enc = encrypt($raw, $msgPass); } catch (Exception $e) { return null; }
    if (file_put_contents(UPLOAD_DIR . $name, $enc) === false) return null;
    return ['stored'=>$name,'original'=>basename($file['name']),'mime'=>$mime,'size'=>$file['size'],'encrypted'=>true];
}

function deleteAttachments(string $mailUid): void {
    $s = db()->prepare("SELECT stored_name FROM attachments WHERE mail_uid=?"); $s->execute([$mailUid]);
    foreach ($s->fetchAll() as $a) {
        $ref = db()->prepare("SELECT COUNT(*) FROM attachments WHERE stored_name=? AND mail_uid!=?");
        $ref->execute([$a['stored_name'], $mailUid]);
        if (!(int)$ref->fetchColumn()) { $fp = UPLOAD_DIR . basename($a['stored_name']); if (file_exists($fp)) @unlink($fp); }
    }
    db()->prepare("DELETE FROM attachments WHERE mail_uid=?")->execute([$mailUid]);
}

// ════════════════════════════ EML EXPORT (NEW v3.4.0) ═════════════════════════
/**
 * generateEML — Build an RFC 2822 / MIME message from a decrypted mail row.
 *
 * Structure:
 *   • No attachments → Content-Type: text/plain; charset=UTF-8
 *   • With attachments → multipart/mixed with text/plain part + binary parts
 *
 * All binary content is base64-encoded.
 * Filename in Content-Disposition uses RFC 5987 filename* only (no CRLF risk).
 */
function generateEML(array $mail, string $body, array $attachments, string $threadKey): string {
    $nl  = "\r\n";
    $hasAttach = false;
    $parts     = [];

    foreach ($attachments as $att) {
        $fp  = UPLOAD_DIR . basename($att['stored_name']);
        if (!file_exists($fp)) continue;
        $raw = file_get_contents($fp);
        if ($att['is_encrypted']) {
            try { $raw = decrypt($raw, $threadKey); } catch (Exception $e) { continue; }
        }
        $parts[]   = ['mime' => $att['mime_type'], 'name' => $att['filename'], 'data' => $raw];
        $hasAttach = true;
    }

    // Encode subject as RFC 2047 encoded-word (UTF-8/Base64)
    $subjectEnc = '=?UTF-8?B?' . base64_encode($mail['subject'] ?: '(no subject)') . '?=';

    // Standard headers
    $hdr  = 'From: ' . $mail['from_addr']  . $nl;
    $hdr .= 'To: '   . $mail['to_addr']    . $nl;
    if (!empty($mail['cc_addr']))  $hdr .= 'CC: '   . $mail['cc_addr']  . $nl;
    if (!empty($mail['bcc_addr'])) $hdr .= 'BCC: '  . $mail['bcc_addr'] . $nl;
    $hdr .= 'Subject: '    . $subjectEnc   . $nl;
    $hdr .= 'Date: '       . date('r', (int)$mail['created_at']) . $nl;
    $hdr .= 'MIME-Version: 1.0' . $nl;
    $hdr .= 'X-Mailer: XMail/' . APP_VER  . $nl;
    $hdr .= 'Message-ID: <' . $mail['uid'] . '.xmail>' . $nl;

    if (!$hasAttach) {
        // Simple single-part plain-text message
        $hdr .= 'Content-Type: text/plain; charset=UTF-8' . $nl;
        $hdr .= 'Content-Transfer-Encoding: base64' . $nl;
        $hdr .= $nl;
        $hdr .= chunk_split(base64_encode($body), 76, $nl);
        return $hdr;
    }

    // Multipart/mixed
    $boundary = '----=_XMailMIMEBoundary_' . bin2hex(random_bytes(12));
    $hdr .= 'Content-Type: multipart/mixed; boundary="' . $boundary . '"' . $nl;
    $hdr .= $nl;
    $hdr .= 'This is a multi-part message in MIME format.' . $nl;

    // Text body part
    $body_part  = '--' . $boundary . $nl;
    $body_part .= 'Content-Type: text/plain; charset=UTF-8' . $nl;
    $body_part .= 'Content-Transfer-Encoding: base64' . $nl;
    $body_part .= $nl;
    $body_part .= chunk_split(base64_encode($body), 76, $nl);

    // Attachment parts
    $attach_parts = '';
    foreach ($parts as $p) {
        $attach_parts .= '--' . $boundary . $nl;
        $attach_parts .= 'Content-Type: ' . $p['mime'] . '; name*=UTF-8\'\'' . rawurlencode($p['name']) . $nl;
        $attach_parts .= 'Content-Transfer-Encoding: base64' . $nl;
        $attach_parts .= 'Content-Disposition: attachment; filename*=UTF-8\'\'' . rawurlencode($p['name']) . $nl;
        $attach_parts .= $nl;
        $attach_parts .= chunk_split(base64_encode($p['data']), 76, $nl);
    }

    return $hdr . $body_part . $attach_parts . '--' . $boundary . '--' . $nl;
}

// ══════════════════════════════ FEDERATION ════════════════════════════════════
function fedFetch(string $url, string $method = 'GET', ?array $body = null, int $redirectsLeft = 3): ?array {
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host || isPrivateHost($host)) return null;
    $ctx = stream_context_create(['http' => [
        'method'          => $method,
        'timeout'         => FED_TIMEOUT,
        'ignore_errors'   => true,
        'follow_location' => 0,
        'header'          => "Accept: application/json\r\nContent-Type: application/json\r\nUser-Agent: XMail/" . APP_VER . "\r\n",
        'content'         => $body !== null ? json_encode($body) : null,
    ]]);
    $raw  = @file_get_contents($url, false, $ctx);
    $hdrs = $http_response_header ?? [];
    $status = 200;
    foreach ($hdrs as $hh) { if (preg_match('#^HTTP/\S+\s+(\d+)#', $hh, $m)) { $status = (int)$m[1]; break; } }
    if (in_array($status, [301,302,303,307,308], true) && $redirectsLeft > 0) {
        foreach ($hdrs as $hh) {
            if (preg_match('/^Location:\s*(\S+)/i', $hh, $m)) {
                $newHost = parse_url($m[1], PHP_URL_HOST);
                if (!$newHost || isPrivateHost($newHost)) return null;
                return fedFetch($m[1], $status === 303 ? 'GET' : $method, $status === 303 ? null : $body, $redirectsLeft - 1);
            }
        }
        return null;
    }
    if (!$raw) return null;
    $d = json_decode($raw, true);
    return is_array($d) ? $d : null;
}

function fedDeliver(array $parsed, array $payload): bool {
    $r = fedFetch($parsed['base_https'] . '?api=receive', 'POST', $payload)
      ?? fedFetch($parsed['base_http']  . '?api=receive', 'POST', $payload);
    return isset($r['ok']);
}

function folderCounts(int $userId): array {
    $s = db()->prepare("SELECT folder, COUNT(*) c, SUM(CASE WHEN is_read=0 THEN 1 ELSE 0 END) u FROM mails WHERE owner_id=? GROUP BY folder");
    $s->execute([$userId]);
    $out = ['inbox'=>['c'=>0,'u'=>0],'sent'=>['c'=>0,'u'=>0],'drafts'=>['c'=>0,'u'=>0],'trash'=>['c'=>0,'u'=>0]];
    foreach ($s->fetchAll() as $r) $out[$r['folder']] = ['c'=>(int)$r['c'],'u'=>(int)$r['u']];
    return $out;
}

// ════════════════════════════ FEDERATION API ══════════════════════════════════
if (isset($_GET['api'])) {
    initDB(); ensureUploads();
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
    $api = $_GET['api'];

    if ($api === 'resolve') {
        $un = preg_replace('/[^a-z0-9_\-]/', '', strtolower($_GET['user'] ?? ''));
        if (!$un) jsonOut(['error' => 'missing user'], 400);
        $s = db()->prepare("SELECT username,display_name FROM users WHERE username=?"); $s->execute([$un]); $u = $s->fetch();
        if (!$u) jsonOut(['error' => 'not found'], 404);
        jsonOut(['ok'=>true,'username'=>$u['username'],'name'=>$u['display_name']?:$u['username'],'instance'=>baseURL(),'version'=>APP_VER]);
    }

    if ($api === 'verify_send') {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonOut(['error' => 'POST required'], 405);
        $b = json_decode(file_get_contents('php://input'), true);
        if (!is_array($b)) jsonOut(['error' => 'invalid JSON'], 400);
        $token    = preg_replace('/[^a-f0-9]/', '', (string)($b['verify_token'] ?? ''));
        $fromAddr = mb_substr(strip_tags((string)($b['from_addr'] ?? '')), 0, 200);
        $toUser   = preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)($b['to_user'] ?? '')));
        if (!$token || !$fromAddr || !$toUser) jsonOut(['error' => 'missing params'], 400);
        $s = db()->prepare("SELECT from_addr, created_at FROM outbound_tokens WHERE token=? AND to_user=?");
        $s->execute([$token, $toUser]); $row = $s->fetch();
        if (!$row) jsonOut(['error' => 'token not found, expired, or wrong recipient'], 404);
        if ((int)$row['created_at'] < time() - TOKEN_TTL) {
            db()->prepare("DELETE FROM outbound_tokens WHERE token=? AND to_user=?")->execute([$token, $toUser]);
            jsonOut(['error' => 'token expired'], 410);
        }
        if ($row['from_addr'] !== $fromAddr) jsonOut(['error' => 'sender address mismatch'], 403);
        jsonOut(['ok' => true, 'from_addr' => $fromAddr]);
    }

    // FIX #8 — unconditional handshake even for local from_addr
    if ($api === 'receive') {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonOut(['error' => 'POST required'], 405);
        $b = json_decode(file_get_contents('php://input'), true);
        if (!is_array($b)) jsonOut(['error' => 'invalid JSON'], 400);
        $toUser    = preg_replace('/[^a-z0-9_\-]/', '', strtolower($b['to_user'] ?? ''));
        $fromAddr  = substr(preg_replace('/[^\w@.\-\/:]/', '', $b['from_addr'] ?? ''), 0, 200);
        $subject   = mb_substr(strip_tags((string)($b['subject'] ?? '')), 0, 255);
        $bodyEnc   = (string)($b['body_enc'] ?? '');
        $threadUid = preg_replace('/[^a-f0-9]/', '', ($b['thread_uid'] ?? ''));
        $repUid    = preg_replace('/[^a-f0-9]/', '', ($b['reply_to_uid'] ?? ''));
        $ccAddr    = mb_substr(strip_tags((string)($b['cc_addr'] ?? '')), 0, 500);
        $mailUid   = preg_replace('/[^a-f0-9]/', '', ($b['uid'] ?? ''));
        $verifyTok = preg_replace('/[^a-f0-9]/', '', ($b['verify_token'] ?? ''));
        $attachMeta = is_array($b['attachments'] ?? null) ? $b['attachments'] : [];
        if (!$toUser || !$fromAddr || !$bodyEnc || strlen($mailUid) !== 32) jsonOut(['error' => 'incomplete payload'], 400);
        if (!$verifyTok) jsonOut(['error' => 'verify_token required'], 400);
        if (!$threadUid) $threadUid = uid();
        $senderParsed = parseAddress($fromAddr);
        if (!$senderParsed) jsonOut(['error' => 'invalid or unsafe sender address'], 400);
        // Always verify — no bypass for same-server addresses
        $verifyPayload = ['verify_token' => $verifyTok, 'from_addr' => $fromAddr, 'to_user' => $toUser];
        $verifyResp    = fedFetch($senderParsed['base_https'] . '?api=verify_send', 'POST', $verifyPayload)
                      ?? fedFetch($senderParsed['base_http']  . '?api=verify_send', 'POST', $verifyPayload);
        if (!isset($verifyResp['ok']) || !$verifyResp['ok'])
            jsonOut(['error' => 'handshake failed — sender could not verify token'], 403);
        if (($verifyResp['from_addr'] ?? '') !== $fromAddr)
            jsonOut(['error' => 'handshake mismatch — sender identity invalid'], 403);
        $s = db()->prepare("SELECT id FROM users WHERE username=?"); $s->execute([$toUser]); $owner = $s->fetch();
        if (!$owner) jsonOut(['error' => 'user not found'], 404);
        $ck = db()->prepare("SELECT id FROM mails WHERE uid=?"); $ck->execute([$mailUid]);
        if ($ck->fetch()) jsonOut(['ok' => true, 'note' => 'duplicate']);
        db()->prepare("INSERT INTO mails(uid,thread_uid,reply_to_uid,from_addr,to_addr,cc_addr,subject,body_enc,owner_id,folder,has_attach) VALUES(?,?,?,?,?,?,?,?,?,'inbox',?)")
            ->execute([$mailUid,$threadUid,$repUid?:null,$fromAddr,$toUser,$ccAddr,$subject,$bodyEnc,$owner['id'],empty($attachMeta)?0:1]);
        if (!empty($attachMeta)) {
            $ins = db()->prepare("INSERT INTO attachments(mail_uid,filename,stored_name,mime_type,size,is_encrypted) VALUES(?,?,?,?,?,?)");
            foreach ($attachMeta as $am) {
                $fn = mb_substr(strip_tags((string)($am['filename'] ?? 'file')), 0, 255);
                $sn = (string)($am['stored_name'] ?? '');
                if (!preg_match('/^[a-f0-9]{32}(\.[a-z0-9]{1,10})?$/', $sn)) continue;
                $mt = mb_substr(strip_tags((string)($am['mime_type'] ?? 'application/octet-stream')), 0, 100);
                $sz = (int)($am['size'] ?? 0);
                $ie = (int)($am['is_encrypted'] ?? 1);
                if ($fn && $sn && $sz > 0) {
                    $ins->execute([$mailUid,$fn,$sn,$mt,$sz,$ie]);
                    if (!empty($am['content'])) {
                        $dp = UPLOAD_DIR . $sn;
                        if (!file_exists($dp)) file_put_contents($dp, $am['content']);
                    }
                }
            }
        }
        jsonOut(['ok' => true]);
    }
    jsonOut(['error' => 'unknown endpoint'], 404);
}

// ═════════════════════════════ ATTACHMENT DOWNLOAD ════════════════════════════
if (isset($_GET['dl'])) {
    initDB(); ensureUploads();
    if (!isLoggedIn()) { http_response_code(403); exit('Forbidden'); }
    $cu = currentUser(); if (!$cu) { http_response_code(403); exit('Forbidden'); }
    $s  = db()->prepare("SELECT a.*,m.owner_id,m.uid AS mail_uid,m.thread_uid,m.id AS mail_id FROM attachments a JOIN mails m ON a.mail_uid=m.uid WHERE a.id=?");
    $s->execute([(int)$_GET['dl']]); $a = $s->fetch();
    if (!$a || (int)$a['owner_id'] !== (int)$cu['id']) { http_response_code(403); exit('Forbidden'); }
    $fp = UPLOAD_DIR . basename($a['stored_name']);
    if (!file_exists($fp)) { http_response_code(404); exit('Not found'); }
    $raw = file_get_contents($fp);
    if ($a['is_encrypted']) {
        $tk = $_SESSION['thread_keys'][$a['thread_uid']] ?? null;
        if (!$tk) redir(baseURL() . '?page=view&id=' . $a['mail_id'] . '&unlock_required=1');
        try { $raw = decrypt($raw, $tk); } catch (Exception $e) { http_response_code(400); exit('Decryption failed'); }
    }
    header('Content-Type: ' . $a['mime_type']);
    header('Content-Disposition: attachment; filename*=UTF-8\'\'' . rawurlencode($a['filename']));
    header('Content-Length: ' . strlen($raw));
    header('Cache-Control: private, no-store');
    echo $raw; exit;
}

// ════════════════════════════ EML DOWNLOAD (NEW v3.4.0) ═══════════════════════
/**
 * ?dl_eml=<mail_id>
 *
 * Exports a single decrypted message as a standards-compliant .eml file.
 * Requires:
 *   - User must be logged in and own the message
 *   - Thread key must be in the session (i.e. message was already decrypted in UI)
 *
 * The exported file can be opened directly in Thunderbird, Apple Mail,
 * Outlook, Evolution, and any RFC 2822-compliant mail client.
 */
if (isset($_GET['dl_eml'])) {
    initDB(); ensureUploads();
    if (!isLoggedIn()) { http_response_code(403); exit('Forbidden'); }
    $cu = currentUser(); if (!$cu) { http_response_code(403); exit('Forbidden'); }
    $mid = (int)$_GET['dl_eml'];
    $s   = db()->prepare("SELECT * FROM mails WHERE id=? AND owner_id=?");
    $s->execute([$mid, $cu['id']]); $mail = $s->fetch();
    if (!$mail) { http_response_code(404); exit('Message not found'); }
    $tuid = $mail['thread_uid'] ?? '';
    $tk   = ($tuid && isset($_SESSION['thread_keys'][$tuid])) ? $_SESSION['thread_keys'][$tuid] : null;
    if (!$tk) { http_response_code(403); exit('Thread is not unlocked. Decrypt the message first.'); }
    try { $body = decrypt($mail['body_enc'], $tk); }
    catch (Exception $e) { http_response_code(400); exit('Decryption failed'); }
    $as = db()->prepare("SELECT * FROM attachments WHERE mail_uid=?");
    $as->execute([$mail['uid']]); $attachments = $as->fetchAll();
    $eml = generateEML($mail, $body, $attachments, $tk);
    // Safe filename derived from subject
    $slug = preg_replace('/[^a-z0-9_\-]/i', '_', mb_substr($mail['subject'] ?: 'message', 0, 60));
    $filename = $slug . '_' . date('Ymd', (int)$mail['created_at']) . '.eml';
    header('Content-Type: message/rfc822');
    header('Content-Disposition: attachment; filename*=UTF-8\'\'' . rawurlencode($filename));
    header('Content-Length: ' . strlen($eml));
    header('Cache-Control: private, no-store');
    echo $eml; exit;
}

// ════════════════════════════ APP INIT ════════════════════════════════════════
initDB(); ensureUploads();

$base       = baseURL();
$csrf_token = csrf();
$errors     = []; $info = '';
$page       = preg_replace('/[^a-z]/', '', (string)($_GET['page'] ?? 'inbox'));
$act        = (string)($_POST['action'] ?? '');
$cu         = currentUser();

$mails=$threadMails=$threadAttachments=[];
$singleMail=$draftMail=null;
$decrypted=false; $threadKey=null; $threadUidCurrent='';
$allUsers=[]; $counts=[]; $totalCount=0;
$offset=max(0,(int)($_GET['offset']??0));
$folderIcons=['inbox'=>'📥','sent'=>'📤','drafts'=>'📝','trash'=>'🗑️'];

$hasAdmin   = (bool)db()->query("SELECT COUNT(*) FROM users WHERE is_admin=1")->fetchColumn();
$isFirstRun = !$hasAdmin;

// ── First-run setup ───────────────────────────────────────────────────────────
if ($isFirstRun && $act === 'setup') {
    if (!checkCsrf()) { $errors[] = 'Invalid CSRF token.'; }
    else {
        $un = strtolower(trim($_POST['username'] ?? '')); $p = $_POST['password'] ?? ''; $p2 = $_POST['password2'] ?? '';
        if (!preg_match('/^[a-z0-9_]{3,30}$/', $un)) $errors[] = 'Invalid username.';
        elseif (strlen($p) < 8)  $errors[] = 'Password ≥ 8 chars.';
        elseif ($p !== $p2)      $errors[] = 'Passwords do not match.';
        if (!$errors) {
            db()->prepare("INSERT INTO users(username,password,display_name,is_admin) VALUES(?,?,?,1)")
                ->execute([$un, password_hash($p, PASSWORD_DEFAULT), $un]);
            session_regenerate_id(true);
            $s = db()->prepare("SELECT id FROM users WHERE username=?"); $s->execute([$un]);
            $_SESSION['uid'] = (int)$s->fetchColumn();
            redir($base);
        }
    }
}
if ($isFirstRun) goto render;

// ── Auth ──────────────────────────────────────────────────────────────────────
if ($act === 'login') {
    $ip2 = clientIp(); $un = trim($_POST['username'] ?? ''); $p = $_POST['password'] ?? '';
    if (!checkLoginRateLimit($ip2)) { $errors[] = 'Too many attempts. Wait 15 min.'; $page = 'login'; }
    else {
        $s = db()->prepare("SELECT * FROM users WHERE username=?"); $s->execute([$un]); $u = $s->fetch();
        if ($u && password_verify($p, $u['password'])) {
            recordLoginAttempt($ip2, true); session_regenerate_id(true); $_SESSION['uid'] = (int)$u['id']; redir($base);
        } else { recordLoginAttempt($ip2, false); $errors[] = 'Invalid username or password.'; $page = 'login'; }
    }
}
if ($act === 'logout') {
    if (checkCsrf()) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', -1, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        session_destroy();
    }
    redir($base . '?page=login');
}

$privatePages = ['inbox','sent','drafts','trash','compose','view','settings','admin'];
if (!isLoggedIn() && in_array($page, $privatePages, true)) redir($base . '?page=login');
if (!isLoggedIn() && !in_array($page, ['login','register'], true)) $page = 'login';
$cu = currentUser(true);
if (isLoggedIn() && !$cu) { session_destroy(); redir($base . '?page=login'); }

// ── Registration ──────────────────────────────────────────────────────────────
if ($act === 'register') {
    if (!checkCsrf()) { $errors[] = 'Invalid CSRF token.'; $page = 'register'; }
    elseif (getSetting('registration') !== 'open') { $errors[] = 'Registration is closed.'; $page = 'register'; }
    else {
        $un = strtolower(trim($_POST['username'] ?? '')); $dn = mb_substr(trim($_POST['display_name'] ?? ''), 0, 100);
        $p  = $_POST['password'] ?? ''; $p2 = $_POST['password2'] ?? '';
        if (!preg_match('/^[a-z0-9_]{3,30}$/', $un))  $errors[] = 'Invalid username.';
        elseif (strlen($p) < 8) $errors[] = 'Password ≥ 8 chars.';
        elseif ($p !== $p2)     $errors[] = 'Passwords do not match.';
        else {
            try {
                db()->prepare("INSERT INTO users(username,password,display_name) VALUES(?,?,?)")
                    ->execute([$un, password_hash($p, PASSWORD_DEFAULT), $dn ?: $un]);
                $info = 'Account created. You can now sign in.'; $page = 'login';
            } catch (Exception $e) { $errors[] = 'Username already taken.'; $page = 'register'; }
        }
    }
}

// ── Unlock thread ─────────────────────────────────────────────────────────────
if ($act === 'unlock_thread' && isLoggedIn() && checkCsrf()) {
    $tid  = preg_replace('/[^a-f0-9]/', '', $_POST['thread_uid'] ?? '');
    $mid  = (int)($_POST['mail_id'] ?? 0);
    $pass = $_POST['msg_password'] ?? '';
    if (!$pass) { $errors[] = 'Enter the message password.'; $page = 'view'; $_GET['id'] = $mid; }
    else {
        $vs = db()->prepare("SELECT body_enc FROM mails WHERE id=? AND owner_id=?");
        $vs->execute([$mid, $cu['id']]); $vm = $vs->fetch();
        if ($vm) {
            try { decrypt($vm['body_enc'], $pass); $_SESSION['thread_keys'][$tid] = $pass; redir($base . '?page=view&id=' . $mid); }
            catch (Exception $e) { $errors[] = 'Wrong password — decryption failed.'; $page = 'view'; $_GET['id'] = $mid; }
        } else { $page = 'inbox'; }
    }
}

// ── Compose / Send / Save Draft ───────────────────────────────────────────────
if (($act === 'send' || $act === 'save_draft') && isLoggedIn() && checkCsrf()) {
    $toRaw   = trim($_POST['to'] ?? '');   $ccRaw  = trim($_POST['cc'] ?? '');
    $bccRaw  = trim($_POST['bcc'] ?? '');  $subj   = mb_substr(trim($_POST['subject'] ?? ''), 0, 255);
    $body    = mb_substr(trim($_POST['body'] ?? ''), 0, 50000);
    $msgPass = $_POST['msg_password'] ?? '';
    $draftId = (int)($_POST['draft_id'] ?? 0);
    $tUid    = preg_replace('/[^a-f0-9]/', '', ($_POST['thread_uid'] ?? '')) ?: uid();
    $repUid  = preg_replace('/[^a-f0-9]/', '', ($_POST['reply_to_uid'] ?? '')) ?: null;
    if ($act === 'send') {
        if (!$toRaw)            $errors[] = 'Recipient is required.';
        if (!$subj)             $errors[] = 'Subject is required.';
        if (!$body)             $errors[] = 'Body cannot be empty.';
        if (strlen($msgPass)<4) $errors[] = 'Message password must be ≥ 4 characters.';
    } elseif (strlen($msgPass) < 4) $errors[] = 'Message password must be ≥ 4 characters.';

    if (!$errors) {
        $mailUid = uid(); $fromAddr = mailAddress($cu);
        $folder  = $act === 'save_draft' ? 'drafts' : 'sent';
        $bodyEnc = encrypt($body ?: '', $msgPass);
        $attachMeta = [];
        if (!empty($_FILES['attachments']['name'][0])) {
            $files = $_FILES['attachments']; $count = is_array($files['name']) ? count($files['name']) : 0;
            for ($i = 0; $i < min($count, 5); $i++) {
                if ((int)$files['error'][$i] === UPLOAD_ERR_NO_FILE) continue;
                $f = ['name'=>$files['name'][$i],'type'=>$files['type'][$i],'tmp_name'=>$files['tmp_name'][$i],'error'=>$files['error'][$i],'size'=>$files['size'][$i]];
                $up = safeUpload($f, $msgPass);
                if (!$up) $errors[] = 'Attachment "' . h($f['name']) . '" rejected.'; else $attachMeta[] = $up;
            }
        }
        if (!$errors) {
            if ($draftId) {
                $ds = db()->prepare("SELECT uid FROM mails WHERE id=? AND owner_id=? AND folder='drafts'");
                $ds->execute([$draftId, $cu['id']]); $dr = $ds->fetch();
                if ($dr) { deleteAttachments($dr['uid']); db()->prepare("DELETE FROM mails WHERE id=?")->execute([$draftId]); }
            }
            db()->prepare("INSERT INTO mails(uid,thread_uid,reply_to_uid,from_addr,to_addr,cc_addr,bcc_addr,subject,body_enc,owner_id,folder,is_read,has_attach) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?)")
                ->execute([$mailUid,$tUid,$repUid,$fromAddr,$toRaw,$ccRaw,$bccRaw,$subj,$bodyEnc,$cu['id'],$folder,empty($attachMeta)?0:1]);
            if (!empty($attachMeta)) {
                $ins = db()->prepare("INSERT INTO attachments(mail_uid,filename,stored_name,mime_type,size,is_encrypted) VALUES(?,?,?,?,?,?)");
                foreach ($attachMeta as $am) $ins->execute([$mailUid,$am['original'],$am['stored'],$am['mime'],$am['size'],$am['encrypted']?1:0]);
            }
            $_SESSION['thread_keys'][$tUid] = $msgPass;
            if ($act === 'send') {
                $allRecips = array_unique(array_filter(array_map('trim', preg_split('/[,;\s]+/', $toRaw.','.$ccRaw))));
                $bccRecips = array_unique(array_filter(array_map('trim', preg_split('/[,;\s]+/', $bccRaw))));
                $fedWarn   = [];
                foreach (array_merge($allRecips, $bccRecips) as $toAddr) {
                    $isBcc  = !in_array($toAddr, $allRecips, true);
                    $parsed = parseAddress($toAddr); if (!$parsed) { $fedWarn[] = "Invalid: $toAddr"; continue; }
                    if (isLocalAddress($base, $parsed)) {
                        $rs = db()->prepare("SELECT id FROM users WHERE username=?"); $rs->execute([$parsed['username']]); $recv = $rs->fetch();
                        if (!$recv) { $fedWarn[] = "Not found: {$parsed['username']}"; continue; }
                        if ((int)$recv['id'] === (int)$cu['id']) continue;
                        $lUid = uid(); $storeCC = $isBcc ? '' : $ccRaw;
                        db()->prepare("INSERT INTO mails(uid,thread_uid,reply_to_uid,from_addr,to_addr,cc_addr,subject,body_enc,owner_id,folder,has_attach) VALUES(?,?,?,?,?,?,?,?,?,'inbox',?)")
                            ->execute([$lUid,$tUid,$repUid,$fromAddr,$toRaw,$storeCC,$subj,$bodyEnc,$recv['id'],empty($attachMeta)?0:1]);
                        if (!empty($attachMeta)) {
                            $ins2 = db()->prepare("INSERT INTO attachments(mail_uid,filename,stored_name,mime_type,size,is_encrypted) VALUES(?,?,?,?,?,?)");
                            foreach ($attachMeta as $am) $ins2->execute([$lUid,$am['original'],$am['stored'],$am['mime'],$am['size'],1]);
                        }
                    } else {
                        $verifyToken = bin2hex(random_bytes(32));
                        db()->prepare("INSERT OR REPLACE INTO outbound_tokens(token,from_addr,to_user,created_at) VALUES(?,?,?,?)")
                            ->execute([$verifyToken, $fromAddr, $parsed['username'], time()]);
                        $amMeta = array_map(function($am) {
                            $fp = UPLOAD_DIR . basename($am['stored']);
                            return ['filename'=>$am['original'],'stored_name'=>$am['stored'],'mime_type'=>$am['mime'],'size'=>$am['size'],'is_encrypted'=>1,'content'=>file_exists($fp)?file_get_contents($fp):null];
                        }, $attachMeta);
                        $payload = ['uid'=>uid(),'thread_uid'=>$tUid,'reply_to_uid'=>$repUid??'',
                                    'from_addr'=>$fromAddr,'to_user'=>$parsed['username'],
                                    'cc_addr'=>$isBcc?'':$ccRaw,'subject'=>$subj,
                                    'body_enc'=>$bodyEnc,'verify_token'=>$verifyToken,'attachments'=>$amMeta];
                        if (!fedDeliver($parsed, $payload)) $fedWarn[] = "Delivery failed: $toAddr";
                    }
                }
                if ($fedWarn) $info = implode('; ', $fedWarn);
                else redir($base . '?page=sent&info=sent');
            } else redir($base . '?page=drafts&info=draft_saved');
        } else $page = 'compose';
    } else $page = 'compose';
}

// ── Mail actions ──────────────────────────────────────────────────────────────
if ($act==='move_trash'&&isLoggedIn()&&checkCsrf()) {
    db()->prepare("UPDATE mails SET folder='trash' WHERE id=? AND owner_id=?")->execute([(int)$_POST['mail_id'],$cu['id']]);
    $back = $_POST['_back'] ?? $base.'?page=inbox';
    if (!isSafeRedirect($back, $base)) $back = $base.'?page=inbox';
    redir($back);
}
if ($act==='restore'&&isLoggedIn()&&checkCsrf()) {
    db()->prepare("UPDATE mails SET folder='inbox' WHERE id=? AND owner_id=? AND folder='trash'")->execute([(int)$_POST['mail_id'],$cu['id']]);
    redir($base.'?page=trash');
}
if ($act==='delete_perm'&&isLoggedIn()&&checkCsrf()) {
    $id=(int)$_POST['mail_id'];
    $s=db()->prepare("SELECT uid FROM mails WHERE id=? AND owner_id=? AND folder='trash'"); $s->execute([$id,$cu['id']]); $m=$s->fetch();
    if ($m) { deleteAttachments($m['uid']); db()->prepare("DELETE FROM mails WHERE id=?")->execute([$id]); }
    redir($base.'?page=trash');
}
if ($act==='empty_trash'&&isLoggedIn()&&checkCsrf()) {
    $s=db()->prepare("SELECT uid FROM mails WHERE owner_id=? AND folder='trash'"); $s->execute([$cu['id']]);
    foreach ($s->fetchAll() as $m) deleteAttachments($m['uid']);
    db()->prepare("DELETE FROM mails WHERE owner_id=? AND folder='trash'")->execute([$cu['id']]);
    redir($base.'?page=trash&info=emptied');
}
if ($act==='bulk_action'&&isLoggedIn()&&checkCsrf()) {
    $ids = array_values(array_filter(array_map('intval',(array)($_POST['ids']??[]))));
    $op  = $_POST['bulk_op']??''; $pg = preg_replace('/[^a-z]/','',($_POST['_page']??'inbox'));
    if ($ids) {
        $ph = implode(',',array_fill(0,count($ids),'?')); $p = array_merge($ids,[$cu['id']]);
        if ($op==='mark_read')      db()->prepare("UPDATE mails SET is_read=1 WHERE id IN ($ph) AND owner_id=?")->execute($p);
        elseif($op==='mark_unread') db()->prepare("UPDATE mails SET is_read=0 WHERE id IN ($ph) AND owner_id=?")->execute($p);
        elseif($op==='trash')       db()->prepare("UPDATE mails SET folder='trash' WHERE id IN ($ph) AND owner_id=? AND folder!='trash'")->execute($p);
        elseif($op==='restore')     db()->prepare("UPDATE mails SET folder='inbox' WHERE id IN ($ph) AND owner_id=? AND folder='trash'")->execute($p);
        elseif($op==='delete') {
            $s2=db()->prepare("SELECT uid FROM mails WHERE id IN ($ph) AND owner_id=? AND folder='trash'"); $s2->execute($p);
            foreach($s2->fetchAll() as $m) deleteAttachments($m['uid']);
            db()->prepare("DELETE FROM mails WHERE id IN ($ph) AND owner_id=? AND folder='trash'")->execute($p);
        }
    }
    redir($base.'?page='.$pg);
}
if ($act==='update_settings'&&isLoggedIn()&&checkCsrf()) {
    $dn=mb_substr(trim($_POST['display_name']??''),0,100);
    $cp=$_POST['current_password']??''; $np=$_POST['new_password']??''; $cf=$_POST['confirm_password']??'';
    if (!password_verify($cp,$cu['password'])) { $errors[]='Current password incorrect.'; }
    else {
        if ($dn) db()->prepare("UPDATE users SET display_name=? WHERE id=?")->execute([$dn,$cu['id']]);
        if ($np) {
            if (strlen($np)<8)   $errors[]='New password ≥ 8 chars.';
            elseif($np!==$cf)    $errors[]='Passwords do not match.';
            else { db()->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($np,PASSWORD_DEFAULT),$cu['id']]); $info='Password updated.'; }
        } else $info='Display name updated.';
    }
    $page='settings';
}
if ($act==='admin_toggle_reg'&&isAdmin()&&checkCsrf()) {
    setSetting('registration',getSetting('registration')==='open'?'closed':'open'); redir($base.'?page=admin');
}
if ($act==='admin_delete_user'&&isAdmin()&&checkCsrf()) {
    $uid2=(int)($_POST['user_id']??0);
    if ($uid2&&$uid2!==(int)$cu['id']) {
        $ms=db()->prepare("SELECT uid FROM mails WHERE owner_id=?"); $ms->execute([$uid2]);
        foreach($ms->fetchAll() as $m) deleteAttachments($m['uid']);
        db()->prepare("DELETE FROM mails WHERE owner_id=?")->execute([$uid2]);
        db()->prepare("DELETE FROM users WHERE id=?")->execute([$uid2]);
    }
    redir($base.'?page=admin');
}
if ($act==='admin_toggle_admin'&&isAdmin()&&checkCsrf()) {
    $uid2=(int)($_POST['user_id']??0);
    if ($uid2&&$uid2!==(int)$cu['id']) {
        $s=db()->prepare("SELECT is_admin FROM users WHERE id=?"); $s->execute([$uid2]); $r=$s->fetch();
        if ($r) db()->prepare("UPDATE users SET is_admin=? WHERE id=?")->execute([$r['is_admin']?0:1,$uid2]);
    }
    redir($base.'?page=admin');
}

if (isLoggedIn()&&$page==='admin'&&!isAdmin()) $page='inbox';
if (isLoggedIn()&&!in_array($page,$privatePages,true)) $page='inbox';

$ip=$_GET['info']??'';
if ($ip==='sent')        $info='Mail sent successfully.';
if ($ip==='draft_saved') $info='Draft saved.';
if ($ip==='emptied')     $info='Trash emptied.';
if (isset($_GET['unlock_required'])) $info='Enter the message password to unlock attachments.';

if (isLoggedIn()) {
    $counts = folderCounts((int)$cu['id']);
    if (in_array($page,['inbox','sent','drafts','trash'],true)) {
        $cq=db()->prepare("SELECT COUNT(*) FROM mails WHERE owner_id=? AND folder=?");
        $cq->execute([$cu['id'],$page]); $totalCount=(int)$cq->fetchColumn();
        $s=db()->prepare("SELECT * FROM mails WHERE owner_id=? AND folder=? ORDER BY created_at DESC LIMIT ? OFFSET ?");
        $s->execute([$cu['id'],$page,PPP,$offset]); $mails=$s->fetchAll();
    }
    if ($page==='view') {
        $mid=(int)($_GET['id']??0);
        $s=db()->prepare("SELECT * FROM mails WHERE id=? AND owner_id=?"); $s->execute([$mid,$cu['id']]); $singleMail=$s->fetch()?:null;
        if ($singleMail) {
            $tuid=$singleMail['thread_uid']??''; $threadUidCurrent=$tuid;
            if ($tuid) {
                $ts=db()->prepare("SELECT * FROM mails WHERE thread_uid=? AND owner_id=? ORDER BY created_at ASC"); $ts->execute([$tuid,$cu['id']]);
                $threadMails=$ts->fetchAll();
                db()->prepare("UPDATE mails SET is_read=1 WHERE thread_uid=? AND owner_id=?")->execute([$tuid,$cu['id']]);
            } else {
                $threadMails=[$singleMail];
                db()->prepare("UPDATE mails SET is_read=1 WHERE id=?")->execute([$mid]);
            }
            foreach($threadMails as $tm) {
                if($tm['has_attach']) {
                    $as=db()->prepare("SELECT * FROM attachments WHERE mail_uid=?"); $as->execute([$tm['uid']]);
                    $threadAttachments[$tm['uid']]=$as->fetchAll();
                }
            }
            $threadKey=$tuid&&isset($_SESSION['thread_keys'][$tuid])?$_SESSION['thread_keys'][$tuid]:null;
            if ($threadKey) {
                foreach($threadMails as &$tm) {
                    try { $tm['_body']=decrypt($tm['body_enc'],$threadKey); $tm['_ok']=true; }
                    catch(Exception $e) { $tm['_body']=null; $tm['_ok']=false; }
                }
                unset($tm); $decrypted=true;
            }
        }
    }
    if ($page==='compose'&&isset($_GET['draft'])) {
        $s=db()->prepare("SELECT * FROM mails WHERE id=? AND owner_id=? AND folder='drafts'");
        $s->execute([(int)$_GET['draft'],$cu['id']]); $draftMail=$s->fetch()?:null;
    }
    if ($page==='admin'&&isAdmin())
        $allUsers=db()->query("SELECT id,username,display_name,is_admin,created_at FROM users ORDER BY created_at ASC")->fetchAll();
}

$composePrefillPass = '';
$composeReplyToUid  = preg_replace('/[^a-f0-9]/','',($_GET['reply_to_uid']??''));
$composeThreadUid   = preg_replace('/[^a-f0-9]/','',($_GET['thread_uid']??''));
if ($composeThreadUid && isset($_SESSION['thread_keys'][$composeThreadUid]))
    $composePrefillPass = $_SESSION['thread_keys'][$composeThreadUid];

render:
$n = ' nonce="'.h($CSP_NONCE).'"';
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?=h(APP_NAME)?></title>
<style<?=$n?>>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#fff;--bg2:#f6f9fc;--bg3:#eef2f7;--bd:#e6ebf1;--bd2:#cdd3da;--tx:#1a1f36;--tx2:#6b7c93;--tx3:#a8b7c7;--pu:#635bff;--pu-h:#5851e8;--pu-l:#ede9fe;--pu-ll:#f5f3ff;--gr:#00875a;--gr-l:#e3fcef;--re:#df1b41;--re-l:#fff0f3;--or:#c44d23;--or-l:#fff4e0;--r:8px;--r2:12px;--r3:16px;--nav-h:62px;--sb-w:236px;--sh:0 2px 8px rgba(50,50,93,.08),0 1px 3px rgba(0,0,0,.05);--sh-md:0 6px 24px rgba(50,50,93,.11),0 2px 8px rgba(0,0,0,.07);--sh-lg:0 20px 60px rgba(50,50,93,.15),0 4px 16px rgba(0,0,0,.07)}
html,body{height:100%}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px;color:var(--tx);background:var(--bg2);min-height:100dvh;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
a{color:var(--pu);text-decoration:none}a:hover{color:var(--pu-h);text-decoration:underline}
button,input,select,textarea{font:inherit}textarea{resize:vertical}
/* ── NAV ── */
.nav{background:rgba(255,255,255,.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--bd);height:var(--nav-h);position:sticky;top:0;z-index:60}
.nav-in{display:flex;align-items:center;gap:12px;height:100%;max-width:1320px;margin:0 auto;padding:0 22px}
.nav-logo{display:flex;align-items:center;gap:9px;text-decoration:none;flex-shrink:0}
.nav-logo-icon{width:30px;height:30px;background:linear-gradient(135deg,#635bff,#a78bfa);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;box-shadow:0 2px 8px rgba(99,91,255,.35);flex-shrink:0}
.nav-logo-text{font-size:16px;font-weight:800;color:var(--tx);letter-spacing:-.03em}
.nav-end{margin-left:auto;display:flex;gap:10px;align-items:center}
.nav-user{font-size:13px;font-weight:500;color:var(--tx2)}
.hamburger{display:none;background:none;border:1px solid var(--bd);border-radius:var(--r);padding:6px 10px;cursor:pointer;font-size:15px;line-height:1;color:var(--tx2)}
/* ── LAYOUT ── */
.app{display:grid;grid-template-columns:var(--sb-w) 1fr;min-height:calc(100dvh - var(--nav-h))}
.sidebar{background:var(--bg);border-right:1px solid var(--bd);padding:14px 0 24px;overflow-y:auto;display:flex;flex-direction:column}
.sb-overlay{display:none;position:fixed;inset:0;top:var(--nav-h);background:rgba(26,31,54,.45);z-index:49;backdrop-filter:blur(3px)}
.sb-section{margin-bottom:4px}
.sb-head{padding:5px 16px 4px;font-size:10px;font-weight:700;color:var(--tx3);text-transform:uppercase;letter-spacing:.9px}
.sb-item{display:flex;align-items:center;gap:9px;padding:8px 12px;color:var(--tx2);font-size:13.5px;font-weight:500;text-decoration:none;margin:1px 8px;border-radius:var(--r);transition:background .12s,color .12s}
.sb-item:hover{background:var(--bg2);color:var(--tx);text-decoration:none}
.sb-item.active{background:var(--pu-ll);color:var(--pu);font-weight:600}
.sb-icon{width:20px;text-align:center;font-size:15px;flex-shrink:0}
.sb-badge{margin-left:auto;background:var(--pu);color:#fff;font-size:9.5px;font-weight:700;padding:2px 7px;border-radius:20px;min-width:20px;text-align:center;line-height:1.5}
.sb-div{height:1px;background:var(--bd);margin:8px 14px}
.sb-addr{padding:10px 12px}
/* ── MAIN ── */
.main{padding:22px 26px;overflow-x:hidden;min-width:0}
/* ── CARD ── */
.card{background:var(--bg);border:1px solid var(--bd);border-radius:var(--r2);box-shadow:var(--sh)}
.card+.card,.card+form>.card,.form+.card{margin-top:14px}
/* ── MAIL LIST ── */
.mail-list-hdr{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--bd);background:var(--bg2);border-radius:var(--r2) var(--r2) 0 0}
.mail-row{display:flex;align-items:center;gap:6px;border-bottom:1px solid var(--bd);transition:background .1s}
.mail-row:last-child{border-bottom:none}.mail-row:hover{background:var(--pu-ll)}
.mail-row input[type=checkbox]{flex-shrink:0;margin-left:14px;width:15px;height:15px;cursor:pointer;accent-color:var(--pu)}
.mail-link{display:flex;align-items:center;gap:10px;flex:1;padding:11px 16px 11px 8px;text-decoration:none;color:var(--tx);overflow:hidden;min-width:0}
.mail-link:hover{text-decoration:none}
.mail-dot{width:7px;height:7px;background:var(--pu);border-radius:50%;flex-shrink:0}
.mail-spacer{width:7px;flex-shrink:0}
.mail-from{font-size:12.5px;color:var(--tx2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;width:130px;flex-shrink:0}
.mail-row.unread .mail-from{color:var(--tx);font-weight:600}
.mail-subj{flex:1;font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.mail-row.unread .mail-subj{font-weight:600}.mail-row.read .mail-subj{color:var(--tx2)}
.mail-attach-icon{font-size:12px;flex-shrink:0;color:var(--tx3)}
.mail-time{font-size:11.5px;color:var(--tx3);flex-shrink:0;white-space:nowrap;font-weight:500}
/* ── BULK BAR ── */
.bulk-bar{display:none;align-items:center;gap:8px;padding:9px 16px;background:var(--pu-ll);border-bottom:1px solid rgba(99,91,255,.18);flex-wrap:wrap;border-radius:var(--r2) var(--r2) 0 0}
.bulk-bar.active{display:flex}
.bulk-count{font-size:13px;font-weight:600;color:var(--pu);margin-right:4px}
/* ── BUTTONS ── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:7px 16px;border-radius:var(--r);border:1px solid;cursor:pointer;font-size:13.5px;font-weight:500;transition:all .15s;text-decoration:none;white-space:nowrap;min-height:36px;letter-spacing:-.01em;line-height:1.3}
.btn:hover{text-decoration:none}
.btn-primary{background:linear-gradient(160deg,var(--pu) 0%,#8b5cf6 100%);color:#fff;border-color:transparent;box-shadow:0 2px 6px rgba(99,91,255,.32)}.btn-primary:hover{box-shadow:0 4px 12px rgba(99,91,255,.42);transform:translateY(-1px)}
.btn-secondary{background:var(--bg);color:var(--tx);border-color:var(--bd);box-shadow:var(--sh)}.btn-secondary:hover{background:var(--bg2);border-color:var(--bd2)}
.btn-danger{background:var(--re);color:#fff;border-color:transparent;box-shadow:0 2px 6px rgba(223,27,65,.22)}.btn-danger:hover{opacity:.9;transform:translateY(-1px)}
.btn-export{background:linear-gradient(160deg,#00875a,#00b894);color:#fff;border-color:transparent;box-shadow:0 2px 6px rgba(0,135,90,.28)}.btn-export:hover{box-shadow:0 4px 12px rgba(0,135,90,.38);transform:translateY(-1px)}
.btn-sm{padding:5px 12px;font-size:12.5px;min-height:30px}
.btn-xs{padding:3px 9px;font-size:12px;min-height:26px}
.btn-icon{padding:5px 10px;min-height:30px}
/* ── FORMS ── */
.form-g{margin-bottom:16px}
.form-label{display:block;font-size:12.5px;font-weight:600;margin-bottom:5px;color:var(--tx)}
.form-input{width:100%;padding:8px 12px;border:1px solid var(--bd);border-radius:var(--r);font-size:13.5px;background:var(--bg);color:var(--tx);transition:border-color .15s,box-shadow .15s;min-height:38px}
.form-input:focus{outline:none;border-color:var(--pu);box-shadow:0 0 0 3px rgba(99,91,255,.12)}
.form-input::placeholder{color:var(--tx3)}
.form-input:disabled{background:var(--bg2);cursor:not-allowed;color:var(--tx2)}
.form-hint{font-size:12px;color:var(--tx2);margin-top:4px;line-height:1.5}
textarea.form-input{min-height:200px;line-height:1.65}
/* ── ALERTS ── */
.alert{padding:11px 14px;border-radius:var(--r);margin-bottom:14px;font-size:13.5px;border:1px solid;line-height:1.5}
.alert-err{background:var(--re-l);color:var(--re);border-color:rgba(223,27,65,.18)}
.alert-ok{background:var(--gr-l);color:var(--gr);border-color:rgba(0,135,90,.18)}
.alert-info{background:var(--pu-l);color:var(--pu-h);border-color:rgba(99,91,255,.18)}
.alert-warn{background:var(--or-l);color:var(--or);border-color:rgba(196,77,35,.18)}
/* ── PAGE HEADER ── */
.page-hdr{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:18px;flex-wrap:wrap}
.page-title{font-size:18px;font-weight:700;color:var(--tx);letter-spacing:-.02em}
/* ── BADGES ── */
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:11.5px;font-weight:600;white-space:nowrap}
.badge-pu{background:var(--pu-ll);color:var(--pu)}.badge-gr{background:var(--gr-l);color:var(--gr)}.badge-re{background:var(--re-l);color:var(--re)}.badge-muted{background:var(--bg2);color:var(--tx2)}
.enc-badge{display:inline-flex;align-items:center;gap:4px;background:var(--gr-l);border:1px solid rgba(0,135,90,.18);border-radius:20px;padding:3px 9px;font-size:11px;font-weight:600;color:var(--gr)}
/* ── THREAD ── */
.thread-msg{border:1px solid var(--bd);border-radius:var(--r2);margin-bottom:12px;overflow:hidden;box-shadow:var(--sh);transition:box-shadow .15s}
.thread-msg:hover{box-shadow:var(--sh-md)}
.thread-msg.unread{border-left:3px solid var(--pu)}
.thread-msg.outgoing .thread-msg-hdr{background:var(--pu-ll)}
.thread-msg-hdr{padding:12px 16px;border-bottom:1px solid var(--bd);display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:8px;background:var(--bg2)}
.thread-msg-meta{display:flex;flex-direction:column;gap:3px;font-size:12.5px;color:var(--tx2)}.thread-msg-meta b{color:var(--tx);font-weight:600}
.thread-msg-time{font-size:11.5px;color:var(--tx3);white-space:nowrap;font-weight:500;flex-shrink:0}
.thread-msg-body{padding:18px 20px;font-size:14px;line-height:1.8;white-space:pre-wrap;word-break:break-word;background:var(--bg);color:var(--tx)}
.thread-msg-attach{padding:12px 16px;border-top:1px solid var(--bd);display:flex;flex-wrap:wrap;gap:8px;background:var(--bg2);align-items:center}
.thread-msg-actions{padding:10px 16px;border-top:1px solid var(--bd);display:flex;gap:8px;flex-wrap:wrap;background:var(--bg2);align-items:center}
.locked-body{display:flex;align-items:center;gap:10px;padding:18px 20px;color:var(--tx2);font-size:13px;background:var(--bg2)}
/* ── ATTACHMENTS ── */
.attach-chip{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);font-size:12.5px;text-decoration:none;color:var(--tx);font-weight:500;box-shadow:var(--sh);transition:all .12s}
.attach-chip:hover{background:var(--bg3);border-color:var(--bd2);text-decoration:none;transform:translateY(-1px)}
.attach-chip.locked{color:var(--tx3);cursor:not-allowed;opacity:.65;box-shadow:none}
.attach-chip.locked:hover{transform:none;background:var(--bg);border-color:var(--bd)}
/* ── PASS GATE ── */
.pass-gate{text-align:center;padding:36px 24px;max-width:400px;margin:0 auto}
.pass-gate-icon{width:56px;height:56px;background:linear-gradient(135deg,var(--pu),#8b5cf6);border-radius:15px;display:flex;align-items:center;justify-content:center;font-size:26px;margin:0 auto 14px;box-shadow:0 4px 14px rgba(99,91,255,.3)}
/* ── EML EXPORT BUTTON (v3.4.0) ── */
.eml-export-btn{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:linear-gradient(160deg,#00875a,#00b894);color:#fff;border:none;border-radius:var(--r);font-size:12.5px;font-weight:600;cursor:pointer;text-decoration:none;box-shadow:0 2px 6px rgba(0,135,90,.28);transition:all .15s;white-space:nowrap}
.eml-export-btn:hover{box-shadow:0 4px 10px rgba(0,135,90,.38);transform:translateY(-1px);color:#fff;text-decoration:none}
.eml-export-btn .eml-icon{font-size:14px}
/* ── AUTH ── */
.auth-wrap{min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:20px;background:linear-gradient(135deg,#f0f4ff 0%,var(--pu-ll) 50%,#f0fff8 100%)}
.auth-card{width:100%;max-width:390px;background:var(--bg);border:1px solid var(--bd);border-radius:var(--r3);padding:32px 28px;box-shadow:var(--sh-lg)}
.auth-logo{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:6px}
.auth-logo-icon{width:44px;height:44px;background:linear-gradient(135deg,#635bff,#a78bfa);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 4px 14px rgba(99,91,255,.32)}
.auth-logo-text{font-size:24px;font-weight:800;color:var(--tx);letter-spacing:-.03em}
.auth-sub{text-align:center;color:var(--tx2);font-size:13.5px;margin-bottom:24px;line-height:1.5}
/* ── TABLES ── */
.tbl{width:100%;border-collapse:collapse;font-size:13.5px}
.tbl th{text-align:left;padding:9px 12px;border-bottom:2px solid var(--bd);font-weight:700;color:var(--tx2);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.tbl td{padding:10px 12px;border-bottom:1px solid var(--bd);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}.tbl tbody tr:hover td{background:var(--bg2)}
/* ── MISC ── */
.addr-box{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:11.5px;background:var(--bg2);border:1px solid var(--bd);padding:7px 11px;border-radius:var(--r);word-break:break-all;user-select:all;color:var(--tx);line-height:1.55}
.empty{text-align:center;padding:56px 16px;color:var(--tx2)}.empty-icon{font-size:42px;margin-bottom:12px;opacity:.45}.empty-title{font-size:15px;font-weight:600;color:var(--tx);margin-bottom:4px}.empty-sub{font-size:13px}
.pager{display:flex;align-items:center;gap:10px;margin-top:14px;font-size:13px;color:var(--tx2)}
.divider{height:1px;background:var(--bd);margin:18px 0}
.stats-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px}
.stat-card{background:var(--bg);border:1px solid var(--bd);border-radius:var(--r2);padding:16px 18px;box-shadow:var(--sh)}
.stat-val{font-size:26px;font-weight:800;color:var(--tx);letter-spacing:-.03em;line-height:1.1}
.stat-lbl{font-size:12px;color:var(--tx2);font-weight:500;margin-top:3px}
.compose-sticky{position:sticky;bottom:0;background:var(--bg);border-top:1px solid var(--bd);padding:14px 20px;display:flex;gap:9px;flex-wrap:wrap;align-items:center;border-radius:0 0 var(--r2) var(--r2);margin:0 -20px -20px}
.section-label{font-size:11px;font-weight:700;color:var(--tx3);text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px}
/* ── BOTTOM NAV ── */
.bottom-nav{display:none;position:fixed;bottom:0;left:0;right:0;height:60px;background:rgba(255,255,255,.95);backdrop-filter:blur(10px);border-top:1px solid var(--bd);z-index:60}
.bottom-nav a{display:flex;flex-direction:column;align-items:center;justify-content:center;flex:1;font-size:9.5px;font-weight:500;color:var(--tx2);text-decoration:none;gap:3px;padding:6px 0;transition:color .12s}
.bottom-nav a .bn-icon{font-size:19px;line-height:1}
.bottom-nav a.active,.bottom-nav a:hover{color:var(--pu);text-decoration:none}
/* ── RESPONSIVE ── */
@media(max-width:900px){.app{grid-template-columns:1fr}.sidebar{position:fixed;left:-260px;top:var(--nav-h);bottom:0;width:256px;z-index:50;overflow-y:auto;transition:left .22s cubic-bezier(.4,0,.2,1)}.sidebar.open{left:0;box-shadow:var(--sh-lg)}.sb-overlay.open{display:block}.hamburger{display:flex}.bottom-nav{display:flex}.main{padding:14px 14px 76px}.stats-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:540px){.mail-from{width:90px}.mail-time{display:none}.nav-in{padding:0 12px}.thread-msg-hdr{flex-direction:column}.tbl th,.tbl td{padding:8px 8px}.tbl{font-size:12.5px}.stats-grid{grid-template-columns:1fr}.page-title{font-size:16px}.auth-card{padding:24px 18px}}
</style>
</head>
<body>

<?php if ($isFirstRun): ?>
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><div class="auth-logo-icon">✦</div><div class="auth-logo-text"><?=h(APP_NAME)?></div></div>
  <div class="auth-sub">Create your admin account to get started</div>
  <?php if($errors):?><div class="alert alert-err">⚠ <?=h(implode(' ',$errors))?></div><?php endif?>
  <form method="POST">
    <input type="hidden" name="action" value="setup">
    <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
    <div class="form-g"><label class="form-label">Username</label><input class="form-input" type="text" name="username" pattern="[a-z0-9_]{3,30}" placeholder="e.g. admin" required autofocus autocomplete="username"><div class="form-hint">3–30 characters · a–z, 0–9, underscore</div></div>
    <div class="form-g"><label class="form-label">Password <span style="font-weight:400;color:var(--tx2)">(min. 8 chars)</span></label><input class="form-input" type="password" name="password" required minlength="8" autocomplete="new-password"></div>
    <div class="form-g"><label class="form-label">Confirm Password</label><input class="form-input" type="password" name="password2" required autocomplete="new-password"></div>
    <button class="btn btn-primary w-full" type="submit" style="width:100%;margin-top:4px">Create Admin Account →</button>
  </form>
</div></div>

<?php elseif($page==='login'&&!isLoggedIn()): ?>
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><div class="auth-logo-icon">✦</div><div class="auth-logo-text"><?=h(APP_NAME)?></div></div>
  <div class="auth-sub">Sign in to your encrypted mailbox</div>
  <?php if($errors):?><div class="alert alert-err">⚠ <?=h(implode(' ',$errors))?></div><?php endif?>
  <?php if($info):?><div class="alert alert-ok">✓ <?=h($info)?></div><?php endif?>
  <form method="POST">
    <input type="hidden" name="action" value="login">
    <div class="form-g"><label class="form-label">Username</label><input class="form-input" type="text" name="username" required autofocus autocomplete="username" placeholder="Your username"></div>
    <div class="form-g"><label class="form-label">Password</label><input class="form-input" type="password" name="password" required autocomplete="current-password" placeholder="Your password"></div>
    <button class="btn btn-primary" type="submit" style="width:100%;margin-top:4px">Sign in →</button>
  </form>
  <?php if(getSetting('registration')==='open'):?>
  <p style="text-align:center;margin-top:18px;font-size:13px;color:var(--tx2)">No account? <a href="<?=h($base.'?page=register')?>">Create one</a></p>
  <?php endif?>
</div></div>

<?php elseif($page==='register'&&!isLoggedIn()): ?>
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><div class="auth-logo-icon">✦</div><div class="auth-logo-text"><?=h(APP_NAME)?></div></div>
  <div class="auth-sub">Create a new encrypted mailbox</div>
  <?php if($errors):?><div class="alert alert-err">⚠ <?=h(implode(' ',$errors))?></div><?php endif?>
  <?php if(getSetting('registration')!=='open'):?><div class="alert alert-err">⚠ Registration is currently closed.</div><?php else:?>
  <form method="POST">
    <input type="hidden" name="action" value="register">
    <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
    <div class="form-g"><label class="form-label">Username <span style="font-weight:400;color:var(--tx2)">(permanent)</span></label><input class="form-input" type="text" name="username" pattern="[a-z0-9_]{3,30}" required autofocus autocomplete="username" placeholder="a–z, 0–9, underscore"><div class="form-hint">3–30 characters · cannot be changed later</div></div>
    <div class="form-g"><label class="form-label">Display Name <span style="font-weight:400;color:var(--tx2)">(optional)</span></label><input class="form-input" type="text" name="display_name" maxlength="100" autocomplete="name" placeholder="Your full name"></div>
    <div class="form-g"><label class="form-label">Password</label><input class="form-input" type="password" name="password" required minlength="8" autocomplete="new-password" placeholder="Min. 8 characters"></div>
    <div class="form-g"><label class="form-label">Confirm Password</label><input class="form-input" type="password" name="password2" required autocomplete="new-password"></div>
    <button class="btn btn-primary" type="submit" style="width:100%;margin-top:4px">Create Account →</button>
  </form>
  <?php endif?>
  <p style="text-align:center;margin-top:18px;font-size:13px;color:var(--tx2)">Have an account? <a href="<?=h($base.'?page=login')?>">Sign in</a></p>
</div></div>

<?php elseif(isLoggedIn()&&$cu): ?>

<nav class="nav">
  <div class="nav-in">
    <button class="hamburger" onclick="toggleSb()" aria-label="Menu">☰</button>
    <a class="nav-logo" href="<?=h($base)?>"><div class="nav-logo-icon">✦</div><span class="nav-logo-text"><?=h(APP_NAME)?></span></a>
    <div class="nav-end">
      <span class="nav-user"><?=h($cu['display_name']?:$cu['username'])?></span>
      <form method="POST" style="display:inline">
        <input type="hidden" name="action" value="logout">
        <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
        <button class="btn btn-secondary btn-sm">Sign out</button>
      </form>
    </div>
  </div>
</nav>
<div class="sb-overlay" id="soverlay" onclick="toggleSb()"></div>

<div class="app">
  <aside class="sidebar" id="sidebar">
    <div style="padding:6px 12px 14px">
      <a class="btn btn-primary" href="<?=h($base.'?page=compose')?>" style="width:100%;justify-content:center" onclick="closeSb()">✉ Compose</a>
    </div>
    <div class="sb-section">
      <div class="sb-head">Mailbox</div>
      <?php foreach($folderIcons as $f=>$icon):$cnt=$counts[$f]??['c'=>0,'u'=>0];?>
      <a class="sb-item <?=$page===$f?'active':''?>" href="<?=h($base.'?page='.$f)?>" onclick="closeSb()">
        <span class="sb-icon"><?=$icon?></span>
        <?=ucfirst($f)?>
        <?php if($cnt['u']>0):?><span class="sb-badge"><?=$cnt['u']?></span><?php endif?>
      </a>
      <?php endforeach?>
    </div>
    <div class="sb-div"></div>
    <div class="sb-section">
      <div class="sb-head">Account</div>
      <a class="sb-item <?=$page==='settings'?'active':''?>" href="<?=h($base.'?page=settings')?>" onclick="closeSb()"><span class="sb-icon">⚙️</span>Settings</a>
      <?php if(isAdmin()):?><a class="sb-item <?=$page==='admin'?'active':''?>" href="<?=h($base.'?page=admin')?>" onclick="closeSb()"><span class="sb-icon">🔑</span>Admin</a><?php endif?>
    </div>
    <div class="sb-div"></div>
    <div class="sb-addr">
      <div class="section-label" style="margin-bottom:6px">Your Address</div>
      <div class="addr-box"><?=h(mailAddress($cu))?></div>
      <div class="form-hint" style="margin-top:5px">Share to receive messages</div>
    </div>
  </aside>

  <main class="main">
  <?php if($errors):?><div class="alert alert-err">⚠ <?=h(implode('<br>',$errors))?></div><?php endif?>
  <?php if($info):?><div class="alert alert-ok">✓ <?=h($info)?></div><?php endif?>

  <?php if(in_array($page,['inbox','sent','drafts','trash'],true)): ?>
  <div class="page-hdr">
    <div class="page-title"><?=$folderIcons[$page]?> <?=ucfirst($page)?></div>
    <?php if($page==='trash'&&!empty($mails)):?>
    <form method="POST" onsubmit="return confirm('Permanently delete ALL messages in trash?')">
      <input type="hidden" name="action" value="empty_trash">
      <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
      <button class="btn btn-danger btn-sm" type="submit">Empty Trash</button>
    </form>
    <?php endif?>
  </div>
  <form method="POST" id="bulk-form">
    <input type="hidden" name="action" value="bulk_action">
    <input type="hidden" name="_csrf"  value="<?=h($csrf_token)?>">
    <input type="hidden" name="_page"  value="<?=h($page)?>">
    <div class="card">
      <?php if(!empty($mails)):?>
      <div class="bulk-bar" id="bulk-bar">
        <span class="bulk-count"><span id="bulk-count">0</span> selected</span>
        <button class="btn btn-secondary btn-xs" type="submit" name="bulk_op" value="mark_read">Mark Read</button>
        <button class="btn btn-secondary btn-xs" type="submit" name="bulk_op" value="mark_unread">Mark Unread</button>
        <?php if($page==='trash'):?>
        <button class="btn btn-secondary btn-xs" type="submit" name="bulk_op" value="restore">↩ Restore</button>
        <button class="btn btn-danger btn-xs" type="submit" name="bulk_op" value="delete" onclick="return confirm('Delete selected permanently?')">Delete Forever</button>
        <?php else:?>
        <button class="btn btn-secondary btn-xs" type="submit" name="bulk_op" value="trash">Move to Trash</button>
        <?php endif?>
      </div>
      <div class="mail-list-hdr">
        <input type="checkbox" id="check-all" onchange="toggleAll(this)" title="Select all" style="width:15px;height:15px;cursor:pointer;accent-color:var(--pu)">
        <span style="font-size:13px;color:var(--tx2);font-weight:500"><?=$totalCount?> message<?=$totalCount!=1?'s':''?></span>
        <?php if($counts[$page]['u']??0):?><span class="badge badge-pu"><?=$counts[$page]['u']?> unread</span><?php endif?>
      </div>
      <?php else:?>
      <div class="mail-list-hdr" style="border-radius:var(--r2)"></div>
      <?php endif?>
      <?php if(!$mails):?>
        <div class="empty">
          <div class="empty-icon"><?=$folderIcons[$page]?></div>
          <div class="empty-title"><?=ucfirst($page)?> is empty</div>
          <div class="empty-sub">Nothing here yet.</div>
        </div>
      <?php else: foreach($mails as $m):
          $isDraft=$m['folder']==='drafts';$isRead=(bool)$m['is_read'];
          $rowHref=$isDraft?h($base.'?page=compose&draft='.$m['id']):h($base.'?page=view&id='.$m['id']);
          $showAddr=($page==='sent'||$isDraft)?$m['to_addr']:$m['from_addr'];
      ?>
      <div class="mail-row <?=$isRead?'read':'unread'?>">
        <input type="checkbox" name="ids[]" value="<?=$m['id']?>" class="row-check" onchange="updateBulk()">
        <a class="mail-link" href="<?=$rowHref?>">
          <?php if(!$isRead):?><div class="mail-dot"></div><?php else:?><div class="mail-spacer"></div><?php endif?>
          <div class="mail-from"><?=h(mb_substr($showAddr,0,26))?></div>
          <div class="mail-subj"><?=h($m['subject']?:'(no subject)')?></div>
          <?php if($m['has_attach']):?><div class="mail-attach-icon">📎</div><?php endif?>
          <div class="mail-time"><?=timeEl($m['created_at'])?></div>
        </a>
      </div>
      <?php endforeach;endif?>
    </div>
  </form>
  <?php if($totalCount>PPP):?>
  <div class="pager">
    <?php if($offset>0):?><a class="btn btn-secondary btn-sm" href="<?=h($base.'?page='.$page.'&offset='.max(0,$offset-PPP))?>">← Previous</a><?php endif?>
    <span style="font-weight:500"><?=$offset+1?>–<?=min($offset+PPP,$totalCount)?> of <?=$totalCount?></span>
    <?php if($offset+PPP<$totalCount):?><a class="btn btn-secondary btn-sm" href="<?=h($base.'?page='.$page.'&offset='.($offset+PPP))?>">Next →</a><?php endif?>
  </div>
  <?php endif?>

  <?php elseif($page==='compose'): ?>
  <div class="page-hdr">
    <div class="page-title">✉ Compose<?=$draftMail?' <span style="font-size:13px;font-weight:400;color:var(--tx2)">(editing draft)</span>':''?></div>
  </div>
  <div class="card" style="max-width:760px"><div style="padding:20px 20px 0">
    <?php if($draftMail):?><div class="alert alert-warn">📝 Draft loaded — re-enter the message password to save or send.</div><?php endif?>
    <form method="POST" enctype="multipart/form-data">
      <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
      <input type="hidden" name="reply_to_uid" value="<?=h($composeReplyToUid)?>">
      <input type="hidden" name="thread_uid" value="<?=h($composeThreadUid?:($draftMail?$draftMail['thread_uid']??'':uid()))?>">
      <?php if($draftMail):?><input type="hidden" name="draft_id" value="<?=$draftMail['id']?>"><?php endif?>
      <div class="form-g"><label class="form-label">To</label><input class="form-input" type="text" name="to" value="<?=h($_POST['to']??($draftMail?$draftMail['to_addr']:($_GET['to']??'')))?>" placeholder="user@host/xmail.php — separate multiple with commas" autocomplete="off"></div>
      <div class="form-g"><label class="form-label">CC <span style="font-weight:400;color:var(--tx2)">(optional)</span></label><input class="form-input" type="text" name="cc" value="<?=h($_POST['cc']??($draftMail?$draftMail['cc_addr']??'':''))?>" placeholder="Carbon copy recipients" autocomplete="off"></div>
      <div class="form-g"><label class="form-label">BCC <span style="font-weight:400;color:var(--tx2)">(optional, hidden from others)</span></label><input class="form-input" type="text" name="bcc" value="<?=h($_POST['bcc']??($draftMail?$draftMail['bcc_addr']??'':''))?>" placeholder="Blind carbon copy" autocomplete="off"></div>
      <div class="form-g"><label class="form-label">Subject</label><input class="form-input" type="text" name="subject" value="<?=h($_POST['subject']??($draftMail?$draftMail['subject']:($_GET['subject']??'')))?>" maxlength="255" placeholder="Subject line (stored unencrypted)"></div>
      <div class="form-g"><label class="form-label">Message</label><textarea class="form-input" name="body" rows="11" maxlength="50000" placeholder="Message body — encrypted end-to-end with the password below…"><?=h($_POST['body']??'')?></textarea></div>
      <div class="divider"></div>
      <div class="form-g">
        <label class="form-label">🔑 Message Password <span class="enc-badge">AES-256-GCM</span></label>
        <input class="form-input" type="password" name="msg_password" value="<?=h($composePrefillPass)?>" minlength="4" autocomplete="new-password" placeholder="Encrypts both body and all attachments">
        <div class="form-hint">Share this with your recipients via a separate secure channel. The server never stores it.</div>
      </div>
      <div class="form-g"><label class="form-label">Attachments <span style="font-weight:400;color:var(--tx2)">(up to 5 · max <?=fmtBytes(MAX_ATTACH)?> each · encrypted)</span></label><input class="form-input" type="file" name="attachments[]" multiple accept="image/*,.pdf,.txt,.csv,.zip,.doc,.docx,.xls,.xlsx" style="padding:5px"></div>
      <div class="compose-sticky">
        <button class="btn btn-primary" type="submit" name="action" value="send">Send Message →</button>
        <button class="btn btn-secondary" type="submit" name="action" value="save_draft">Save Draft</button>
        <a class="btn btn-secondary" href="<?=h($base.'?page=inbox')?>">Cancel</a>
      </div>
    </form>
  </div></div>

  <?php elseif($page==='view'): ?>
  <?php if(!$singleMail): ?>
    <div class="card"><div class="empty"><div class="empty-icon">🔍</div><div class="empty-title">Message not found</div></div></div>
  <?php else:
    $subject = h($singleMail['subject']?:'(no subject)');
    $replyUrl= $base.'?page=compose&reply_to_uid='.urlencode($singleMail['uid'])
             .'&thread_uid='.urlencode($threadUidCurrent)
             .'&to='.urlencode($singleMail['from_addr'])
             .'&subject='.urlencode(preg_replace('/^(Re:\s*)*/i','Re: ',$singleMail['subject']));
  ?>
  <div style="margin-bottom:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
    <a class="btn btn-secondary btn-sm" href="javascript:history.back()">← Back</a>
    <div class="page-title" style="font-size:16px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?=$subject?></div>
    <span class="enc-badge">🔒 AES-256-GCM</span>
    <?php if($decrypted):?>
    <span style="font-size:11.5px;color:var(--gr);font-weight:600;background:var(--gr-l);padding:4px 10px;border-radius:20px;border:1px solid rgba(0,135,90,.18)">✓ Decrypted</span>
    <?php endif?>
  </div>

  <?php if(!$decrypted): ?>
  <div class="card">
    <div class="pass-gate">
      <div class="pass-gate-icon">🔒</div>
      <div style="font-size:16px;font-weight:700;margin-bottom:6px">Encrypted Thread</div>
      <div class="form-hint" style="margin-bottom:20px;font-size:13px">Enter the message password to decrypt <?=count($threadMails)?> message<?=count($threadMails)!=1?'s':''?> in this thread.</div>
      <?php if(!empty($errors)):?><div class="alert alert-err">⚠ <?=h(implode(' ',$errors))?></div><?php endif?>
      <form method="POST">
        <input type="hidden" name="action" value="unlock_thread">
        <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
        <input type="hidden" name="thread_uid" value="<?=h($threadUidCurrent)?>">
        <input type="hidden" name="mail_id" value="<?=$singleMail['id']?>">
        <input class="form-input" type="password" name="msg_password" placeholder="Message password" required autofocus autocomplete="off" style="margin-bottom:10px">
        <button class="btn btn-primary" type="submit" style="width:100%">Decrypt & Read →</button>
      </form>
    </div>
    <?php if(count($threadMails)>1):?>
    <div style="border-top:1px solid var(--bd);padding:12px 18px">
      <div class="section-label" style="margin-bottom:8px">Thread Preview · <?=count($threadMails)?> messages</div>
      <?php foreach($threadMails as $tm):?>
      <div style="display:flex;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid var(--bg3)">
        <span style="font-size:12.5px;color:var(--tx2);width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?=h(mb_substr($tm['from_addr'],0,32))?></span>
        <span style="flex:1"><span class="badge badge-pu" style="font-size:10px">🔒 encrypted</span></span>
        <span class="mail-time"><?=timeEl($tm['created_at'])?></span>
      </div>
      <?php endforeach?>
    </div>
    <?php endif?>
  </div>
  <?php else: /* ── DECRYPTED THREAD VIEW ── */ ?>
  <div class="thread-wrap">
  <?php foreach($threadMails as $tm):
      $isFromMe=($tm['from_addr']===mailAddress($cu));
      $tmIsRead=(bool)$tm['is_read'];
      $tmAttach=$threadAttachments[$tm['uid']]??[];
  ?>
    <div class="thread-msg <?=$tmIsRead?'read':'unread'?> <?=$isFromMe?'outgoing':'incoming'?>">
      <div class="thread-msg-hdr">
        <div class="thread-msg-meta">
          <div><b>From:</b> <?=h($tm['from_addr'])?>
            <?php if($isFromMe):?><span class="badge badge-pu" style="font-size:10px;margin-left:5px">you</span><?php endif?>
          </div>
          <div><b>To:</b> <?=h($tm['to_addr'])?></div>
          <?php if($tm['cc_addr']):?><div><b>CC:</b> <?=h($tm['cc_addr'])?></div><?php endif?>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
          <div class="thread-msg-time"><?=timeEl($tm['created_at'])?></div>
          <?php /* ── EML EXPORT BUTTON — shown only when decrypted (v3.4.0) ── */ ?>
          <a class="eml-export-btn"
             href="<?=h($base.'?dl_eml='.$tm['id'])?>"
             title="Export as .eml — opens in Thunderbird, Apple Mail, Outlook, etc.">
            <span class="eml-icon">📧</span> Export .eml
          </a>
        </div>
      </div>
      <?php if($tm['_ok']??false): ?>
        <div class="thread-msg-body"><?=h($tm['_body']??'')?></div>
      <?php else: ?>
        <div class="locked-body">🔒 Could not decrypt this message with the current password.</div>
      <?php endif?>
      <?php if(!empty($tmAttach)):?>
      <div class="thread-msg-attach">
        <span class="section-label" style="width:100%;margin-bottom:5px">📎 Attachments</span>
        <?php foreach($tmAttach as $a):?>
          <a class="attach-chip" href="<?=h($base.'?dl='.$a['id'])?>">📄 <?=h($a['filename'])?> <span style="color:var(--tx3);font-size:11.5px">(<?=fmtBytes($a['size'])?>)</span></a>
        <?php endforeach?>
      </div>
      <?php endif?>
      <div class="thread-msg-actions">
        <?php if($tm['folder']==='trash'):?>
          <form method="POST" style="display:inline"><input type="hidden" name="action" value="restore"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="mail_id" value="<?=$tm['id']?>"><button class="btn btn-secondary btn-sm">↩ Restore</button></form>
          <form method="POST" style="display:inline" onsubmit="return confirm('Delete this message permanently?')"><input type="hidden" name="action" value="delete_perm"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="mail_id" value="<?=$tm['id']?>"><button class="btn btn-danger btn-sm">Delete Forever</button></form>
        <?php elseif($tm['folder']!=='sent'):?>
          <form method="POST" style="display:inline"><input type="hidden" name="action" value="move_trash"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="mail_id" value="<?=$tm['id']?>"><input type="hidden" name="_back" value="<?=h($base.'?page='.$tm['folder'])?>"><button class="btn btn-secondary btn-sm">Move to Trash</button></form>
        <?php endif?>
      </div>
    </div>
  <?php endforeach?>
  <div style="padding:4px 0 10px">
    <a class="btn btn-primary" href="<?=h($replyUrl)?>">↩ Reply to Thread</a>
  </div>
  </div>
  <?php endif?>
  <?php endif?>

  <?php elseif($page==='settings'): ?>
  <div class="page-hdr"><div class="page-title">⚙️ Settings</div></div>
  <div class="card" style="max-width:540px">
    <div style="padding:18px 20px;border-bottom:1px solid var(--bd)">
      <div class="form-label" style="margin-bottom:6px">Your Mail Address</div>
      <div class="addr-box"><?=h(mailAddress($cu))?></div>
      <div class="form-hint" style="margin-top:5px">Share this address so others can send you encrypted messages.</div>
    </div>
    <div style="padding:18px 20px;border-bottom:1px solid var(--bd)">
      <div class="form-label" style="margin-bottom:5px">Username <span style="font-weight:400;color:var(--tx2)">(permanent)</span></div>
      <input class="form-input" value="<?=h($cu['username'])?>" disabled>
    </div>
    <div style="padding:18px 20px">
      <form method="POST">
        <input type="hidden" name="action" value="update_settings">
        <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
        <div class="form-g"><label class="form-label">Display Name</label><input class="form-input" type="text" name="display_name" value="<?=h($cu['display_name'])?>" maxlength="100"></div>
        <div class="divider"></div>
        <div style="font-weight:600;font-size:13.5px;margin-bottom:10px">Change Account Password</div>
        <div class="alert alert-info" style="margin-bottom:14px">Your account password is for login only. Message passwords are separate — changing it does not affect encrypted mail.</div>
        <div class="form-g"><label class="form-label">Current Password</label><input class="form-input" type="password" name="current_password" required autocomplete="current-password"></div>
        <div class="form-g"><label class="form-label">New Password <span style="font-weight:400;color:var(--tx2)">(min. 8 chars, leave blank to keep)</span></label><input class="form-input" type="password" name="new_password" minlength="8" autocomplete="new-password"></div>
        <div class="form-g"><label class="form-label">Confirm New Password</label><input class="form-input" type="password" name="confirm_password" autocomplete="new-password"></div>
        <button class="btn btn-primary" type="submit">Save Changes →</button>
      </form>
    </div>
  </div>

  <?php elseif($page==='admin'&&isAdmin()): ?>
  <div class="page-hdr"><div class="page-title">🔑 Admin Panel</div></div>
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-val"><?=count($allUsers)?></div><div class="stat-lbl">Total users</div></div>
    <div class="stat-card"><div class="stat-val"><?=(int)db()->query("SELECT COUNT(*) FROM mails")->fetchColumn()?></div><div class="stat-lbl">Total messages</div></div>
    <div class="stat-card"><div class="stat-val" style="color:<?=getSetting('registration')==='open'?'var(--gr)':'var(--re)'?>;font-size:16px;padding-top:4px"><?=getSetting('registration')==='open'?'✅ Open':'🔒 Closed'?></div><div class="stat-lbl">Registration</div></div>
  </div>
  <div class="card" style="max-width:720px">
    <div style="padding:14px 20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
      <span style="font-weight:600;font-size:13.5px">Registration: <span style="color:<?=getSetting('registration')==='open'?'var(--gr)':'var(--re)'?>"><?=getSetting('registration')==='open'?'Open':'Closed'?></span></span>
      <form method="POST"><input type="hidden" name="action" value="admin_toggle_reg"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><button class="btn btn-secondary btn-sm"><?=getSetting('registration')==='open'?'Close Registration':'Open Registration'?></button></form>
    </div>
    <div style="padding:14px 20px;overflow-x:auto">
      <div class="section-label" style="margin-bottom:12px">Users (<?=count($allUsers)?>)</div>
      <table class="tbl">
        <thead><tr><th>Username</th><th>Display Name</th><th>Role</th><th>Joined</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach($allUsers as $u):?>
          <tr>
            <td><code style="font-size:12.5px;background:var(--bg2);padding:2px 7px;border-radius:5px;color:var(--tx)"><?=h($u['username'])?></code></td>
            <td><?=h($u['display_name'])?></td>
            <td><?=$u['is_admin']?'<span class="badge badge-pu">Admin</span>':'<span class="badge badge-muted">User</span>'?></td>
            <td style="color:var(--tx2);font-size:12.5px"><?=date('M j, Y',$u['created_at'])?></td>
            <td><?php if((int)$u['id']!==(int)$cu['id']):?>
              <div style="display:flex;gap:6px;flex-wrap:wrap">
                <form method="POST" style="display:inline"><input type="hidden" name="action" value="admin_toggle_admin"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="user_id" value="<?=$u['id']?>"><button class="btn btn-secondary btn-xs"><?=$u['is_admin']?'Revoke Admin':'Make Admin'?></button></form>
                <form method="POST" style="display:inline" onsubmit="return confirm('Delete user and all their messages?')"><input type="hidden" name="action" value="admin_delete_user"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="user_id" value="<?=$u['id']?>"><button class="btn btn-danger btn-xs">Delete</button></form>
              </div>
            <?php else:?><span class="badge badge-muted">you</span><?php endif?></td>
          </tr>
        <?php endforeach?>
        </tbody>
      </table>
    </div>
  </div>
  <?php endif?>
  </main>
</div>

<nav class="bottom-nav">
  <a href="<?=h($base.'?page=inbox')?>" class="<?=$page==='inbox'?'active':''?>"><span class="bn-icon">📥</span>Inbox<?php if(($counts['inbox']['u']??0)>0):?> <sup style="color:var(--pu);font-weight:700"><?=$counts['inbox']['u']?></sup><?php endif?></a>
  <a href="<?=h($base.'?page=compose')?>" class="<?=$page==='compose'?'active':''?>"><span class="bn-icon">✉️</span>Compose</a>
  <a href="<?=h($base.'?page=sent')?>" class="<?=$page==='sent'?'active':''?>"><span class="bn-icon">📤</span>Sent</a>
  <a href="<?=h($base.'?page=drafts')?>" class="<?=$page==='drafts'?'active':''?>"><span class="bn-icon">📝</span>Drafts</a>
  <a href="<?=h($base.'?page=settings')?>" class="<?=in_array($page,['settings','admin'],true)?'active':''?>"><span class="bn-icon">⚙️</span>More</a>
</nav>

<?php endif?>
<script<?=$n?>>
function toggleSb(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('soverlay').classList.toggle('open');}
function closeSb(){document.getElementById('sidebar').classList.remove('open');document.getElementById('soverlay').classList.remove('open');}
function updateBulk(){var n=document.querySelectorAll('.row-check:checked').length;var bar=document.getElementById('bulk-bar');if(bar){bar.className='bulk-bar'+(n>0?' active':'');var el=document.getElementById('bulk-count');if(el)el.textContent=n;}}
function toggleAll(cb){document.querySelectorAll('.row-check').forEach(function(c){c.checked=cb.checked;});updateBulk();}
window.addEventListener('resize',function(){if(window.innerWidth>900)closeSb();});
</script>
</body>
</html>

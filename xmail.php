<?php
/**
 * XMail — Federated Encrypted Mail System
 *
 * @author  xsukax
 * @version 3.0.1
 * @license GPL-3.0-or-later
 *
 * Encryption model (zero-knowledge):
 *   - Sender picks a password at compose time; AES-256-GCM encrypts body + attachments.
 *   - Subject is stored in plaintext. Body + files never leave the server unencrypted.
 *   - Server never stores or transmits the message password.
 *   - Recipient (and sender re-reading) enters the password on the view page.
 *   - All replies in a thread share the same password; once unlocked it persists in session.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v3 or later.
 */

define('APP_NAME',    'XMail');
define('APP_VER',     '3.0.1');
define('DB_PATH',     __DIR__ . '/xmail.db');
define('UPLOAD_DIR',  __DIR__ . '/attachments/');
define('MAX_ATTACH',  10485760);   // 10 MB
define('PPP',         25);
define('FED_TIMEOUT', 30);  // increased: large encrypted payloads need more time

foreach (['pdo_sqlite', 'openssl'] as $ext)
    if (!extension_loaded($ext)) die("<h2>XMail requires the <code>$ext</code> PHP extension.</h2>");

session_start();

// ═══════════════════════════════ DATABASE ════════════════════════════════════

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
            thread_uid TEXT NOT NULL DEFAULT '',
            reply_to_uid TEXT DEFAULT NULL,
            from_addr TEXT NOT NULL, to_addr TEXT NOT NULL DEFAULT '',
            cc_addr TEXT NOT NULL DEFAULT '', bcc_addr TEXT NOT NULL DEFAULT '',
            subject TEXT NOT NULL DEFAULT '',
            body_enc TEXT NOT NULL DEFAULT '',
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
        INSERT OR IGNORE INTO settings(key,value) VALUES('registration','open');
        CREATE INDEX IF NOT EXISTS idx_mails_owner  ON mails(owner_id, folder, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_mails_thread ON mails(thread_uid);
        CREATE INDEX IF NOT EXISTS idx_attach_uid   ON attachments(mail_uid);
    ");
    foreach ([
        "ALTER TABLE mails ADD COLUMN thread_uid TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mails ADD COLUMN reply_to_uid TEXT DEFAULT NULL",
        "ALTER TABLE mails ADD COLUMN cc_addr TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mails ADD COLUMN bcc_addr TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE mails ADD COLUMN subject TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE attachments ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0",
    ] as $sql) { try { db()->exec($sql); } catch (Exception $e) {} }
}
function getSetting(string $k): string {
    static $c = [];
    if (array_key_exists($k,$c)) return $c[$k];
    $s = db()->prepare("SELECT value FROM settings WHERE key=?"); $s->execute([$k]);
    return $c[$k] = (string)($s->fetchColumn() ?: '');
}
function setSetting(string $k, string $v): void {
    db()->prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)")->execute([$k,$v]);
}

// ═══════════════════════════════ CRYPTO ══════════════════════════════════════

function deriveKey(string $password, string $salt): string {
    return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
}
/** AES-256-GCM encrypt → base64(salt16|iv12|tag16|ct) */
function encrypt(string $pt, string $pass): string {
    $salt = random_bytes(16); $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($pt, 'aes-256-gcm', deriveKey($pass, $salt), OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new RuntimeException('Encryption failed');
    return base64_encode($salt . $iv . $tag . $ct);
}
/** AES-256-GCM decrypt. Throws on wrong password or corruption. */
function decrypt(string $blob, string $pass): string {
    $raw = base64_decode($blob, true);
    if ($raw === false || strlen($raw) < 44) throw new RuntimeException('Invalid ciphertext');
    $pt = openssl_decrypt(substr($raw,44), 'aes-256-gcm',
          deriveKey($pass, substr($raw,0,16)), OPENSSL_RAW_DATA, substr($raw,16,12), substr($raw,28,16));
    if ($pt === false) throw new RuntimeException('Wrong password or corrupted data');
    return $pt;
}

// ═══════════════════════════════ HELPERS ═════════════════════════════════════

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
function baseURL(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    return ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
         . ($_SERVER['SCRIPT_NAME'] ?? '/xmail.php');
}
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
    $d = max(0, time()-$ts);
    if ($d < 60)      return $d.'s ago';
    if ($d < 3600)    return floor($d/60).'m ago';
    if ($d < 86400)   return floor($d/3600).'h ago';
    if ($d < 604800)  return floor($d/86400).'d ago';
    return date('M j, Y', $ts);
}
function timeEl(int $ts): string {
    return '<time datetime="'.date('c',$ts).'" title="'.date('F j, Y g:i a',$ts).'">'.h(ago($ts)).'</time>';
}
function fmtBytes(int $b): string {
    if ($b<1024) return $b.' B'; if ($b<1048576) return round($b/1024,1).' KB';
    return round($b/1048576,1).' MB';
}
function uid(): string { return bin2hex(random_bytes(16)); }

// ════════════════════════════ USER HELPERS ═══════════════════════════════════

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
    $url  = baseURL();
    return $user['username'].'@'.(parse_url($url,PHP_URL_HOST)??'localhost')
         .(parse_url($url,PHP_URL_PATH)??'/xmail.php');
}
function parseAddress(string $addr): ?array {
    if (!preg_match('/^([^@\s]+)@([^\s\/]+)(\/\S*)?$/', trim($addr), $m)) return null;
    return ['username'=>$m[1],
            'base_https'=>'https://'.$m[2].($m[3]??'/xmail.php'),
            'base_http' =>'http://' .$m[2].($m[3]??'/xmail.php')];
}
function isLocalAddress(string $base, array $p): bool {
    return $p['base_https'] === $base || $p['base_http'] === str_replace('https://','http://',$base);
}

// ════════════════════════════ FILE HELPERS ═══════════════════════════════════

function ensureUploads(): void {
    if (!is_dir(UPLOAD_DIR)) @mkdir(UPLOAD_DIR, 0750, true);
    $ht = UPLOAD_DIR.'.htaccess';
    if (!file_exists($ht)) @file_put_contents($ht,"Deny from all\nOptions -Indexes\n<FilesMatch \"\\.php$\">\nDeny from all\n</FilesMatch>\n");
    $dht = __DIR__.'/.htaccess';
    if (!file_exists($dht)) @file_put_contents($dht,"<FilesMatch \"\\.(db|sqlite|sqlite3)$\">\nDeny from all\n</FilesMatch>\n");
}
$ALLOWED_MIME = ['image/jpeg','image/png','image/gif','image/webp','application/pdf',
    'text/plain','text/csv','application/zip','application/x-zip-compressed','application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];

function safeUpload(array $file, string $msgPass): ?array {
    global $ALLOWED_MIME;
    if ($file['error'] !== UPLOAD_ERR_OK || $file['size'] > MAX_ATTACH || $file['size'] === 0) return null;
    if (!is_uploaded_file($file['tmp_name'])) return null;
    $mime = mime_content_type($file['tmp_name']);
    if (!in_array($mime, $ALLOWED_MIME, true)) return null;
    $ext  = strtolower(preg_replace('/[^a-z0-9]/','',pathinfo($file['name'],PATHINFO_EXTENSION)));
    $name = bin2hex(random_bytes(16)).($ext ? '.'.$ext : '');
    $dest = UPLOAD_DIR.$name;
    // Read, encrypt, write
    $raw = file_get_contents($file['tmp_name']);
    if ($raw === false) return null;
    try { $enc = encrypt($raw, $msgPass); } catch (Exception $e) { return null; }
    if (file_put_contents($dest, $enc) === false) return null;
    return ['stored'=>$name,'original'=>basename($file['name']),'mime'=>$mime,'size'=>$file['size'],'encrypted'=>true];
}
function deleteAttachments(string $mailUid): void {
    $s = db()->prepare("SELECT stored_name FROM attachments WHERE mail_uid=?"); $s->execute([$mailUid]);
    foreach ($s->fetchAll() as $a) {
        $ref = db()->prepare("SELECT COUNT(*) FROM attachments WHERE stored_name=? AND mail_uid!=?");
        $ref->execute([$a['stored_name'],$mailUid]);
        if (!(int)$ref->fetchColumn()) { $fp = UPLOAD_DIR.basename($a['stored_name']); if (file_exists($fp)) @unlink($fp); }
    }
    db()->prepare("DELETE FROM attachments WHERE mail_uid=?")->execute([$mailUid]);
}

// ════════════════════════════ FEDERATION ═════════════════════════════════════

function fedFetch(string $url, string $method='GET', ?array $body=null): ?array {
    $ctx = stream_context_create(['http'=>[
        'method'=>$method,'timeout'=>FED_TIMEOUT,'ignore_errors'=>true,
        'follow_location'=>1,'max_redirects'=>3,
        'header'=>"Accept: application/json\r\nContent-Type: application/json\r\nUser-Agent: XMail/".APP_VER."\r\n",
        'content'=>$body!==null?json_encode($body):null,
    ]]);
    $raw = @file_get_contents($url, false, $ctx);
    if (!$raw) return null;
    $d = json_decode($raw, true);
    return is_array($d) ? $d : null;
}
function fedDeliver(array $parsed, array $payload): bool {
    $r = fedFetch($parsed['base_https'].'?api=receive','POST',$payload)
      ?? fedFetch($parsed['base_http'] .'?api=receive','POST',$payload);
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
    if ($_SERVER['REQUEST_METHOD']==='OPTIONS') { http_response_code(204); exit; }
    $api = $_GET['api'];

    if ($api === 'resolve') {
        $un = preg_replace('/[^a-z0-9_\-]/','',strtolower($_GET['user']??''));
        if (!$un) jsonOut(['error'=>'missing user'],400);
        $s = db()->prepare("SELECT username,display_name FROM users WHERE username=?"); $s->execute([$un]); $u=$s->fetch();
        if (!$u) jsonOut(['error'=>'not found'],404);
        jsonOut(['ok'=>true,'username'=>$u['username'],'name'=>$u['display_name']?:$u['username'],'instance'=>baseURL(),'version'=>APP_VER]);
    }

    if ($api === 'receive') {
        if ($_SERVER['REQUEST_METHOD']!=='POST') jsonOut(['error'=>'POST required'],405);
        $b = json_decode(file_get_contents('php://input'),true);
        if (!is_array($b)) jsonOut(['error'=>'invalid JSON'],400);
        $toUser    = preg_replace('/[^a-z0-9_\-]/','',strtolower($b['to_user']??''));
        $fromAddr  = substr(preg_replace('/[^\w@.\-\/:]/','',$b['from_addr']??''),0,200);
        $subject   = mb_substr(strip_tags((string)($b['subject']??'')),0,255);
        $bodyEnc   = (string)($b['body_enc']??'');
        $threadUid = preg_replace('/[^a-f0-9]/','',($b['thread_uid']??''));
        $repUid    = preg_replace('/[^a-f0-9]/','',($b['reply_to_uid']??''));
        $ccAddr    = mb_substr(strip_tags((string)($b['cc_addr']??'')),0,500);
        $mailUid   = preg_replace('/[^a-f0-9]/','',($b['uid']??''));
        $attachMeta= is_array($b['attachments']??null)?$b['attachments']:[];
        if (!$toUser||!$fromAddr||!$bodyEnc||strlen($mailUid)!==32) jsonOut(['error'=>'incomplete payload'],400);
        if (!$threadUid) $threadUid = uid();
        $s = db()->prepare("SELECT id FROM users WHERE username=?"); $s->execute([$toUser]); $owner=$s->fetch();
        if (!$owner) jsonOut(['error'=>'user not found'],404);
        $ck = db()->prepare("SELECT id FROM mails WHERE uid=?"); $ck->execute([$mailUid]);
        if ($ck->fetch()) jsonOut(['ok'=>true,'note'=>'duplicate']);
        db()->prepare("INSERT INTO mails(uid,thread_uid,reply_to_uid,from_addr,to_addr,cc_addr,subject,body_enc,owner_id,folder,has_attach) VALUES(?,?,?,?,?,?,?,?,?,'inbox',?)")
            ->execute([$mailUid,$threadUid,$repUid?:null,$fromAddr,$toUser,$ccAddr,$subject,$bodyEnc,$owner['id'],empty($attachMeta)?0:1]);
        if (!empty($attachMeta)) {
            $ins = db()->prepare("INSERT INTO attachments(mail_uid,filename,stored_name,mime_type,size,is_encrypted) VALUES(?,?,?,?,?,?)");
            foreach ($attachMeta as $am) {
                $fn = mb_substr(strip_tags((string)($am['filename']??'file')),0,255);
                $sn = preg_replace('/[^a-f0-9.]/','',($am['stored_name']??''));
                $mt = mb_substr(strip_tags((string)($am['mime_type']??'application/octet-stream')),0,100);
                $sz = (int)($am['size']??0);
                $ie = (int)($am['is_encrypted']??1);
                if ($fn && $sn && $sz > 0) {
                    $ins->execute([$mailUid,$fn,$sn,$mt,$sz,$ie]);
                    // ── FIX: write the encrypted file bytes sent by the sender ──
                    if (!empty($am['content'])) {
                        $destPath = UPLOAD_DIR . basename($sn);
                        // Only write if not already present (idempotent re-delivery)
                        if (!file_exists($destPath)) {
                            // content is the raw encrypted blob (already base64 from encrypt())
                            file_put_contents($destPath, $am['content']);
                        }
                    }
                }
            }
        }
        jsonOut(['ok'=>true]);
    }
    jsonOut(['error'=>'unknown endpoint'],404);
}

// ════════════════════════════ DOWNLOAD ═══════════════════════════════════════

if (isset($_GET['dl'])) {
    initDB();
    if (!isLoggedIn()) { http_response_code(403); exit('Forbidden'); }
    $cu = currentUser(); if (!$cu) { http_response_code(403); exit('Forbidden'); }
    $s = db()->prepare("SELECT a.*,m.owner_id,m.uid AS mail_uid,m.thread_uid,m.id AS mail_id FROM attachments a JOIN mails m ON a.mail_uid=m.uid WHERE a.id=?");
    $s->execute([(int)$_GET['dl']]); $a=$s->fetch();
    if (!$a||(int)$a['owner_id']!==(int)$cu['id']) { http_response_code(403); exit('Forbidden'); }
    $fp = UPLOAD_DIR.basename($a['stored_name']);
    if (!file_exists($fp)) { http_response_code(404); exit('Not found'); }
    $raw = file_get_contents($fp);
    if ($a['is_encrypted']) {
        $tk = $_SESSION['thread_keys'][$a['thread_uid']]??null;
        if (!$tk) redir(baseURL().'?page=view&id='.$a['mail_id'].'&unlock_required=1');
        try { $raw = decrypt($raw, $tk); } catch (Exception $e) { http_response_code(400); exit('Decryption failed'); }
    }
    header('Content-Type: '.$a['mime_type']);
    header('Content-Disposition: attachment; filename="'.addslashes($a['filename']).'"; filename*=UTF-8\'\''.rawurlencode($a['filename']));
    header('Content-Length: '.strlen($raw));
    header('Cache-Control: private, no-store');
    echo $raw; exit;
}

// ════════════════════════════ APP INIT ═══════════════════════════════════════

initDB(); ensureUploads();
$base       = baseURL();
$csrf_token = csrf();
$errors     = []; $info = '';
$page       = preg_replace('/[^a-z]/','', (string)($_GET['page']??'inbox'));
$act        = (string)($_POST['action']??'');
$cu         = currentUser();

// Pre-init all render variables (goto safety)
$mails=$threadMails=$threadAttachments=[]; $singleMail=$draftMail=null;
$decrypted=false; $threadKey=null; $threadUidCurrent='';
$allUsers=[]; $counts=[]; $totalCount=0; $offset=max(0,(int)($_GET['offset']??0));
$folderIcons=['inbox'=>'📥','sent'=>'📤','drafts'=>'📝','trash'=>'🗑️'];

$hasAdmin   = (bool)db()->query("SELECT COUNT(*) FROM users WHERE is_admin=1")->fetchColumn();
$isFirstRun = !$hasAdmin;

// ─── First-run setup ──────────────────────────────────────────────────────────
if ($isFirstRun && $act==='setup') {
    $un=$p=$p2=''; extract(['un'=>strtolower(trim($_POST['username']??'')),'p'=>$_POST['password']??'','p2'=>$_POST['password2']??'']);
    $un=strtolower(trim($_POST['username']??'')); $p=$_POST['password']??''; $p2=$_POST['password2']??'';
    if (!preg_match('/^[a-z0-9_]{3,30}$/',$un)) $errors[]='Invalid username.';
    elseif (strlen($p)<8)  $errors[]='Password ≥ 8 chars.';
    elseif ($p!==$p2)      $errors[]='Passwords do not match.';
    if (!$errors) {
        db()->prepare("INSERT INTO users(username,password,display_name,is_admin) VALUES(?,?,?,1)")
            ->execute([$un,password_hash($p,PASSWORD_DEFAULT),$un]);
        session_regenerate_id(true);
        $s=db()->prepare("SELECT id FROM users WHERE username=?"); $s->execute([$un]);
        $_SESSION['uid']=(int)$s->fetchColumn();
        redir($base);
    }
}
if ($isFirstRun) goto render;

// ─── Auth ──────────────────────────────────────────────────────────────────────
if ($act==='login') {
    $un=trim($_POST['username']??''); $p=$_POST['password']??'';
    $s=db()->prepare("SELECT * FROM users WHERE username=?"); $s->execute([$un]); $u=$s->fetch();
    if ($u && password_verify($p,$u['password'])) {
        session_regenerate_id(true); $_SESSION['uid']=(int)$u['id']; redir($base);
    }
    $errors[]='Invalid username or password.'; $page='login';
}
if ($act==='logout') {
    $p=session_get_cookie_params();
    setcookie(session_name(),'',-1,$p['path'],$p['domain'],$p['secure'],$p['httponly']);
    session_destroy(); redir($base.'?page=login');
}
$privatePages=['inbox','sent','drafts','trash','compose','view','settings','admin'];
if (!isLoggedIn() && in_array($page,$privatePages,true)) redir($base.'?page=login');
if (!isLoggedIn() && !in_array($page,['login','register'],true)) $page='login';
$cu=currentUser(true);
if (isLoggedIn()&&!$cu) { session_destroy(); redir($base.'?page=login'); }

// ─── Registration ─────────────────────────────────────────────────────────────
if ($act==='register') {
    if (getSetting('registration')!=='open') { $errors[]='Registration is closed.'; $page='register'; }
    else {
        $un=strtolower(trim($_POST['username']??'')); $dn=mb_substr(trim($_POST['display_name']??''),0,100);
        $p=$_POST['password']??''; $p2=$_POST['password2']??'';
        if (!preg_match('/^[a-z0-9_]{3,30}$/',$un)) $errors[]='Invalid username.';
        elseif (strlen($p)<8) $errors[]='Password ≥ 8 chars.';
        elseif ($p!==$p2)     $errors[]='Passwords do not match.';
        else {
            try { db()->prepare("INSERT INTO users(username,password,display_name) VALUES(?,?,?)")->execute([$un,password_hash($p,PASSWORD_DEFAULT),$dn?:$un]); $info='Account created.'; $page='login'; }
            catch (Exception $e) { $errors[]='Username taken.'; $page='register'; }
        }
    }
}

// ─── Unlock thread (password gate POST) ──────────────────────────────────────
if ($act==='unlock_thread' && isLoggedIn() && checkCsrf()) {
    $tid  = preg_replace('/[^a-f0-9]/','', $_POST['thread_uid']??'');
    $mid  = (int)($_POST['mail_id']??0);
    $pass = $_POST['msg_password']??'';
    if (!$pass) { $errors[]='Enter the message password.'; $page='view'; $_GET['id']=$mid; }
    else {
        $vs=db()->prepare("SELECT body_enc FROM mails WHERE id=? AND owner_id=?");
        $vs->execute([$mid,$cu['id']]); $vm=$vs->fetch();
        if ($vm) {
            try { decrypt($vm['body_enc'],$pass); $_SESSION['thread_keys'][$tid]=$pass; redir($base.'?page=view&id='.$mid); }
            catch (Exception $e) { $errors[]='Wrong password — decryption failed.'; $page='view'; $_GET['id']=$mid; }
        } else { $page='inbox'; }
    }
}

// ─── Compose / Send / Save Draft ──────────────────────────────────────────────
if (($act==='send'||$act==='save_draft') && isLoggedIn() && checkCsrf()) {
    $toRaw   = trim($_POST['to']??'');
    $ccRaw   = trim($_POST['cc']??'');
    $bccRaw  = trim($_POST['bcc']??'');
    $subj    = mb_substr(trim($_POST['subject']??''),0,255);
    $body    = mb_substr(trim($_POST['body']??''),0,50000);
    $msgPass = $_POST['msg_password']??'';
    $draftId = (int)($_POST['draft_id']??0);
    $tUid    = preg_replace('/[^a-f0-9]/','',($_POST['thread_uid']??'')) ?: uid();
    $repUid  = preg_replace('/[^a-f0-9]/','',($_POST['reply_to_uid']??'')) ?: null;

    if ($act==='send') {
        if (!$toRaw)              $errors[]='Recipient is required.';
        if (!$subj)               $errors[]='Subject is required.';
        if (!$body)               $errors[]='Body cannot be empty.';
        if (strlen($msgPass)<4)   $errors[]='Message password must be ≥ 4 characters.';
    } elseif (strlen($msgPass)<4) $errors[]='Message password must be ≥ 4 characters.';

    if (!$errors) {
        $mailUid  = uid();
        $fromAddr = mailAddress($cu);
        $folder   = $act==='save_draft'?'drafts':'sent';
        $bodyEnc  = encrypt($body?:'', $msgPass);
        $attachMeta = [];

        if (!empty($_FILES['attachments']['name'][0])) {
            $files=$_FILES['attachments']; $count=is_array($files['name'])?count($files['name']):0;
            for ($i=0;$i<min($count,5);$i++) {
                if ((int)$files['error'][$i]===UPLOAD_ERR_NO_FILE) continue;
                $f=['name'=>$files['name'][$i],'type'=>$files['type'][$i],'tmp_name'=>$files['tmp_name'][$i],'error'=>$files['error'][$i],'size'=>$files['size'][$i]];
                $up=safeUpload($f,$msgPass);
                if (!$up) $errors[]='Attachment "'.h($f['name']).'" rejected.'; else $attachMeta[]=$up;
            }
        }

        if (!$errors) {
            if ($draftId) {
                $ds=db()->prepare("SELECT uid FROM mails WHERE id=? AND owner_id=? AND folder='drafts'");
                $ds->execute([$draftId,$cu['id']]); $dr=$ds->fetch();
                if ($dr) { deleteAttachments($dr['uid']); db()->prepare("DELETE FROM mails WHERE id=?")->execute([$draftId]); }
            }
            db()->prepare("INSERT INTO mails(uid,thread_uid,reply_to_uid,from_addr,to_addr,cc_addr,bcc_addr,subject,body_enc,owner_id,folder,is_read,has_attach) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?)")
                ->execute([$mailUid,$tUid,$repUid,$fromAddr,$toRaw,$ccRaw,$bccRaw,$subj,$bodyEnc,$cu['id'],$folder,empty($attachMeta)?0:1]);
            if (!empty($attachMeta)) {
                $ins=db()->prepare("INSERT INTO attachments(mail_uid,filename,stored_name,mime_type,size,is_encrypted) VALUES(?,?,?,?,?,?)");
                foreach ($attachMeta as $am) $ins->execute([$mailUid,$am['original'],$am['stored'],$am['mime'],$am['size'],$am['encrypted']?1:0]);
            }
            // Store key in session so sender can re-read from Sent
            $_SESSION['thread_keys'][$tUid] = $msgPass;

            if ($act==='send') {
                $allRecips = array_unique(array_filter(array_map('trim', preg_split('/[,;\s]+/',
                    $toRaw.','.$ccRaw))));
                $bccRecips = array_unique(array_filter(array_map('trim', preg_split('/[,;\s]+/',$bccRaw))));
                $fedWarn=[];
                foreach (array_merge($allRecips,$bccRecips) as $toAddr) {
                    $isBcc = !in_array($toAddr,$allRecips,true);
                    $parsed=parseAddress($toAddr); if (!$parsed) { $fedWarn[]="Invalid: $toAddr"; continue; }
                    if (isLocalAddress($base,$parsed)) {
                        $rs=db()->prepare("SELECT id FROM users WHERE username=?"); $rs->execute([$parsed['username']]); $recv=$rs->fetch();
                        if (!$recv) { $fedWarn[]="Not found: {$parsed['username']}"; continue; }
                        if ((int)$recv['id']===(int)$cu['id']) continue;
                        $lUid=uid();
                        $storeCC = $isBcc ? '' : $ccRaw;
                        db()->prepare("INSERT INTO mails(uid,thread_uid,reply_to_uid,from_addr,to_addr,cc_addr,subject,body_enc,owner_id,folder,has_attach) VALUES(?,?,?,?,?,?,?,?,?,'inbox',?)")
                            ->execute([$lUid,$tUid,$repUid,$fromAddr,$toRaw,$storeCC,$subj,$bodyEnc,$recv['id'],empty($attachMeta)?0:1]);
                        if (!empty($attachMeta)) {
                            $ins2=db()->prepare("INSERT INTO attachments(mail_uid,filename,stored_name,mime_type,size,is_encrypted) VALUES(?,?,?,?,?,?)");
                            foreach ($attachMeta as $am) $ins2->execute([$lUid,$am['original'],$am['stored'],$am['mime'],$am['size'],1]);
                        }
                    } else {
                        // ── FIX: read encrypted file contents and embed in the federation payload ──
                        $amMeta = array_map(function($am) {
                            $fp      = UPLOAD_DIR . basename($am['stored']);
                            $content = file_exists($fp) ? file_get_contents($fp) : null;
                            return [
                                'filename'     => $am['original'],
                                'stored_name'  => $am['stored'],
                                'mime_type'    => $am['mime'],
                                'size'         => $am['size'],
                                'is_encrypted' => 1,
                                // Already a base64 string from encrypt(); recipient writes it directly to disk
                                'content'      => $content,
                            ];
                        }, $attachMeta);

                        if (!fedDeliver($parsed,['uid'=>uid(),'thread_uid'=>$tUid,'reply_to_uid'=>$repUid??'','from_addr'=>$fromAddr,'to_user'=>$parsed['username'],'cc_addr'=>$isBcc?'':$ccRaw,'subject'=>$subj,'body_enc'=>$bodyEnc,'attachments'=>$amMeta]))
                            $fedWarn[]="Delivery failed: $toAddr";
                    }
                }
                if ($fedWarn) { $info=implode('; ',$fedWarn); }
                else redir($base.'?page=sent&info=sent');
            } else redir($base.'?page=drafts&info=draft_saved');
        } else $page='compose';
    } else $page='compose';
}

// ─── Mail actions ──────────────────────────────────────────────────────────────
if ($act==='move_trash'&&isLoggedIn()&&checkCsrf()) {
    db()->prepare("UPDATE mails SET folder='trash' WHERE id=? AND owner_id=?")->execute([(int)$_POST['mail_id'],$cu['id']]);
    redir($_POST['_back']??$base.'?page=inbox');
}
if ($act==='restore'&&isLoggedIn()&&checkCsrf()) {
    db()->prepare("UPDATE mails SET folder='inbox' WHERE id=? AND owner_id=? AND folder='trash'")->execute([(int)$_POST['mail_id'],$cu['id']]);
    redir($base.'?page=trash');
}
if ($act==='delete_perm'&&isLoggedIn()&&checkCsrf()) {
    $id=(int)$_POST['mail_id']; $s=db()->prepare("SELECT uid FROM mails WHERE id=? AND owner_id=? AND folder='trash'");
    $s->execute([$id,$cu['id']]); $m=$s->fetch();
    if ($m) { deleteAttachments($m['uid']); db()->prepare("DELETE FROM mails WHERE id=?")->execute([$id]); }
    redir($base.'?page=trash');
}
if ($act==='empty_trash'&&isLoggedIn()&&checkCsrf()) {
    $s=db()->prepare("SELECT uid FROM mails WHERE owner_id=? AND folder='trash'"); $s->execute([$cu['id']]);
    foreach ($s->fetchAll() as $m) deleteAttachments($m['uid']);
    db()->prepare("DELETE FROM mails WHERE owner_id=? AND folder='trash'")->execute([$cu['id']]);
    redir($base.'?page=trash&info=emptied');
}

// ─── Bulk actions ─────────────────────────────────────────────────────────────
if ($act==='bulk_action'&&isLoggedIn()&&checkCsrf()) {
    $ids  = array_values(array_filter(array_map('intval',(array)($_POST['ids']??[]))));
    $op   = $_POST['bulk_op']??'';
    $pg   = preg_replace('/[^a-z]/','',($_POST['_page']??'inbox'));
    if ($ids) {
        $ph = implode(',',array_fill(0,count($ids),'?'));
        $p  = array_merge($ids,[$cu['id']]);
        if ($op==='mark_read')
            db()->prepare("UPDATE mails SET is_read=1 WHERE id IN ($ph) AND owner_id=?")->execute($p);
        elseif ($op==='mark_unread')
            db()->prepare("UPDATE mails SET is_read=0 WHERE id IN ($ph) AND owner_id=?")->execute($p);
        elseif ($op==='trash')
            db()->prepare("UPDATE mails SET folder='trash' WHERE id IN ($ph) AND owner_id=? AND folder!='trash'")->execute($p);
        elseif ($op==='restore')
            db()->prepare("UPDATE mails SET folder='inbox' WHERE id IN ($ph) AND owner_id=? AND folder='trash'")->execute($p);
        elseif ($op==='delete') {
            $s2=db()->prepare("SELECT uid FROM mails WHERE id IN ($ph) AND owner_id=? AND folder='trash'"); $s2->execute($p);
            foreach ($s2->fetchAll() as $m) deleteAttachments($m['uid']);
            db()->prepare("DELETE FROM mails WHERE id IN ($ph) AND owner_id=? AND folder='trash'")->execute($p);
        }
    }
    redir($base.'?page='.$pg);
}

// ─── Settings ──────────────────────────────────────────────────────────────────
if ($act==='update_settings'&&isLoggedIn()&&checkCsrf()) {
    $dn=mb_substr(trim($_POST['display_name']??''),0,100);
    $cp=$_POST['current_password']??''; $np=$_POST['new_password']??''; $cf=$_POST['confirm_password']??'';
    if (!password_verify($cp,$cu['password'])) { $errors[]='Current password incorrect.'; }
    else {
        if ($dn) db()->prepare("UPDATE users SET display_name=? WHERE id=?")->execute([$dn,$cu['id']]);
        if ($np) {
            if (strlen($np)<8) $errors[]='New password ≥ 8 chars.';
            elseif ($np!==$cf) $errors[]='New passwords do not match.';
            else { db()->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($np,PASSWORD_DEFAULT),$cu['id']]); $info='Password updated.'; }
        } else $info='Display name updated.';
    }
    $page='settings';
}

// ─── Admin ────────────────────────────────────────────────────────────────────
if ($act==='admin_toggle_reg'&&isAdmin()&&checkCsrf()) { setSetting('registration',getSetting('registration')==='open'?'closed':'open'); redir($base.'?page=admin'); }
if ($act==='admin_delete_user'&&isAdmin()&&checkCsrf()) {
    $uid2=(int)($_POST['user_id']??0);
    if ($uid2&&$uid2!==(int)$cu['id']) {
        $ms=db()->prepare("SELECT uid FROM mails WHERE owner_id=?"); $ms->execute([$uid2]);
        foreach ($ms->fetchAll() as $m) deleteAttachments($m['uid']);
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

// ─── Page guard ───────────────────────────────────────────────────────────────
if (isLoggedIn()&&$page==='admin'&&!isAdmin()) $page='inbox';
if (isLoggedIn()&&!in_array($page,$privatePages,true)) $page='inbox';

// ─── Page data loading ────────────────────────────────────────────────────────
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
            $tuid=$singleMail['thread_uid']??'';
            $threadUidCurrent=$tuid;
            if ($tuid) {
                $ts=db()->prepare("SELECT * FROM mails WHERE thread_uid=? AND owner_id=? ORDER BY created_at ASC"); $ts->execute([$tuid,$cu['id']]);
                $threadMails=$ts->fetchAll();
                db()->prepare("UPDATE mails SET is_read=1 WHERE thread_uid=? AND owner_id=?")->execute([$tuid,$cu['id']]);
            } else { $threadMails=[$singleMail]; db()->prepare("UPDATE mails SET is_read=1 WHERE id=?")->execute([$mid]); }
            foreach ($threadMails as $tm) {
                if ($tm['has_attach']) { $as=db()->prepare("SELECT * FROM attachments WHERE mail_uid=?"); $as->execute([$tm['uid']]); $threadAttachments[$tm['uid']]=$as->fetchAll(); }
            }
            $threadKey=$tuid&&isset($_SESSION['thread_keys'][$tuid])?$_SESSION['thread_keys'][$tuid]:null;
            if ($threadKey) {
                foreach ($threadMails as &$tm) { try { $tm['_body']=decrypt($tm['body_enc'],$threadKey); $tm['_ok']=true; } catch(Exception $e) { $tm['_body']=null; $tm['_ok']=false; } }
                unset($tm); $decrypted=true;
            }
        }
    }
    if ($page==='compose'&&isset($_GET['draft'])) {
        $s=db()->prepare("SELECT * FROM mails WHERE id=? AND owner_id=? AND folder='drafts'"); $s->execute([(int)$_GET['draft'],$cu['id']]); $draftMail=$s->fetch()?:null;
    }
    if ($page==='admin'&&isAdmin()) {
        $allUsers=db()->query("SELECT id,username,display_name,is_admin,created_at FROM users ORDER BY created_at ASC")->fetchAll();
    }
}

// Pre-fill compose password from session (reply / draft re-open)
$composePrefillPass = '';
$composeReplyToUid  = preg_replace('/[^a-f0-9]/','',($_GET['reply_to_uid']??''));
$composeThreadUid   = preg_replace('/[^a-f0-9]/','',($_GET['thread_uid']??''));
if ($composeThreadUid && isset($_SESSION['thread_keys'][$composeThreadUid]))
    $composePrefillPass = $_SESSION['thread_keys'][$composeThreadUid];

render:
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= h(APP_NAME) ?></title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#fff;--bg2:#f6f8fa;--bg3:#eaeef2;--bd:#d0d7de;--tx:#1f2328;--tx2:#636e7b;--blue:#0969da;--blue-h:#0550ae;--green:#1a7f37;--red:#cf222e;--orange:#bc4c00;--r:6px;--nav-h:52px;--sb-w:220px}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;font-size:14px;color:var(--tx);background:var(--bg2);min-height:100dvh}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
button,input,textarea,select{font:inherit}textarea{resize:vertical}
/* ── Nav ── */
.nav{background:var(--bg);border-bottom:1px solid var(--bd);height:var(--nav-h);position:sticky;top:0;z-index:60}
.nav-in{display:flex;align-items:center;gap:10px;height:100%;max-width:1200px;margin:0 auto;padding:0 14px}
.nav-logo{font-size:17px;font-weight:800;color:var(--tx);text-decoration:none;flex-shrink:0}
.nav-logo span{color:var(--blue)}
.nav-end{margin-left:auto;display:flex;gap:8px;align-items:center;font-size:13px;color:var(--tx2)}
.hamburger{display:none;background:none;border:1px solid var(--bd);border-radius:var(--r);padding:5px 9px;cursor:pointer;font-size:16px;line-height:1}
/* ── Layout ── */
.app{display:grid;grid-template-columns:var(--sb-w) 1fr;min-height:calc(100dvh - var(--nav-h))}
/* ── Sidebar ── */
.sidebar{background:var(--bg);border-right:1px solid var(--bd);padding:12px 0;overflow-y:auto}
.sb-overlay{display:none;position:fixed;inset:0;top:var(--nav-h);background:rgba(0,0,0,.35);z-index:49}
.sb-head{padding:4px 14px 8px;font-size:11px;font-weight:600;color:var(--tx2);text-transform:uppercase;letter-spacing:.6px}
.sb-item{display:flex;align-items:center;gap:8px;padding:8px 14px;color:var(--tx);font-size:13.5px;font-weight:500;text-decoration:none;transition:background .1s;cursor:pointer}
.sb-item:hover{background:var(--bg2);text-decoration:none}
.sb-item.active{background:rgba(9,105,218,.08);color:var(--blue)}
.sb-badge{margin-left:auto;background:var(--blue);color:#fff;font-size:10px;font-weight:700;padding:1px 6px;border-radius:8px;min-width:18px;text-align:center}
.sb-div{height:1px;background:var(--bd);margin:8px 0}
/* ── Main ── */
.main{padding:16px 18px;overflow-x:hidden;min-width:0}
/* ── Cards ── */
.card{background:var(--bg);border:1px solid var(--bd);border-radius:var(--r)}
.card+.card{margin-top:12px}
/* ── Mail list ── */
.mail-list-hdr{display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--bd);background:var(--bg2)}
.mail-row{display:flex;align-items:center;gap:8px;padding:0;border-bottom:1px solid var(--bd);transition:background .1s}
.mail-row:last-child{border-bottom:none}
.mail-row.read{background:var(--bg2)}
.mail-row.unread{background:var(--bg)}
.mail-row:hover{background:#eaf3ff}
.mail-row input[type=checkbox]{flex-shrink:0;margin-left:12px;width:15px;height:15px;cursor:pointer;accent-color:var(--blue)}
.mail-link{display:flex;align-items:center;gap:10px;flex:1;padding:10px 14px 10px 8px;text-decoration:none;color:var(--tx);overflow:hidden}
.mail-link:hover{text-decoration:none}
.mail-from{font-size:12px;color:var(--tx2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;width:120px;flex-shrink:0}
.mail-row.unread .mail-from{color:var(--tx);font-weight:600}
.mail-subj{flex:1;font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.mail-row.unread .mail-subj{font-weight:700}
.mail-row.read .mail-subj{color:var(--tx2)}
.mail-icons{display:flex;gap:3px;font-size:12px;flex-shrink:0}
.mail-time{font-size:11px;color:var(--tx2);flex-shrink:0;white-space:nowrap}
/* ── Bulk bar ── */
.bulk-bar{display:none;align-items:center;gap:8px;padding:8px 14px;background:#fffbdd;border-bottom:1px solid #e0c84a;flex-wrap:wrap}
.bulk-bar.active{display:flex}
.bulk-count{font-size:13px;font-weight:600;color:var(--tx);margin-right:4px}
/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:6px 14px;border-radius:var(--r);border:1px solid;cursor:pointer;font-size:13.5px;font-weight:500;transition:all .12s;text-decoration:none;white-space:nowrap;min-height:34px}
.btn:hover{text-decoration:none}
.btn-primary{background:var(--blue);color:#fff;border-color:var(--blue)}
.btn-primary:hover{background:var(--blue-h);border-color:var(--blue-h)}
.btn-secondary{background:var(--bg);color:var(--tx);border-color:var(--bd)}
.btn-secondary:hover{background:var(--bg2)}
.btn-danger{background:var(--red);color:#fff;border-color:var(--red)}
.btn-danger:hover{opacity:.88}
.btn-sm{padding:4px 10px;font-size:12px;min-height:28px}
/* ── Forms ── */
.form-g{margin-bottom:14px}
.form-label{display:block;font-size:13px;font-weight:600;margin-bottom:5px}
.form-input{width:100%;padding:7px 10px;border:1px solid var(--bd);border-radius:var(--r);font-size:13.5px;background:var(--bg);color:var(--tx);transition:border-color .12s;min-height:36px}
.form-input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(9,105,218,.1)}
.form-hint{font-size:11.5px;color:var(--tx2);margin-top:3px}
textarea.form-input{min-height:180px}
/* ── Alerts ── */
.alert{padding:10px 13px;border-radius:var(--r);margin-bottom:12px;font-size:13.5px;border:1px solid}
.alert-err{background:#fff0ef;color:var(--red);border-color:#fcc3c0}
.alert-ok{background:#dafbe1;color:var(--green);border-color:#aceebb}
.alert-info{background:#ddf4ff;color:#0550ae;border-color:#9cd0f5}
.alert-warn{background:#fff8c5;color:var(--orange);border-color:#f0c800}
/* ── Page header ── */
.page-hdr{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px;flex-wrap:wrap}
.page-title{font-size:17px;font-weight:700}
.enc-badge{display:inline-flex;align-items:center;gap:3px;background:rgba(26,127,55,.08);border:1px solid rgba(26,127,55,.2);border-radius:10px;padding:2px 7px;font-size:11px;color:var(--green);margin-left:5px;vertical-align:middle}
/* ── Thread view ── */
.thread-wrap{display:flex;flex-direction:column;gap:0}
.thread-msg{border:1px solid var(--bd);border-radius:var(--r);margin-bottom:10px;overflow:hidden}
.thread-msg.unread{border-left:3px solid var(--blue)}
.thread-msg.read{opacity:.92}
.thread-msg.outgoing .thread-msg-hdr{background:rgba(9,105,218,.04)}
.thread-msg-hdr{padding:10px 14px;border-bottom:1px solid var(--bd);display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:6px;background:var(--bg)}
.thread-msg-meta{display:flex;flex-direction:column;gap:2px;font-size:12.5px;color:var(--tx2)}
.thread-msg-meta b{color:var(--tx)}
.thread-msg-time{font-size:11.5px;color:var(--tx2);white-space:nowrap}
.thread-msg-body{padding:14px 16px;font-size:14px;line-height:1.75;white-space:pre-wrap;word-break:break-word;background:var(--bg)}
.thread-msg-attach{padding:10px 14px;border-top:1px solid var(--bd);display:flex;flex-wrap:wrap;gap:7px;background:var(--bg2)}
.thread-msg-actions{padding:8px 14px;border-top:1px solid var(--bd);display:flex;gap:7px;flex-wrap:wrap;background:var(--bg2)}
.locked-body{display:flex;align-items:center;gap:8px;padding:14px 16px;color:var(--tx2);font-size:13px;font-style:italic;background:var(--bg2)}
.attach-chip{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);font-size:12.5px;text-decoration:none;color:var(--tx)}
.attach-chip:hover{background:var(--bg3);text-decoration:none}
.attach-chip.locked{color:var(--tx2);cursor:default;opacity:.7}
/* ── Password gate ── */
.pass-gate{text-align:center;padding:28px 20px;max-width:360px;margin:0 auto}
/* ── Auth ── */
.auth-wrap{min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:16px;background:var(--bg2)}
.auth-card{width:100%;max-width:360px;background:var(--bg);border:1px solid var(--bd);border-radius:10px;padding:26px 24px}
.auth-logo{text-align:center;font-size:24px;font-weight:800;margin-bottom:4px}
.auth-logo span{color:var(--blue)}
.auth-sub{text-align:center;color:var(--tx2);font-size:13.5px;margin-bottom:20px}
/* ── Admin table ── */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;padding:8px 10px;border-bottom:2px solid var(--bd);font-weight:600;color:var(--tx2);font-size:12px}
.tbl td{padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
/* ── Misc ── */
.addr-box{font-family:monospace;font-size:12px;background:var(--bg2);border:1px solid var(--bd);padding:5px 10px;border-radius:var(--r);word-break:break-all;user-select:all}
.empty{text-align:center;padding:44px 16px;color:var(--tx2)}
.empty-icon{font-size:36px;margin-bottom:10px}
.pager{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:13px;color:var(--tx2)}
.divider{height:1px;background:var(--bd);margin:14px 0}
.flex{display:flex}.gap-8{gap:8px}.gap-6{gap:6px}.items-center{align-items:center}
.mt-8{margin-top:8px}.mt-12{margin-top:12px}.w-full{width:100%}
.text-muted{color:var(--tx2)}.text-sm{font-size:12.5px}.fw-600{font-weight:600}
/* ── Bottom mobile nav ── */
.bottom-nav{display:none;position:fixed;bottom:0;left:0;right:0;height:58px;background:var(--bg);border-top:1px solid var(--bd);z-index:60}
.bottom-nav a{display:flex;flex-direction:column;align-items:center;justify-content:center;flex:1;font-size:10px;color:var(--tx2);text-decoration:none;gap:2px;padding:6px 0;transition:color .1s}
.bottom-nav a .bn-icon{font-size:20px;line-height:1}
.bottom-nav a.active,.bottom-nav a:hover{color:var(--blue);text-decoration:none}
/* ── Responsive ── */
@media(max-width:900px){
  .app{grid-template-columns:1fr}
  .sidebar{position:fixed;left:-240px;top:var(--nav-h);bottom:0;width:240px;z-index:50;overflow-y:auto;transition:left .22s cubic-bezier(.4,0,.2,1)}
  .sidebar.open{left:0;box-shadow:4px 0 24px rgba(0,0,0,.18)}
  .sb-overlay.open{display:block}
  .hamburger{display:flex}
  .bottom-nav{display:flex}
  .main{padding:12px 12px 74px}
}
@media(max-width:500px){
  .mail-from{width:80px}
  .mail-time{display:none}
  .nav-in{padding:0 10px}
  .thread-msg-hdr{flex-direction:column}
  .tbl{font-size:12px}
  .tbl th,.tbl td{padding:6px 6px}
}
@media(min-width:901px){.nav-end .username-label{display:inline}}
</style>
</head>
<body>

<?php if ($isFirstRun): ?>
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><?=h(APP_NAME)?> <span>✦</span></div>
  <div class="auth-sub">Create your admin account</div>
  <?php if($errors):?><div class="alert alert-err"><?=h(implode(' ',$errors))?></div><?php endif?>
  <form method="POST">
    <input type="hidden" name="action" value="setup">
    <div class="form-g"><label class="form-label">Username</label><input class="form-input" type="text" name="username" pattern="[a-z0-9_]{3,30}" placeholder="e.g. admin" required autofocus autocomplete="username"><div class="form-hint">3–30 chars · a-z, 0-9, _</div></div>
    <div class="form-g"><label class="form-label">Password <span class="text-muted">(min 8 chars)</span></label><input class="form-input" type="password" name="password" required minlength="8" autocomplete="new-password"></div>
    <div class="form-g"><label class="form-label">Confirm Password</label><input class="form-input" type="password" name="password2" required autocomplete="new-password"></div>
    <button class="btn btn-primary w-full" type="submit">Create Admin Account</button>
  </form>
</div></div>

<?php elseif($page==='login'&&!isLoggedIn()): ?>
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><?=h(APP_NAME)?> <span>✦</span></div>
  <div class="auth-sub">Sign in to your mailbox</div>
  <?php if($errors):?><div class="alert alert-err"><?=h(implode(' ',$errors))?></div><?php endif?>
  <?php if($info):?><div class="alert alert-ok"><?=h($info)?></div><?php endif?>
  <form method="POST">
    <input type="hidden" name="action" value="login">
    <div class="form-g"><label class="form-label">Username</label><input class="form-input" type="text" name="username" required autofocus autocomplete="username"></div>
    <div class="form-g"><label class="form-label">Password</label><input class="form-input" type="password" name="password" required autocomplete="current-password"></div>
    <button class="btn btn-primary w-full" type="submit">Sign in</button>
  </form>
  <?php if(getSetting('registration')==='open'):?>
  <div style="text-align:center;margin-top:14px;font-size:13px"><a href="<?=h($base.'?page=register')?>">Create an account →</a></div>
  <?php endif?>
</div></div>

<?php elseif($page==='register'&&!isLoggedIn()): ?>
<div class="auth-wrap"><div class="auth-card">
  <div class="auth-logo"><?=h(APP_NAME)?> <span>✦</span></div>
  <div class="auth-sub">Create a new account</div>
  <?php if($errors):?><div class="alert alert-err"><?=h(implode(' ',$errors))?></div><?php endif?>
  <?php if(getSetting('registration')!=='open'):?><div class="alert alert-err">Registration is currently closed.</div><?php else:?>
  <form method="POST">
    <input type="hidden" name="action" value="register">
    <div class="form-g"><label class="form-label">Username <span class="text-muted">(permanent)</span></label><input class="form-input" type="text" name="username" pattern="[a-z0-9_]{3,30}" required autofocus autocomplete="username"><div class="form-hint">3–30 chars · a-z, 0-9, _</div></div>
    <div class="form-g"><label class="form-label">Display Name</label><input class="form-input" type="text" name="display_name" maxlength="100" autocomplete="name"></div>
    <div class="form-g"><label class="form-label">Password</label><input class="form-input" type="password" name="password" required minlength="8" autocomplete="new-password"></div>
    <div class="form-g"><label class="form-label">Confirm Password</label><input class="form-input" type="password" name="password2" required autocomplete="new-password"></div>
    <button class="btn btn-primary w-full" type="submit">Create Account</button>
  </form>
  <?php endif?>
  <div style="text-align:center;margin-top:14px;font-size:13px"><a href="<?=h($base.'?page=login')?>">← Sign in</a></div>
</div></div>

<?php elseif(isLoggedIn()&&$cu): ?>

<nav class="nav">
  <div class="nav-in">
    <button class="hamburger" onclick="toggleSb()" aria-label="Menu">☰</button>
    <a class="nav-logo" href="<?=h($base)?>"><?=h(APP_NAME)?> <span>✦</span></a>
    <div class="nav-end">
      <span class="username-label"><?=h($cu['display_name']?:$cu['username'])?></span>
      <form method="POST" style="display:inline"><input type="hidden" name="action" value="logout"><button class="btn btn-secondary btn-sm">Sign out</button></form>
    </div>
  </div>
</nav>

<div class="sb-overlay" id="soverlay" onclick="toggleSb()"></div>

<div class="app">
  <aside class="sidebar" id="sidebar">
    <div style="padding:10px 14px 8px"><a class="btn btn-primary w-full" href="<?=h($base.'?page=compose')?>">✉️ Compose</a></div>
    <div style="height:6px"></div>
    <div class="sb-head">Mailbox</div>
    <?php foreach($folderIcons as $f=>$icon): $cnt=$counts[$f]??['c'=>0,'u'=>0]; ?>
    <a class="sb-item <?=$page===$f?'active':''?>" href="<?=h($base.'?page='.$f)?>" onclick="closeSb()">
      <?=$icon?> <?=ucfirst($f)?>
      <?php if($cnt['u']>0):?><span class="sb-badge"><?=$cnt['u']?></span><?php endif?>
    </a>
    <?php endforeach?>
    <div class="sb-div"></div>
    <div class="sb-head">Account</div>
    <a class="sb-item <?=$page==='settings'?'active':''?>" href="<?=h($base.'?page=settings')?>" onclick="closeSb()">⚙️ Settings</a>
    <?php if(isAdmin()):?><a class="sb-item <?=$page==='admin'?'active':''?>" href="<?=h($base.'?page=admin')?>" onclick="closeSb()">🔑 Admin</a><?php endif?>
    <div class="sb-div"></div>
    <div style="padding:8px 14px"><div class="addr-box"><?=h(mailAddress($cu))?></div><div class="form-hint" style="margin-top:4px">Your mail address</div></div>
  </aside>

  <main class="main">
  <?php if($errors):?><div class="alert alert-err"><?=h(implode('<br>',$errors))?></div><?php endif?>
  <?php if($info):?><div class="alert alert-ok"><?=h($info)?></div><?php endif?>

  <?php /* ════ MAIL LIST ════ */ if(in_array($page,['inbox','sent','drafts','trash'],true)): ?>
  <div class="page-hdr">
    <div class="page-title"><?=ucfirst($page)?></div>
    <?php if($page==='trash'&&!empty($mails)):?>
    <form method="POST" onsubmit="return confirm('Permanently delete ALL trash?')">
      <input type="hidden" name="action" value="empty_trash">
      <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
      <button class="btn btn-danger btn-sm" type="submit">🗑️ Empty Trash</button>
    </form>
    <?php endif?>
  </div>
  <form method="POST" id="bulk-form">
    <input type="hidden" name="action" value="bulk_action">
    <input type="hidden" name="_csrf"  value="<?=h($csrf_token)?>">
    <input type="hidden" name="_page"  value="<?=h($page)?>">
    <div class="card">
      <!-- Bulk bar -->
      <div class="bulk-bar" id="bulk-bar">
        <span class="bulk-count"><span id="bulk-count">0</span> selected</span>
        <button class="btn btn-secondary btn-sm" type="submit" name="bulk_op" value="mark_read">✓ Mark Read</button>
        <button class="btn btn-secondary btn-sm" type="submit" name="bulk_op" value="mark_unread">● Mark Unread</button>
        <?php if($page==='trash'):?>
        <button class="btn btn-secondary btn-sm" type="submit" name="bulk_op" value="restore">↩ Restore</button>
        <button class="btn btn-danger btn-sm"    type="submit" name="bulk_op" value="delete" onclick="return confirm('Delete selected permanently?')">🗑️ Delete Forever</button>
        <?php else:?>
        <button class="btn btn-secondary btn-sm" type="submit" name="bulk_op" value="trash">🗑️ Move to Trash</button>
        <?php endif?>
      </div>
      <!-- List header -->
      <?php if(!empty($mails)):?>
      <div class="mail-list-hdr">
        <input type="checkbox" id="check-all" onchange="toggleAll(this)" title="Select all" style="width:15px;height:15px;cursor:pointer;accent-color:var(--blue)">
        <span class="text-muted text-sm"><?=$totalCount?> message<?=$totalCount!=1?'s':''?> · <?=$counts[$page]['u']??0?> unread</span>
      </div>
      <?php endif?>
      <?php if(!$mails):?>
        <div class="empty"><div class="empty-icon"><?=$folderIcons[$page]?></div><?=ucfirst($page)?> is empty.</div>
      <?php else: foreach($mails as $m):
          $isDraft=$m['folder']==='drafts';
          $isRead=(bool)$m['is_read'];
          $rowHref=$isDraft?h($base.'?page=compose&draft='.$m['id']):h($base.'?page=view&id='.$m['id']);
          $showAddr=($page==='sent'||$isDraft)?$m['to_addr']:$m['from_addr'];
      ?>
      <div class="mail-row <?=$isRead?'read':'unread'?>">
        <input type="checkbox" name="ids[]" value="<?=$m['id']?>" class="row-check" onchange="updateBulk()">
        <a class="mail-link" href="<?=$rowHref?>">
          <div class="mail-from"><?=h(mb_substr($showAddr,0,28))?></div>
          <div class="mail-subj"><?=h($m['subject']?:'(no subject)')?></div>
          <div class="mail-icons"><?=$m['has_attach']?'📎':''?><?=!$isRead?'<span style="color:var(--blue);font-size:8px">●</span>':''?></div>
          <div class="mail-time"><?=timeEl($m['created_at'])?></div>
        </a>
      </div>
      <?php endforeach; endif?>
    </div>
  </form>
  <?php if($totalCount>PPP):?>
  <div class="pager">
    <?php if($offset>0):?><a class="btn btn-secondary btn-sm" href="<?=h($base.'?page='.$page.'&offset='.max(0,$offset-PPP))?>">← Prev</a><?php endif?>
    <span><?=$offset+1?>–<?=min($offset+PPP,$totalCount)?> of <?=$totalCount?></span>
    <?php if($offset+PPP<$totalCount):?><a class="btn btn-secondary btn-sm" href="<?=h($base.'?page='.$page.'&offset='.($offset+PPP))?>">Next →</a><?php endif?>
  </div>
  <?php endif?>

  <?php /* ════ COMPOSE ════ */ elseif($page==='compose'): ?>
  <div class="page-hdr"><div class="page-title">Compose <?=$draftMail!==null?'<span style="font-size:13px;font-weight:400;color:var(--tx2)">(draft)</span>':''?></div></div>
  <div class="card" style="max-width:720px"><div style="padding:16px">
    <?php if($draftMail):?><div class="alert alert-warn text-sm">📝 Draft loaded. Re-enter the message password to save/send.</div><?php endif?>
    <form method="POST" enctype="multipart/form-data">
      <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
      <input type="hidden" name="reply_to_uid" value="<?=h($composeReplyToUid)?>">
      <input type="hidden" name="thread_uid" value="<?=h($composeThreadUid?:($draftMail?$draftMail['thread_uid']??'':uid()))?>">
      <?php if($draftMail):?><input type="hidden" name="draft_id" value="<?=$draftMail['id']?>"><?php endif?>
      <div class="form-g"><label class="form-label">To</label><input class="form-input" type="text" name="to" value="<?=h($_POST['to']??($draftMail?$draftMail['to_addr']:($_GET['to']??'')))?>" placeholder="user@host/xmail.php (comma-separate)" autocomplete="off"></div>
      <div class="form-g"><label class="form-label">CC <span class="text-muted">(optional)</span></label><input class="form-input" type="text" name="cc" value="<?=h($_POST['cc']??($draftMail?$draftMail['cc_addr']??'':''))?>" placeholder="Carbon copy recipients" autocomplete="off"></div>
      <div class="form-g"><label class="form-label">BCC <span class="text-muted">(optional, hidden from others)</span></label><input class="form-input" type="text" name="bcc" value="<?=h($_POST['bcc']??($draftMail?$draftMail['bcc_addr']??'':''))?>" placeholder="Blind carbon copy recipients" autocomplete="off"></div>
      <div class="form-g"><label class="form-label">Subject</label><input class="form-input" type="text" name="subject" value="<?=h($_POST['subject']??($draftMail?$draftMail['subject']:($_GET['subject']??'')))?>" maxlength="255" placeholder="Subject (stored unencrypted)"></div>
      <div class="form-g"><label class="form-label">Body</label><textarea class="form-input" name="body" rows="10" maxlength="50000" placeholder="Message body (encrypted with message password)…"><?=h($_POST['body']??'')?></textarea></div>
      <div class="divider"></div>
      <div class="form-g">
        <label class="form-label">🔑 Message Password <span class="enc-badge">AES-256-GCM</span></label>
        <input class="form-input" type="password" name="msg_password" value="<?=h($composePrefillPass)?>" minlength="4" autocomplete="new-password" placeholder="Password to encrypt body + attachments">
        <div class="form-hint">⚠️ Encrypts the <b>body and all attachments</b>. Share this password with recipients via a secure channel (e.g. phone, Signal). The server never stores it. You'll need it to re-read this message.</div>
      </div>
      <div class="form-g"><label class="form-label">Attachments <span class="text-muted">(≤ 5 files · max <?=fmtBytes(MAX_ATTACH)?> each · encrypted)</span></label><input class="form-input" type="file" name="attachments[]" multiple accept="image/*,.pdf,.txt,.csv,.zip,.doc,.docx,.xls,.xlsx" style="padding:4px"></div>
      <div class="flex gap-8" style="flex-wrap:wrap">
        <button class="btn btn-primary"   type="submit" name="action" value="send">Send ✈️</button>
        <button class="btn btn-secondary" type="submit" name="action" value="save_draft">Save Draft</button>
        <a class="btn btn-secondary" href="<?=h($base.'?page=inbox')?>">Cancel</a>
      </div>
    </form>
  </div></div>

  <?php /* ════ VIEW / THREAD ════ */ elseif($page==='view'): ?>
  <?php if(!$singleMail): ?>
    <div class="card"><div class="empty"><div class="empty-icon">🔍</div>Message not found.</div></div>
  <?php else:
    $subject = h($singleMail['subject']?:'(no subject)');
    $replyUrl= $base.'?page=compose&reply_to_uid='.urlencode($singleMail['uid'])
             .'&thread_uid='.urlencode($threadUidCurrent)
             .'&to='.urlencode($singleMail['from_addr'])
             .'&subject='.urlencode(preg_replace('/^(Re:\s*)*/i','Re: ',$singleMail['subject']));
  ?>
  <div style="margin-bottom:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
    <a class="btn btn-secondary btn-sm" href="javascript:history.back()">← Back</a>
    <div class="page-title" style="font-size:16px"><?=$subject?></div>
    <span class="enc-badge">🔒 AES-256-GCM</span>
  </div>

  <?php if(!$decrypted): ?>
  <!-- Password gate -->
  <div class="card">
    <div class="pass-gate">
      <div style="font-size:32px;margin-bottom:10px">🔒</div>
      <div class="fw-600" style="margin-bottom:5px;font-size:15px">This thread is encrypted</div>
      <div class="text-muted text-sm" style="margin-bottom:16px">Enter the message password set by the sender to decrypt <?=count($threadMails)?> message<?=count($threadMails)!=1?'s':''?>.</div>
      <?php if(!empty($errors)):?><div class="alert alert-err"><?=h(implode(' ',$errors))?></div><?php endif?>
      <form method="POST">
        <input type="hidden" name="action" value="unlock_thread">
        <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
        <input type="hidden" name="thread_uid" value="<?=h($threadUidCurrent)?>">
        <input type="hidden" name="mail_id" value="<?=$singleMail['id']?>">
        <input class="form-input" type="password" name="msg_password" placeholder="Message password" required autofocus autocomplete="off" style="margin-bottom:10px">
        <button class="btn btn-primary w-full" type="submit">🔓 Decrypt &amp; Read</button>
      </form>
    </div>
    <!-- Show locked thread preview -->
    <?php if(count($threadMails)>1):?>
    <div style="border-top:1px solid var(--bd);padding:10px 14px">
      <div class="text-muted text-sm fw-600" style="margin-bottom:8px">Thread (<?=count($threadMails)?> messages)</div>
      <?php foreach($threadMails as $tm):?>
      <div style="display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--bg3)">
        <span style="font-size:12px;color:var(--tx2);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?=h(mb_substr($tm['from_addr'],0,30))?></span>
        <span class="text-muted text-sm" style="flex:1">🔒 Encrypted</span>
        <span style="font-size:11px;color:var(--tx2)"><?=timeEl($tm['created_at'])?></span>
      </div>
      <?php endforeach?>
    </div>
    <?php endif?>
  </div>

  <?php else: ?>
  <!-- Decrypted thread -->
  <div class="thread-wrap">
  <?php foreach($threadMails as $tm):
      $isFromMe = ($tm['from_addr']===mailAddress($cu));
      $tmIsRead = (bool)$tm['is_read'];
      $tmAttach = $threadAttachments[$tm['uid']]??[];
  ?>
    <div class="thread-msg <?=$tmIsRead?'read':'unread'?> <?=$isFromMe?'outgoing':'incoming'?>">
      <div class="thread-msg-hdr">
        <div class="thread-msg-meta">
          <div><b>From:</b> <?=h($tm['from_addr'])?>  <?=$isFromMe?'<span style="font-size:11px;color:var(--blue)">(you)</span>':''?></div>
          <div><b>To:</b> <?=h($tm['to_addr'])?></div>
          <?php if($tm['cc_addr']):?><div><b>CC:</b> <?=h($tm['cc_addr'])?></div><?php endif?>
        </div>
        <div class="thread-msg-time"><?=timeEl($tm['created_at'])?></div>
      </div>
      <?php if($tm['_ok']??false): ?>
        <div class="thread-msg-body"><?=h($tm['_body']??'')?></div>
      <?php else: ?>
        <div class="locked-body">🔒 Could not decrypt this message with the current password.</div>
      <?php endif?>
      <?php if(!empty($tmAttach)):?>
      <div class="thread-msg-attach">
        <div class="text-muted text-sm fw-600" style="width:100%;margin-bottom:4px">📎 Attachments</div>
        <?php foreach($tmAttach as $a):
            $canDownload = !$a['is_encrypted'] || $decrypted;
        ?>
          <?php if($canDownload):?>
          <a class="attach-chip" href="<?=h($base.'?dl='.$a['id'])?>">📄 <?=h($a['filename'])?> <span class="text-muted">(<?=fmtBytes($a['size'])?>)</span></a>
          <?php else:?>
          <span class="attach-chip locked">🔒 <?=h($a['filename'])?></span>
          <?php endif?>
        <?php endforeach?>
      </div>
      <?php endif?>
      <div class="thread-msg-actions">
        <?php if($tm['folder']==='trash'):?>
          <form method="POST" style="display:inline"><input type="hidden" name="action" value="restore"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="mail_id" value="<?=$tm['id']?>"><button class="btn btn-secondary btn-sm">↩ Restore</button></form>
          <form method="POST" style="display:inline" onsubmit="return confirm('Delete permanently?')"><input type="hidden" name="action" value="delete_perm"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="mail_id" value="<?=$tm['id']?>"><button class="btn btn-danger btn-sm">🗑️ Delete</button></form>
        <?php elseif($tm['folder']!=='sent'):?>
          <form method="POST" style="display:inline"><input type="hidden" name="action" value="move_trash"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="mail_id" value="<?=$tm['id']?>"><input type="hidden" name="_back" value="<?=h($base.'?page='.$tm['folder'])?>"><button class="btn btn-secondary btn-sm">🗑️ Trash</button></form>
        <?php endif?>
      </div>
    </div>
  <?php endforeach?>
  <!-- Reply bar -->
  <div style="padding:4px 0 8px">
    <a class="btn btn-primary" href="<?=h($replyUrl)?>">↩️ Reply to thread</a>
  </div>
  </div>
  <?php endif?>
  <?php endif?>

  <?php /* ════ SETTINGS ════ */ elseif($page==='settings'): ?>
  <div class="page-hdr"><div class="page-title">Settings</div></div>
  <div class="card" style="max-width:500px"><div style="padding:16px">
    <div class="form-g"><label class="form-label">Your Mail Address</label><div class="addr-box"><?=h(mailAddress($cu))?></div><div class="form-hint">Share with others to receive XMail messages.</div></div>
    <div class="form-g"><label class="form-label">Username <span class="text-muted">(permanent)</span></label><input class="form-input" value="<?=h($cu['username'])?>" disabled style="background:var(--bg2)"></div>
  </div>
  <div style="padding:0 16px 16px">
    <form method="POST">
      <input type="hidden" name="action" value="update_settings">
      <input type="hidden" name="_csrf" value="<?=h($csrf_token)?>">
      <div class="form-g"><label class="form-label">Display Name</label><input class="form-input" type="text" name="display_name" value="<?=h($cu['display_name'])?>" maxlength="100"></div>
      <div class="divider"></div>
      <div class="fw-600 text-sm" style="margin-bottom:8px">Change Account Password</div>
      <div class="alert alert-info text-sm">Your <b>account password</b> is for login only. <b>Message passwords</b> are separate and set per-message — changing your account password does not affect encrypted mail.</div>
      <div class="form-g mt-8"><label class="form-label">Current Password</label><input class="form-input" type="password" name="current_password" required autocomplete="current-password"></div>
      <div class="form-g"><label class="form-label">New Password</label><input class="form-input" type="password" name="new_password" minlength="8" autocomplete="new-password"></div>
      <div class="form-g"><label class="form-label">Confirm New Password</label><input class="form-input" type="password" name="confirm_password" autocomplete="new-password"></div>
      <button class="btn btn-primary" type="submit">Save Settings</button>
    </form>
  </div></div>

  <?php /* ════ ADMIN ════ */ elseif($page==='admin'&&isAdmin()): ?>
  <div class="page-hdr"><div class="page-title">Admin Panel</div></div>
  <div class="card" style="max-width:650px">
    <div style="padding:14px 16px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <div><span class="fw-600">Registration:</span> <span style="color:<?=getSetting('registration')==='open'?'var(--green)':'var(--red)'?>"><?=getSetting('registration')==='open'?'✅ Open':'🔒 Closed'?></span></div>
      <form method="POST"><input type="hidden" name="action" value="admin_toggle_reg"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><button class="btn btn-secondary btn-sm"><?=getSetting('registration')==='open'?'Close Registration':'Open Registration'?></button></form>
    </div>
    <div style="padding:14px 16px;overflow-x:auto">
      <div class="fw-600 text-sm" style="margin-bottom:10px">Users (<?=count($allUsers)?>)</div>
      <table class="tbl"><thead><tr><th>Username</th><th>Display Name</th><th>Role</th><th>Joined</th><th></th></tr></thead><tbody>
      <?php foreach($allUsers as $u):?>
        <tr>
          <td><code><?=h($u['username'])?></code></td>
          <td><?=h($u['display_name'])?></td>
          <td><?=$u['is_admin']?'🔑 Admin':'User'?></td>
          <td class="text-muted"><?=date('M j, Y',$u['created_at'])?></td>
          <td><?php if((int)$u['id']!==(int)$cu['id']):?>
            <div class="flex gap-6" style="flex-wrap:wrap">
              <form method="POST"><input type="hidden" name="action" value="admin_toggle_admin"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="user_id" value="<?=$u['id']?>"><button class="btn btn-secondary btn-sm"><?=$u['is_admin']?'Revoke':'Make Admin'?></button></form>
              <form method="POST" onsubmit="return confirm('Delete user and all their mail?')"><input type="hidden" name="action" value="admin_delete_user"><input type="hidden" name="_csrf" value="<?=h($csrf_token)?>"><input type="hidden" name="user_id" value="<?=$u['id']?>"><button class="btn btn-danger btn-sm">Delete</button></form>
            </div>
          <?php else:?><span class="text-muted text-sm">(you)</span><?php endif?></td>
        </tr>
      <?php endforeach?></tbody></table>
    </div>
  </div>
  <?php endif?>
  </main>
</div>

<!-- Mobile bottom nav -->
<nav class="bottom-nav">
  <a href="<?=h($base.'?page=inbox')?>" class="<?=$page==='inbox'?'active':''?>"><span class="bn-icon">📥</span>Inbox<?php if(($counts['inbox']['u']??0)>0):?> <sup style="color:var(--blue);font-weight:700"><?=$counts['inbox']['u']?></sup><?php endif?></a>
  <a href="<?=h($base.'?page=compose')?>" class="<?=$page==='compose'?'active':''?>"><span class="bn-icon">✉️</span>Compose</a>
  <a href="<?=h($base.'?page=sent')?>" class="<?=$page==='sent'?'active':''?>"><span class="bn-icon">📤</span>Sent</a>
  <a href="<?=h($base.'?page=drafts')?>" class="<?=$page==='drafts'?'active':''?>"><span class="bn-icon">📝</span>Drafts</a>
  <a href="<?=h($base.'?page=settings')?>" class="<?=in_array($page,['settings','admin'],true)?'active':''?>"><span class="bn-icon">⚙️</span>More</a>
</nav>

<?php endif?>
<script>
function toggleSb(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('soverlay').classList.toggle('open');}
function closeSb(){document.getElementById('sidebar').classList.remove('open');document.getElementById('soverlay').classList.remove('open');}
function updateBulk(){var n=document.querySelectorAll('.row-check:checked').length;var bar=document.getElementById('bulk-bar');if(bar){bar.className='bulk-bar'+(n>0?' active':'');var el=document.getElementById('bulk-count');if(el)el.textContent=n;}}
function toggleAll(cb){document.querySelectorAll('.row-check').forEach(function(c){c.checked=cb.checked;});updateBulk();}
// Close sidebar on outside resize
window.addEventListener('resize',function(){if(window.innerWidth>900)closeSb();});
</script>
</body>
</html>
<?php
declare(strict_types=1);

const APP_NAME = 'File Port';
const SESSION_NAME = 'sfm_session';
const MAX_TEXT_EDIT_BYTES = 2_000_000;

$ROOT_DIR = '/storage-files';
$PASSWORD = getenv('SFM_PASSWORD') ?: 'yourstrongpassword';

// Generate keys as below
// openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
// openssl rsa -pubout -in private.pem -out public.pem

// RSA Public Key for UPLOAD - exposed to JS (Safe for browser)
$UP_PUBLIC_KEY_PEM = <<<'EOD'
-----BEGIN PUBLIC KEY-----
PASTE_YOUR_RSA_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
EOD;

// RSA Private Key for UPLOAD - kept strictly on the server
$UP_PRIVATE_KEY_PEM = <<<'EOD'
-----BEGIN PRIVATE KEY-----
PASTE_YOUR_RSA_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----
EOD;

// RSA Public Key for DOWNLOAD - exposed to JS (Safe for browser)
// REPLACE WITH YOUR OWN RSA PUBLIC KEY (2048-bit or higher)
$DOWN_PUBLIC_KEY_PEM = <<<'EOD'
-----BEGIN PUBLIC KEY-----
PASTE_YOUR_RSA_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
EOD;

// RSA Private Key for DOWNLOAD - kept strictly on the server
// REPLACE WITH YOUR OWN RSA PRIVATE KEY (matching the public key above)
$DOWN_PRIVATE_KEY_PEM = <<<'EOD'
-----BEGIN PRIVATE KEY-----
PASTE_YOUR_RSA_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----
EOD;

$ALLOW_UPLOAD = true;
$ALLOW_DELETE = true;
$ALLOW_EDIT = true;
$ALLOW_CREATE = true;
$MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
$BLOCKED_EXTENSIONS = ['php', 'phtml', 'phar', 'cgi', 'pl', 'py', 'sh', 'asp', 'aspx', 'jsp'];
$HIDDEN_EXTENSIONS = ['php', 'phtml', 'phar', 'cgi', 'pl', 'py', 'sh', 'asp', 'aspx', 'jsp'];

date_default_timezone_set('Europe/London');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}
session_name(SESSION_NAME);
session_start();

function respond(int $status, array $payload): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['csrf'];
}
function require_csrf(): void {
    $sent = (string)($_POST['csrf'] ?? '');
    if ($sent === '' || !hash_equals(csrf_token(), $sent)) {
        respond(403, ['ok' => false, 'error' => 'Security token expired. Refresh the page and try again.']);
    }
}
function root_path(string $root): string {
    $real = realpath($root);
    if ($real === false || !is_dir($real)) {
        throw new RuntimeException('ROOT_DIR does not exist or is not a directory.');
    }
    return rtrim($real, DIRECTORY_SEPARATOR);
}
function safe_path(string $root, string $relative, bool $mustExist = true): string {
    $relative = str_replace('\\', '/', $relative);
    if (str_contains($relative, "\0") || str_starts_with($relative, '/') || preg_match('/^[A-Za-z]:/', $relative)) {
        throw new RuntimeException('Invalid path.');
    }
    $parts = ($relative === '') ? [] : explode('/', $relative);
    foreach ($parts as $part) {
        if ($part === '' || $part === '.' || $part === '..') {
            throw new RuntimeException('Invalid path.');
        }
    }
    $candidate = $root . ($relative === '' ? '' : DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative));
    if ($mustExist) {
        if (is_link($candidate)) {
            throw new RuntimeException('Symbolic links cannot be opened or modified.');
        }
        $real = realpath($candidate);
        if ($real === false) {
            throw new RuntimeException('File or folder not found.');
        }
        $prefix = $root . DIRECTORY_SEPARATOR;
        if ($real !== $root && !str_starts_with($real, $prefix)) {
            throw new RuntimeException('Path is outside the managed directory.');
        }
        return $real;
    }
    $parent = realpath(dirname($candidate));
    if ($parent === false || ($parent !== $root && !str_starts_with($parent, $root . DIRECTORY_SEPARATOR))) {
        throw new RuntimeException('Invalid destination folder.');
    }
    return $parent . DIRECTORY_SEPARATOR . basename($candidate);
}
function valid_name(string $name): string {
    $name = trim($name);
    if ($name === '' || $name === '.' || $name === '..' || str_contains($name, '/') ||
        str_contains($name, '\\') || str_contains($name, "\0") || preg_match('/[\x00-\x1F]/', $name)) {
        throw new RuntimeException('Enter a valid name without slashes or control characters.');
    }
    return $name;
}
function ensure_not_root(string $root, string $path): void {
    if ($path === $root) {
        throw new RuntimeException('This operation is not allowed on the root folder.');
    }
}
function is_blocked(string $name, array $extensions): bool {
    return in_array(strtolower(pathinfo($name, PATHINFO_EXTENSION)), $extensions, true);
}
function remove_tree(string $path, string $root): void {
    ensure_not_root($root, $path);
    if (is_link($path)) {
        if (!unlink($path)) throw new RuntimeException('Could not remove symbolic link.');
        return;
    }
    if (is_dir($path)) {
        $items = scandir($path);
        if ($items === false) throw new RuntimeException('Could not read folder.');
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            remove_tree($path . DIRECTORY_SEPARATOR . $item, $root);
        }
        if (!rmdir($path)) throw new RuntimeException('Could not remove folder.');
    } else {
        if (!unlink($path)) throw new RuntimeException('Could not remove file.');
    }
}
function json_request(): bool {
    return isset($_GET['api']) || isset($_POST['api']);
}
function authenticated(): bool {
    return !empty($_SESSION['sfm_authenticated']);
}

try {
    $ROOT = root_path($ROOT_DIR);
} catch (Throwable $e) {
    http_response_code(500);
    echo '<!doctype html><meta charset="utf-8"><h1>Configuration error</h1><p>' . h($e->getMessage()) . '</p>';
    exit;
}
if ($PASSWORD === '' || $PASSWORD === 'CHANGE-ME') {
    http_response_code(503);
    echo '<!doctype html><meta charset="utf-8"><h1>Setup required</h1><p>Set a strong password before using this tool.</p>';
    exit;
}
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], (bool)$p['secure'], (bool)$p['httponly']);
    }
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}
if (!authenticated()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_password'])) {
        if (hash_equals($PASSWORD, (string)$_POST['login_password'])) {
            session_regenerate_id(true);
            $_SESSION['sfm_authenticated'] = true;
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        }
        $loginError = 'Incorrect password.';
    }
    ?><!doctype html>
    <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · <?= h(APP_NAME) ?></title>
    <style>body{font:16px system-ui;background:#f3f5f9;display:grid;place-items:center;min-height:100vh;margin:0;color:#172033}.card{background:white;padding:2rem;border-radius:16px;box-shadow:0 10px 40px #18243b18;width:min(360px,calc(100% - 64px))}input,button{font:inherit;padding:.8rem;border-radius:8px;border:1px solid #ccd3df;width:100%;box-sizing:border-box}button{margin-top:1rem;background:#2459d3;color:white;border:0;cursor:pointer}.error{color:#b42318}</style></head>
    <body><form class="card" method="post"><h1><?= h(APP_NAME) ?></h1><p>Sign in to manage files.</p><?php if (!empty($loginError)): ?><p class="error"><?= h($loginError) ?></p><?php endif; ?><label for="pw">Password</label><input id="pw" type="password" name="login_password" required autofocus autocomplete="current-password"><button type="submit">Sign in</button></form></body></html><?php
    exit;
}
if (empty($_SESSION['last_activity']) || time() - (int)$_SESSION['last_activity'] > 1800) {
    if (isset($_SESSION['last_activity'])) {
        $_SESSION = [];
        session_destroy();
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }
}
$_SESSION['last_activity'] = time();

if (json_request()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') require_csrf();
    $action = (string)($_GET['api'] ?? $_POST['api'] ?? '');
    $relative = (string)($_GET['path'] ?? $_POST['path'] ?? '');
    try {
        $path = safe_path($ROOT, $relative, true);
        switch ($action) {
            case 'list':
                if (!is_dir($path)) respond(400, ['ok'=>false, 'error'=>'Not a folder.']);
                $items = scandir($path);
                if ($items === false) respond(403, ['ok'=>false, 'error'=>'Folder cannot be read.']);
                $results = [];
                foreach ($items as $name) {
                    if ($name === '.' || $name === '..' || $name === basename(__FILE__) || is_blocked($name, $HIDDEN_EXTENSIONS)) continue;
                    $full = $path . DIRECTORY_SEPARATOR . $name;
                    $isLink = is_link($full);
                    $real = realpath($full);
                    if ($isLink && ($real === false || ($real !== $ROOT && !str_starts_with($real, $ROOT . DIRECTORY_SEPARATOR)))) continue;
                    $isDir = is_dir($full);
                    $stat = @lstat($full);
                    if ($stat === false) continue;
                    $results[] = [
                        'name'=>$name,
                        'path'=>ltrim(($relative === '' ? '' : trim($relative, '/') . '/') . $name, '/'),
                        'dir'=>$isDir,
                        'link'=>$isLink,
                        'size'=>$isDir ? null : (int)$stat['size'],
                        'mtime'=>(int)$stat['mtime'],
                        'readable'=>is_readable($full),
                        'writable'=>is_writable($full),
                    ];
                }
                respond(200, ['ok'=>true, 'path'=>$relative, 'writable'=>is_writable($path), 'items'=>$results]);
            case 'mkdir':
                if (!$ALLOW_CREATE) throw new RuntimeException('Folder creation is disabled.');
                if (!is_dir($path) || !is_writable($path)) throw new RuntimeException('Folder is not writable.');
                $name = valid_name((string)($_POST['name'] ?? ''));
                $target = safe_path($ROOT, trim($relative . '/' . $name, '/'), false);
                if (!mkdir($target, 0750)) throw new RuntimeException('Could not create folder.');
                respond(200, ['ok'=>true]);
            case 'newfile':
                if (!$ALLOW_CREATE) throw new RuntimeException('File creation is disabled.');
                if (!is_dir($path) || !is_writable($path)) throw new RuntimeException('Folder is not writable.');
                $name = valid_name((string)($_POST['name'] ?? ''));
                if (is_blocked($name, $BLOCKED_EXTENSIONS)) throw new RuntimeException('That file extension is blocked.');
                $target = safe_path($ROOT, trim($relative . '/' . $name, '/'), false);
                if (file_put_contents($target, '', LOCK_EX) === false) throw new RuntimeException('Could not create file.');
                respond(200, ['ok'=>true]);
            case 'rename':
                if (!is_writable(dirname($path))) throw new RuntimeException('Parent folder is not writable.');
                ensure_not_root($ROOT, $path);
                $name = valid_name((string)($_POST['name'] ?? ''));
                if (is_blocked($name, $BLOCKED_EXTENSIONS)) throw new RuntimeException('That file extension is blocked.');
                $target = safe_path($ROOT, trim(dirname($relative) === '.' ? $name : dirname($relative) . '/' . $name, '/'), false);
                if (!rename($path, $target)) throw new RuntimeException('Rename failed.');
                respond(200, ['ok'=>true]);
            case 'delete':
                if (!$ALLOW_DELETE) throw new RuntimeException('Deletion is disabled.');
                ensure_not_root($ROOT, $path);
                if (!is_writable(dirname($path))) throw new RuntimeException('Parent folder is not writable.');
                remove_tree($path, $ROOT);
                respond(200, ['ok'=>true]);
            case 'upload':
                if (!$ALLOW_UPLOAD) throw new RuntimeException('Uploads are disabled.');
                if (!is_dir($path) || !is_writable($path)) throw new RuntimeException('Destination folder is not writable.');
                if (!isset($_FILES['file_data'])) throw new RuntimeException('No file uploaded.');
                $file = $_FILES['file_data'];
                if ($file['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('Upload failed (error code ' . (int)$file['error'] . ').');
                if ((int)$file['size'] > $MAX_UPLOAD_BYTES) throw new RuntimeException('Upload exceeds max size limit.');
                
                $originalName = (string)$file['name'];
                $saveName = $originalName;
                $content = file_get_contents($file['tmp_name']);

                if (str_ends_with(strtolower($originalName), '.fm')) {
                    // Binary layout:
                    // 2 bytes: Key Length (N)
                    // N bytes: RSA-Encrypted AES Key
                    // 12 bytes: AES-GCM IV
                    // 16 bytes: AES-GCM Tag
                    // Remaining bytes: Ciphertext
                    if (strlen($content) < 30) {
                        throw new RuntimeException('Corrupted encrypted payload size.');
                    }
                    
                    $keyLength = unpack('n', substr($content, 0, 2))[1];
                    $encryptedKey = substr($content, 2, $keyLength);
                    $iv = substr($content, 2 + $keyLength, 12);
                    $tag = substr($content, 2 + $keyLength + 12, 16);
                    $ciphertext = substr($content, 2 + $keyLength + 12 + 16);

                    $privKey = openssl_pkey_get_private($UP_PRIVATE_KEY_PEM);
                    if ($privKey === false) {
                        throw new RuntimeException('Server RSA private key error.');
                    }

                    $aesKey = '';
                    $success = openssl_private_decrypt($encryptedKey, $aesKey, $privKey, OPENSSL_PKCS1_OAEP_PADDING);
                    if (!$success) {
                        throw new RuntimeException('Asymmetric RSA decryption failed.');
                    }

                    $decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);
                    if ($decrypted === false) {
                        throw new RuntimeException('Symmetric payload decryption failed.');
                    }

                    $content = $decrypted;
                    $saveName = substr($originalName, 0, -3); // Strip '.fm'
                }
                
                $name = valid_name(basename(str_replace('\\', '/', $saveName)));
                if (is_blocked($name, $BLOCKED_EXTENSIONS)) throw new RuntimeException('Upload blocked for file type: ' . $name);
                $target = safe_path($ROOT, trim($relative . '/' . $name, '/'), false);
                
                if (file_put_contents($target, $content, LOCK_EX) === false) {
                    throw new RuntimeException('Could not save file.');
                }
                respond(200, ['ok'=>true, 'uploaded'=>$name]);
            case 'read':
                if (is_blocked(basename($path), $HIDDEN_EXTENSIONS)) throw new RuntimeException('This file type is hidden.');
                if (!str_ends_with(strtolower(basename($path)), '.txt')) throw new RuntimeException('Only .txt files can be edited.');
                if (is_dir($path) || !is_file($path) || !is_readable($path)) throw new RuntimeException('File cannot be read.');
                if (filesize($path) > MAX_TEXT_EDIT_BYTES) throw new RuntimeException('Files larger than 2 MB cannot be opened.');
                $content = file_get_contents($path);
                if ($content === false || str_contains($content, "\0")) throw new RuntimeException('Not a text file.');
                respond(200, ['ok'=>true, 'content'=>$content, 'name'=>basename($path)]);
            case 'save':
                if (!$ALLOW_EDIT) throw new RuntimeException('Editing is disabled.');
                if (!str_ends_with(strtolower(basename($path)), '.txt')) throw new RuntimeException('Only .txt files can be edited.');
                if (is_dir($path) || !is_file($path) || !is_writable($path)) throw new RuntimeException('File is not writable.');
                $content = (string)($_POST['content'] ?? '');
                if (strlen($content) > MAX_TEXT_EDIT_BYTES) throw new RuntimeException('Editor content exceeds limit.');
                if (file_put_contents($path, $content, LOCK_EX) === false) throw new RuntimeException('Could not save file.');
                respond(200, ['ok'=>true]);
            case 'download':
                if (is_blocked(basename($path), $HIDDEN_EXTENSIONS)) throw new RuntimeException('This file type is hidden.');
                if (is_dir($path) || !is_file($path) || !is_readable($path)) throw new RuntimeException('File cannot be downloaded.');
                $name = basename($path);
                $secure = isset($_GET['secure']) && $_GET['secure'] === '1';
                
                if ($secure) {
                    // Secure download with asymmetric encryption
                    $fileSize = filesize($path);
                    
                    // Warn for very large files (> 512MB) - may cause memory issues
                    if ($fileSize > 512 * 1024 * 1024) {
                        error_log("WARNING: Secure download requested for large file ($fileSize bytes). May cause memory issues.");
                    }
                    
                    $content = file_get_contents($path);
                    if ($content === false) throw new RuntimeException('Could not read file.');
                    
                    error_log("Secure download: Original size = " . strlen($content) . " bytes");
                    
                    // Generate random AES key
                    $aesKey = random_bytes(32);
                    $iv = random_bytes(12);
                    
                    // Encrypt file content with AES-256-GCM
                    $tag = '';
                    $ciphertext = openssl_encrypt($content, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);
                    if ($ciphertext === false) throw new RuntimeException('Payload encryption failed.');
                    
                    error_log("Secure download: Encrypted size = " . strlen($ciphertext) . " bytes");
                    
                    // Encrypt AES key with RSA public key (for download)
                    $pubKey = openssl_pkey_get_public($DOWN_PUBLIC_KEY_PEM);
                    if ($pubKey === false) throw new RuntimeException('Server RSA public key error.');
                    
                    $encryptedKey = '';
                    $success = openssl_public_encrypt($aesKey, $encryptedKey, $pubKey, OPENSSL_PKCS1_OAEP_PADDING);
                    if (!$success) throw new RuntimeException('Key encryption failed.');
                    
                    // Build binary stream: [2 bytes key length][N bytes encrypted key][12 bytes IV][16 bytes Tag][Ciphertext]
                    $keyLen = strlen($encryptedKey);
                    $binaryPayload = pack('n', $keyLen) . $encryptedKey . $iv . $tag . $ciphertext;
                    
                    error_log("Secure download: Final payload size = " . strlen($binaryPayload) . " bytes, filename = " . $name . ".fm");
                    
                    header('Content-Type: application/octet-stream');
                    header('X-Content-Type-Options: nosniff');
                    header('Content-Length: ' . strlen($binaryPayload));
                    header("Content-Disposition: attachment; filename*=UTF-8''" . rawurlencode($name . '.fm'));
                    echo $binaryPayload;
                    exit;
                } else {
                    // Standard download
                    header('Content-Type: application/octet-stream');
                    header('X-Content-Type-Options: nosniff');
                    header('Content-Length: ' . filesize($path));
                    header("Content-Disposition: attachment; filename*=UTF-8''" . rawurlencode($name));
                    readfile($path);
                    exit;
                }
            default:
                respond(400, ['ok'=>false, 'error'=>'Unknown action.']);
        }
    } catch (Throwable $e) {
        respond(400, ['ok'=>false, 'error'=>$e->getMessage()]);
    }
}
$csrf = csrf_token();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h(APP_NAME) ?></title>
<style>
:root{color-scheme:light;--bg:#f4f6fa;--panel:#fff;--text:#1b2434;--muted:#697586;--line:#e2e7ef;--accent:#2859c5;--danger:#b42318}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{background:var(--panel);border-bottom:1px solid var(--line);padding:16px clamp(16px,4vw,44px);display:flex;align-items:center;justify-content:space-between;gap:16px}
h1{font-size:20px;margin:0}header a{color:var(--muted);text-decoration:none}.wrap{max-width:1200px;margin:28px auto;padding:0 18px}
.toolbar,.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:0 3px 12px #17203308}
.toolbar{padding:14px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:14px}.toolbar input[type=text]{flex:1;min-width:180px}
input,button,textarea{font:inherit;border:1px solid #cbd3df;border-radius:8px;padding:9px 11px}button{cursor:pointer;background:#fff;color:var(--text)}button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}button.danger{color:var(--danger)}button:disabled{opacity:.5;cursor:not-allowed}
.panel{overflow:hidden}.crumb{padding:13px 16px;border-bottom:1px solid var(--line);color:var(--muted);overflow-wrap:anywhere}.crumb button{border:0;padding:0;color:var(--accent);background:none}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--line)}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);background:#fafbfc;cursor:pointer;user-select:none}th:hover{color:var(--text)}tbody tr:hover{background:#f8faff}td.name{overflow-wrap:anywhere}.name button{border:0;background:none;color:var(--accent);padding:0;text-align:left}.meta{color:var(--muted);font-size:12px}.actions{display:flex;gap:6px;flex-wrap:wrap}.actions button{font-size:12px;padding:5px 8px}.empty{text-align:center;color:var(--muted);padding:38px}.status{min-height:24px;margin:10px 2px;color:var(--muted)}.status.error{color:var(--danger)}.hidden{display:none!important}
#file_drop_target{border:2px dashed #b7c4d8;padding:12px 16px;text-align:center;border-radius:10px;color:var(--muted);background:#fafbfc}
#file_drop_target.drag_over{border-color:var(--accent);background:#eef4ff}
#upload_progress{margin:14px 0}#upload_progress>div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.progress_track{flex:1;height:6px;background:#e2e7ef;border-radius:3px;overflow:hidden}.progress{height:100%;background:var(--accent);width:0;transition:width .1s}
.modal{position:fixed;inset:0;background:#10182888;display:grid;place-items:center;padding:18px;z-index:10}.dialog{background:white;border-radius:14px;width:min(900px,100%);max-height:90vh;display:flex;flex-direction:column;overflow:hidden}.dialog header{padding:14px 18px}.dialog .body{padding:16px;overflow:auto}.dialog textarea{width:100%;min-height:55vh;font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;resize:vertical}.dialog footer{padding:12px 16px;border-top:1px solid var(--line);display:flex;justify-content:flex-end;gap:8px}.small{font-size:12px;color:var(--muted)}@media(max-width:680px){.hide-mobile{display:none}th,td{padding:10px 8px}.toolbar>*{width:100%}.toolbar input[type=text]{min-width:0}.actions button{padding:6px}.wrap{margin-top:16px}}
</style>
</head>
<body>
<header><h1><?= h(APP_NAME) ?></h1><a href="?logout=1">Sign out</a></header>
<main class="wrap">
  <section class="toolbar">
    <input id="search" type="text" placeholder="Search this folder..." aria-label="Search files">
    <?php if ($ALLOW_CREATE): ?><button id="newFolder">New folder</button><button id="newFile">New text file</button><?php endif; ?>
    <label style="display:flex;align-items:center;gap:6px;white-space:nowrap">
      <input type="checkbox" id="secureDownload" style="width:auto">
      <span>Secure Download</span>
    </label>
    <?php if ($ALLOW_UPLOAD): ?>
      <div id="file_drop_target">
        Drop files here or <input type="file" id="upload" multiple style="display:inline-block">
      </div>
    <?php endif; ?>
  </section>
  <div id="upload_progress"></div>
  <div id="download_progress"></div>
  <section class="panel">
    <div class="crumb" id="crumb">Loading...</div>
    <div style="overflow-x:auto"><table><thead><tr><th data-sort="name">Name ↕</th><th class="hide-mobile" data-sort="size">Size ↕</th><th class="hide-mobile" data-sort="mtime">Modified ↕</th><th>Actions</th></tr></thead><tbody id="rows"><tr><td colspan="4" class="empty">Loading...</td></tr></tbody></table></div>
  </section>
  <div id="status" class="status" role="status" aria-live="polite"></div>
</main>
<div id="editor" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="editorTitle"><section class="dialog"><header><strong id="editorTitle">Edit file</strong><button id="closeEditor" aria-label="Close editor">✕</button></header><div class="body"><textarea id="content" spellcheck="false"></textarea><p class="small">Text files up to 2 MB. Save carefully; changes overwrite the existing file.</p></div><footer><button id="cancelEdit">Cancel</button><button class="primary" id="saveEdit">Save changes</button></footer></section></div>
<script>
'use strict';
const CSRF = <?= json_encode($csrf) ?>;
const MAX_UPLOAD_BYTES = <?= (int)$MAX_UPLOAD_BYTES ?>;
const UP_RSA_PUBLIC_KEY_PEM = <?= json_encode($UP_PUBLIC_KEY_PEM) ?>;
const DOWN_RSA_PRIVATE_KEY_PEM = <?= json_encode($DOWN_PRIVATE_KEY_PEM) ?>;
const rows = document.getElementById('rows');
const statusBox = document.getElementById('status');
let currentPath = '';
let editingPath = '';
let allItems = [];
let sortField = 'name';
let sortAsc = true;

function prettySize(bytes) {
  if (bytes === null || bytes === undefined) return '—';
  const units = ['B','KB','MB','GB','TB']; let n = bytes, i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n >= 10 ? 0 : 1) : n) + ' ' + units[i];
}
function notify(message, error=false) {
  statusBox.textContent = message || '';
  statusBox.className = 'status' + (error ? ' error' : '');
}
async function api(action, path=currentPath, data={}) {
  const body = new FormData();
  body.append('api', action); body.append('path', path); body.append('csrf', CSRF);
  Object.entries(data).forEach(([key,value]) => body.append(key, value));
  const response = await fetch(location.pathname, {method:'POST', body, credentials:'same-origin'});
  let result;
  try { result = await response.json(); } catch { throw new Error('Unexpected server response.'); }
  if (!response.ok || !result.ok) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
}
async function load(path=currentPath) {
  try {
    const response = await fetch(location.pathname + '?api=list&path=' + encodeURIComponent(path), {credentials:'same-origin'});
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || 'Could not load folder.');
    currentPath = result.path || '';
    allItems = result.items;
    render();
    renderCrumb();
    notify(`${allItems.length} item${allItems.length===1?'':'s'}`);
  } catch (e) { notify(e.message, true); rows.innerHTML = `<tr><td colspan="4" class="empty">${esc(e.message)}</td></tr>`; }
}
function esc(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function renderCrumb() {
  const crumb = document.getElementById('crumb');
  crumb.replaceChildren();
  const home = document.createElement('button'); home.textContent='Home'; home.onclick=()=>{location.hash='';load('');}; crumb.append(home);
  let path = '';
  currentPath.split('/').filter(Boolean).forEach(part => {
    path = path ? path + '/' + part : part;
    crumb.append(document.createTextNode(' / '));
    const button = document.createElement('button'); button.textContent=part; const target=path;
    button.onclick=()=>{location.hash=target;load(target);}; crumb.append(button);
  });
}
function render() {
  const query = document.getElementById('search').value.trim().toLocaleLowerCase();
  let items = allItems.filter(item => item.name.toLocaleLowerCase().includes(query));
  
  items.sort((a, b) => {
    if (a.dir !== b.dir) return a.dir ? -1 : 1;
    let valA = a[sortField];
    let valB = b[sortField];
    if (valA === null) valA = '';
    if (valB === null) valB = '';
    let cmp = 0;
    if (typeof valA === 'string') {
      cmp = valA.localeCompare(valB, undefined, {numeric: true, sensitivity: 'base'});
    } else {
      cmp = valA - valB;
    }
    return sortAsc ? cmp : -cmp;
  });

  rows.replaceChildren();
  if (!items.length) {
    const tr=document.createElement('tr'); tr.innerHTML=`<td colspan="4" class="empty">${query?'No matching files.':'This folder is empty.'}</td>`; rows.append(tr); return;
  }
  items.forEach(item => {
    const tr=document.createElement('tr');
    const name=document.createElement('td'); name.className='name';
    const open=document.createElement('button'); open.textContent=(item.dir?'📁 ':'📄 ')+item.name; open.title=item.name;
    open.onclick=()=> item.dir ? (location.hash=item.path,load(item.path)) : openFile(item);
    name.append(open);
    const size=document.createElement('td'); size.className='hide-mobile'; size.textContent=prettySize(item.size);
    const modified=document.createElement('td'); modified.className='hide-mobile'; modified.textContent=new Date(item.mtime*1000).toLocaleString();
    const actions=document.createElement('td'); actions.className='actions';
    if (!item.dir) {
      const download=document.createElement('button'); download.textContent='Download'; download.onclick=()=>downloadFile(item); actions.append(download);
      if (item.name.toLowerCase().endsWith('.txt')) {
        const edit=document.createElement('button'); edit.textContent='Edit'; edit.onclick=()=>openEditor(item.path); actions.append(edit);
      }
    }
    const rename=document.createElement('button'); rename.textContent='Rename'; rename.onclick=()=>renameItem(item); actions.append(rename);
    const del=document.createElement('button'); del.textContent='Delete'; del.className='danger'; del.onclick=()=>deleteItem(item); actions.append(del);
    tr.append(name,size,modified,actions); rows.append(tr);
  });
}
document.querySelectorAll('th[data-sort]').forEach(th => {
  th.onclick = () => {
    const field = th.getAttribute('data-sort');
    if (sortField === field) { sortAsc = !sortAsc; } else { sortField = field; sortAsc = true; }
    render();
  };
});
async function renameItem(item) {
  const name=prompt('New name:', item.name); if (name===null || name.trim()===item.name) return;
  try { await api('rename',item.path,{name:name.trim()}); notify('Renamed successfully.'); await load(); }
  catch(e){notify(e.message,true);}
}
async function deleteItem(item) {
  if (!confirm(`Permanently delete ${item.dir?'folder and all its contents':'file'} "${item.name}"?`)) return;
  try { await api('delete',item.path); notify('Deleted.'); await load(); }
  catch(e){notify(e.message,true);}
}
async function openFile(item) {
  const ext=item.name.split('.').pop().toLowerCase();
  if (ext !== 'txt') {
    notify('Preview/Editing is restricted to .txt files.');
    return;
  }
  await openEditor(item.path);
}
async function openEditor(path) {
  try {
    const result=await api('read',path);
    editingPath=path; document.getElementById('editorTitle').textContent='Edit: '+result.name;
    document.getElementById('content').value=result.content;
    document.getElementById('editor').classList.remove('hidden');
    document.getElementById('content').focus();
  } catch(e){notify(e.message,true);}
}
function closeEditor(){document.getElementById('editor').classList.add('hidden');editingPath='';}
document.getElementById('closeEditor').onclick=closeEditor;
document.getElementById('cancelEdit').onclick=closeEditor;
document.getElementById('saveEdit').onclick=async()=>{
  try {await api('save',editingPath,{content:document.getElementById('content').value});closeEditor();notify('File saved.');await load();}
  catch(e){notify(e.message,true);}
};
document.getElementById('newFolder')?.addEventListener('click',async()=>{
  const name=prompt('Folder name:'); if(name===null||!name.trim())return;
  try{await api('mkdir',currentPath,{name:name.trim()});notify('Folder created.');await load();}
  catch(e){notify(e.message,true);}
});
document.getElementById('newFile')?.addEventListener('click',async()=>{
  const name=prompt('New text file name:'); if(name===null||!name.trim())return;
  try{await api('newfile',currentPath,{name:name.trim()});notify('File created.');await load();}
  catch(e){notify(e.message,true);}
});
document.getElementById('search').addEventListener('input',render);

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----\w+ PUBLIC KEY-----/g, '').replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function importRsaPublicKey(pem) {
  const binaryDer = pemToArrayBuffer(pem);
  return window.crypto.subtle.importKey(
    'spki',
    binaryDer,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
}

async function hybridEncrypt(fileBuffer, rsaPublicKeyPem) {
  // 1. Generate random AES-256 key for symmetric payload encryption
  const aesRawKey = window.crypto.getRandomValues(new Uint8Array(32));
  const aesKey = await window.crypto.subtle.importKey(
    'raw', aesRawKey, { name: 'AES-GCM' }, false, ['encrypt']
  );

  // 2. Encrypt AES raw key with RSA Public Key
  const rsaKey = await importRsaPublicKey(rsaPublicKeyPem);
  const encryptedAesKey = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    rsaKey,
    aesRawKey
  );

  // 3. Encrypt payload with AES key
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedFile = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    fileBuffer
  );

  // Separate tag (last 16 bytes) and ciphertext
  const ciphertext = encryptedFile.slice(0, encryptedFile.byteLength - 16);
  const tag = encryptedFile.slice(encryptedFile.byteLength - 16);

  // 4. Build binary stream
  // [2 bytes key length][N bytes encrypted key][12 bytes IV][16 bytes Tag][Ciphertext]
  const keyLen = encryptedAesKey.byteLength;
  const keyLenBuffer = new Uint8Array([(keyLen >> 8) & 0xff, keyLen & 0xff]);

  const combined = new Uint8Array(
    2 + keyLen + iv.length + tag.byteLength + ciphertext.byteLength
  );

  let offset = 0;
  combined.set(keyLenBuffer, offset); offset += 2;
  combined.set(new Uint8Array(encryptedAesKey), offset); offset += keyLen;
  combined.set(iv, offset); offset += iv.length;
  combined.set(new Uint8Array(tag), offset); offset += tag.byteLength;
  combined.set(new Uint8Array(ciphertext), offset);

  return combined;
}

function pemToPrivateKeyArrayBuffer(pem) {
  const b64 = pem.replace(/-----\w+ PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function importRsaPrivateKey(pem) {
  const binaryDer = pemToPrivateKeyArrayBuffer(pem);
  return window.crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['decrypt']
  );
}

async function hybridDecrypt(encryptedBuffer, rsaPrivateKeyPem) {
  const data = new Uint8Array(encryptedBuffer);
  
  // Parse binary layout: [2 bytes key length][N bytes encrypted key][12 bytes IV][16 bytes Tag][Ciphertext]
  const keyLength = (data[0] << 8) | data[1];
  const encryptedAesKey = data.slice(2, 2 + keyLength);
  const iv = data.slice(2 + keyLength, 2 + keyLength + 12);
  const tag = data.slice(2 + keyLength + 12, 2 + keyLength + 12 + 16);
  const ciphertext = data.slice(2 + keyLength + 12 + 16);

  // 1. Decrypt AES key with RSA Private Key
  const rsaKey = await importRsaPrivateKey(rsaPrivateKeyPem);
  const aesRawKey = await window.crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    rsaKey,
    encryptedAesKey
  );

  // 2. Import AES key
  const aesKey = await window.crypto.subtle.importKey(
    'raw', aesRawKey, { name: 'AES-GCM' }, false, ['decrypt']
  );

  // 3. Combine ciphertext and tag for decryption
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  // 4. Decrypt payload
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    combined
  );

  return decrypted;
}

async function downloadFile(item) {
  const secureDownload = document.getElementById('secureDownload').checked;
  
  if (!secureDownload) {
    // Standard download
    location.href = location.pathname + '?api=download&path=' + encodeURIComponent(item.path);
    return;
  }

  // Warn for large files in secure mode
  if (item.size && item.size > 512 * 1024 * 1024) {
    if (!confirm('This file is ' + prettySize(item.size) + '. Secure download of large files may fail due to browser memory limits. Continue?')) {
      return;
    }
  }

  // Secure download with decryption and progress
  const progressContainer = document.getElementById('download_progress');
  const row = document.createElement('div');
  const nameSpan = document.createElement('span');
  nameSpan.textContent = item.name;
  const track = document.createElement('div');
  track.className = 'progress_track';
  const fill = document.createElement('div');
  fill.className = 'progress';
  track.appendChild(fill);
  const statusSpan = document.createElement('span');
  statusSpan.textContent = 'Starting...';
  row.appendChild(nameSpan);
  row.appendChild(track);
  row.appendChild(statusSpan);
  progressContainer.appendChild(row);

  try {
    notify('Downloading and decrypting ' + item.name + '...');
    
    console.log('[Secure Download] Starting download for:', item.name);
    
    const response = await fetch(
      location.pathname + '?api=download&path=' + encodeURIComponent(item.path) + '&secure=1',
      { credentials: 'same-origin' }
    );
    
    if (!response.ok) {
      throw new Error('Download failed: ' + response.statusText);
    }

    const contentLength = response.headers.get('Content-Length');
    const total = contentLength ? parseInt(contentLength, 10) : 0;
    
    console.log('[Secure Download] Content-Length:', total, 'bytes');
    
    const reader = response.body.getReader();
    const chunks = [];
    let loaded = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      chunks.push(value);
      loaded += value.length;
      
      if (total > 0) {
        const percent = Math.round((loaded / total) * 100);
        fill.style.width = percent + '%';
        statusSpan.textContent = prettySize(loaded) + ' / ' + prettySize(total);
      } else {
        statusSpan.textContent = prettySize(loaded);
      }
    }

    console.log('[Secure Download] Downloaded', loaded, 'bytes (encrypted)');
    statusSpan.textContent = 'Decrypting...';
    fill.style.width = '100%';

    // Combine chunks into single buffer
    const encryptedBuffer = new Uint8Array(loaded);
    let position = 0;
    for (const chunk of chunks) {
      encryptedBuffer.set(chunk, position);
      position += chunk.length;
    }

    console.log('[Secure Download] Starting decryption...');
    const decryptedBuffer = await hybridDecrypt(encryptedBuffer.buffer, DOWN_RSA_PRIVATE_KEY_PEM);
    console.log('[Secure Download] Decrypted size:', decryptedBuffer.byteLength, 'bytes');

    // Trigger download of decrypted file
    const blob = new Blob([decryptedBuffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = item.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    statusSpan.textContent = 'Complete';
    setTimeout(() => row.remove(), 2000);
    notify('Successfully downloaded and decrypted ' + item.name);
    console.log('[Secure Download] Complete:', item.name);
  } catch (err) {
    console.error('[Secure Download] Error:', err);
    statusSpan.textContent = 'Failed';
    statusSpan.style.color = 'var(--danger)';
    notify('Download/decryption failed: ' + err.message, true);
    setTimeout(() => row.remove(), 5000);
  }
}

function uploadFile(file) {
  if (file.size > MAX_UPLOAD_BYTES) {
    notify('File ' + file.name + ' exceeds max upload size.', true);
    return;
  }
  const row = document.createElement('div');
  const nameSpan = document.createElement('span');
  nameSpan.textContent = file.name;
  const track = document.createElement('div');
  track.className = 'progress_track';
  const fill = document.createElement('div');
  fill.className = 'progress';
  track.appendChild(fill);
  const sizeSpan = document.createElement('span');
  sizeSpan.textContent = prettySize(file.size);
  row.appendChild(nameSpan);
  row.appendChild(track);
  row.appendChild(sizeSpan);
  document.getElementById('upload_progress').appendChild(row);

  file.arrayBuffer().then(async (buffer) => {
    try {
      const encryptedBytes = await hybridEncrypt(buffer, UP_RSA_PUBLIC_KEY_PEM);
      const maskedFileName = file.name + '.fm';
      const blob = new Blob([encryptedBytes], { type: 'application/octet-stream' });

      const fd = new FormData();
      fd.append('api', 'upload');
      fd.append('path', currentPath);
      fd.append('csrf', CSRF);
      fd.append('file_data', blob, maskedFileName);

      const xhr = new XMLHttpRequest();
      xhr.open('POST', location.pathname, true);
      xhr.withCredentials = true;
      xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
          fill.style.width = Math.round((e.loaded / e.total) * 100) + '%';
        }
      };
      xhr.onload = function() {
        row.remove();
        try {
          const res = JSON.parse(xhr.responseText);
          if (xhr.status !== 200 || !res.ok) {
            notify(res.error || 'Upload failed.', true);
            return;
          }
        } catch {
          notify('Upload failed: Invalid server response.', true);
          return;
        }
        load();
      };
      xhr.onerror = function() {
        row.remove();
        notify('Network error during upload for ' + file.name, true);
      };
      xhr.send(fd);
    } catch (err) {
      row.remove();
      notify('Encryption error: ' + err.message, true);
    }
  }).catch(() => {
    row.remove();
    notify('Failed to read local file.', true);
  });
}

document.getElementById('upload')?.addEventListener('change', function(e) {
  e.preventDefault();
  Array.from(this.files).forEach(uploadFile);
  this.value = '';
});
const drop = document.getElementById('file_drop_target');
if (drop) {
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag_over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag_over'));
  drop.addEventListener('drop', e => {
    e.preventDefault();
    drop.classList.remove('drag_over');
    Array.from(e.dataTransfer.files).forEach(uploadFile);
  });
}
window.addEventListener('hashchange',()=>load(decodeURIComponent(location.hash.slice(1))));
load(decodeURIComponent(location.hash.slice(1)));
</script>
</body></html>

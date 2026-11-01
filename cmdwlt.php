<?php
/**
 * cmdwlt - Universal Command & Snippet Manager
 * Supports: Linux, Windows, macOS, Payloads, Code Snippets
 * Security: CSRF, XSS, SQLi protection, bcrypt auth, rate limiting
 *
 * @author  Vineet Pratap Singh <psvineet.me>
 * @version 1.0.0
 */

define('DB_PATH', __DIR__ . '/vault.db');
define('APP_VERSION', '1.0.0');
define('SESSION_LIFETIME', 3600);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900);

session_set_cookie_params([
    'lifetime' => SESSION_LIFETIME,
    'path'     => '/',
    'secure'   => false,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

// ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
if (!isset($_GET['api'])) {
    // Block all search engine indexing
    header("X-Robots-Tag: noindex, nofollow, noarchive, nosnippet");
    // Security hardening
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: no-referrer");
    header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");
}

// ─── DB INIT ──────────────────────────────────────────────────────────────────
function get_db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec("PRAGMA journal_mode=WAL;");
    $pdo->exec("PRAGMA foreign_keys=ON;");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            ip         TEXT NOT NULL,
            ts         INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS commands (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title       TEXT NOT NULL,
            os          TEXT NOT NULL DEFAULT 'linux',
            type        TEXT NOT NULL DEFAULT 'command',
            description TEXT,
            created_at  INTEGER DEFAULT (strftime('%s','now')),
            updated_at  INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS steps (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id INTEGER NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
            step_order INTEGER NOT NULL,
            code       TEXT NOT NULL,
            note       TEXT
        );
        CREATE TABLE IF NOT EXISTS tags (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS command_tags (
            command_id INTEGER NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
            tag_id     INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY (command_id, tag_id)
        );
        CREATE INDEX IF NOT EXISTS idx_commands_user ON commands(user_id);
        CREATE INDEX IF NOT EXISTS idx_steps_cmd    ON steps(command_id, step_order);
        CREATE INDEX IF NOT EXISTS idx_cmd_tags     ON command_tags(command_id);
    ");
    // migrate: add pinned column if not present
    $cols = array_column($pdo->query("PRAGMA table_info(commands)")->fetchAll(), 'name');
    if (!in_array('pinned', $cols)) {
        $pdo->exec("ALTER TABLE commands ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0");
    }
    return $pdo;
}

// ─── SECURITY HELPERS ─────────────────────────────────────────────────────────
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function csrf_check(): void {
    $tok = $_POST['_csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', $tok)) {
        http_response_code(403); die(json_encode(['error' => 'CSRF mismatch']));
    }
}

function is_rate_limited(string $username): bool {
    $db  = get_db();
    $ip  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $cut = time() - LOCKOUT_TIME;
    $st  = $db->prepare("SELECT COUNT(*) FROM login_attempts WHERE (username=? OR ip=?) AND ts>?");
    $st->execute([$username, $ip, $cut]);
    return (int)$st->fetchColumn() >= MAX_LOGIN_ATTEMPTS;
}
function record_attempt(string $username): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    get_db()->prepare("INSERT INTO login_attempts (username,ip) VALUES (?,?)")->execute([$username,$ip]);
}

function authed(): bool {
    if (empty($_SESSION['uid']) || empty($_SESSION['ua'])) return false;
    if ($_SESSION['ua'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) return false;
    if (time() - ($_SESSION['last_active'] ?? 0) > SESSION_LIFETIME) {
        session_destroy(); return false;
    }
    $_SESSION['last_active'] = time();
    return true;
}
function require_auth(): void { if (!authed()) { http_response_code(401); die(json_encode(['error'=>'Unauthorized'])); } }

function setup_needed(): bool {
    $st = get_db()->query("SELECT COUNT(*) FROM users");
    return (int)$st->fetchColumn() === 0;
}

function captcha_refresh(): void {
    $a = rand(1, 12); $b = rand(1, 12);
    $_SESSION['captcha_a'] = $a;
    $_SESSION['captcha_b'] = $b;
    $_SESSION['captcha_ans'] = $a + $b;
}

function captcha_question(): string {
    if (empty($_SESSION['captcha_ans'])) captcha_refresh();
    return $_SESSION['captcha_a'] . ' + ' . $_SESSION['captcha_b'];
}

function captcha_check(string $answer): bool {
    $ok = isset($_SESSION['captcha_ans']) && (int)$answer === (int)$_SESSION['captcha_ans'];
    captcha_refresh(); // always refresh after attempt
    return $ok;
}

// ─── API ROUTER ───────────────────────────────────────────────────────────────
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    $action = $_GET['api'];

    // Public
    if ($action === 'setup_needed') { echo json_encode(['needed' => setup_needed()]); exit; }

    if ($action === 'register') {
        csrf_check();
        if (!setup_needed()) { echo json_encode(['error' => 'Already registered']); exit; }
        $u = trim($_POST['username'] ?? '');
        $p = $_POST['password'] ?? '';
        if (strlen($u) < 3 || strlen($p) < 8) { echo json_encode(['error' => 'Username ≥3 chars, password ≥8 chars']); exit; }
        $hash = password_hash($p, PASSWORD_BCRYPT, ['cost' => 12]);
        try {
            get_db()->prepare("INSERT INTO users (username,password) VALUES (?,?)")->execute([$u,$hash]);
            echo json_encode(['ok' => true]); 
        } catch (Exception $e) { echo json_encode(['error' => 'Username taken']); }
        exit;
    }

    if ($action === 'captcha') {
        echo json_encode(['q' => captcha_question()]); exit;
    }

    if ($action === 'login') {
        csrf_check();
        $u = trim($_POST['username'] ?? '');
        $p = $_POST['password'] ?? '';
        $cap = trim($_POST['captcha'] ?? '');
        if (!captcha_check($cap)) {
            echo json_encode(['error' => 'Wrong answer to verification question.', 'captcha_refresh' => true]);
            exit;
        }
        if (is_rate_limited($u)) { echo json_encode(['error' => "Too many attempts. Wait 15 min."]); exit; }
        $st = get_db()->prepare("SELECT id,password FROM users WHERE username=?");
        $st->execute([$u]);
        $row = $st->fetch();
        if ($row && password_verify($p, $row['password'])) {
            session_regenerate_id(true);
            $_SESSION['uid']         = $row['id'];
            $_SESSION['uname']       = $u;
            $_SESSION['ua']          = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $_SESSION['last_active'] = time();
            echo json_encode(['ok' => true, 'username' => $u]);
        } else {
            record_attempt($u);
            echo json_encode(['error' => 'Invalid credentials']);
        }
        exit;
    }

    if ($action === 'logout') {
        session_destroy();
        echo json_encode(['ok' => true]); exit;
    }

    // Protected
    require_auth();
    $uid = (int)$_SESSION['uid'];

    // ── LIST ──
    if ($action === 'list') {
        $where  = "c.user_id = ?";
        $params = [$uid];
        if (!empty($_GET['q'])) {
            $where  .= " AND (c.title LIKE ? OR c.description LIKE ?)";
            $q = '%' . $_GET['q'] . '%';
            $params[] = $q; $params[] = $q;
        }
        if (!empty($_GET['os'])) { $where .= " AND c.os=?"; $params[] = $_GET['os']; }
        if (!empty($_GET['type'])) { $where .= " AND c.type=?"; $params[] = $_GET['type']; }
        if (!empty($_GET['tag'])) {
            $where .= " AND EXISTS (SELECT 1 FROM command_tags ct JOIN tags t ON ct.tag_id=t.id WHERE ct.command_id=c.id AND t.name=?)";
            $params[] = $_GET['tag'];
        }
        $st = get_db()->prepare("
            SELECT c.id, c.title, c.os, c.type, c.description, c.created_at, c.updated_at, c.pinned,
                   GROUP_CONCAT(DISTINCT t.name) AS tags,
                   COUNT(DISTINCT s.id) AS step_count
            FROM commands c
            LEFT JOIN command_tags ct ON ct.command_id=c.id
            LEFT JOIN tags t ON t.id=ct.tag_id
            LEFT JOIN steps s ON s.command_id=c.id
            WHERE $where GROUP BY c.id ORDER BY c.pinned DESC, c.updated_at DESC
        ");
        $st->execute($params);
        echo json_encode($st->fetchAll()); exit;
    }

    // ── GET SINGLE ──
    if ($action === 'get') {
        $id = (int)($_GET['id'] ?? 0);
        $st = get_db()->prepare("SELECT * FROM commands WHERE id=? AND user_id=?");
        $st->execute([$id, $uid]);
        $cmd = $st->fetch();
        if (!$cmd) { echo json_encode(['error'=>'Not found']); exit; }
        $st2 = get_db()->prepare("SELECT * FROM steps WHERE command_id=? ORDER BY step_order");
        $st2->execute([$id]);
        $cmd['steps'] = $st2->fetchAll();
        $st3 = get_db()->prepare("SELECT t.name FROM tags t JOIN command_tags ct ON ct.tag_id=t.id WHERE ct.command_id=?");
        $st3->execute([$id]);
        $cmd['tags'] = array_column($st3->fetchAll(), 'name');
        echo json_encode($cmd); exit;
    }

    // ── SAVE (create/update) ──
    if ($action === 'save') {
        csrf_check();
        $data  = json_decode(file_get_contents('php://input'), true);
        $id    = (int)($data['id'] ?? 0);
        $title = trim($data['title'] ?? '');
        $os    = $data['os'] ?? 'linux';
        $type  = $data['type'] ?? 'command';
        $desc  = trim($data['description'] ?? '');
        $steps = $data['steps'] ?? [];
        $tags  = $data['tags'] ?? [];

        $valid_os   = ['linux','windows','macos','android','payload','snippet','other'];
        $valid_type = ['command','chain','payload','snippet','oneliner','other'];
        if (!$title) { echo json_encode(['error'=>'Title required']); exit; }
        if (!in_array($os, $valid_os)) { echo json_encode(['error'=>'Invalid OS']); exit; }
        if (!in_array($type, $valid_type)) { echo json_encode(['error'=>'Invalid type']); exit; }

        $db = get_db();
        $db->beginTransaction();
        try {
            if ($id) {
                $st = $db->prepare("SELECT id FROM commands WHERE id=? AND user_id=?");
                $st->execute([$id,$uid]);
                if (!$st->fetch()) throw new Exception('Not found');
                $db->prepare("UPDATE commands SET title=?,os=?,type=?,description=?,updated_at=strftime('%s','now') WHERE id=?")
                   ->execute([$title,$os,$type,$desc,$id]);
                $db->prepare("DELETE FROM steps WHERE command_id=?")->execute([$id]);
                $db->prepare("DELETE FROM command_tags WHERE command_id=?")->execute([$id]);
            } else {
                $db->prepare("INSERT INTO commands (user_id,title,os,type,description) VALUES (?,?,?,?,?)")
                   ->execute([$uid,$title,$os,$type,$desc]);
                $id = (int)$db->lastInsertId();
            }
            foreach ($steps as $i => $step) {
                $code = trim($step['code'] ?? '');
                $note = trim($step['note'] ?? '');
                if ($code === '') continue;
                $db->prepare("INSERT INTO steps (command_id,step_order,code,note) VALUES (?,?,?,?)")
                   ->execute([$id, $i+1, $code, $note]);
            }
            foreach ($tags as $tag) {
                $tag = strtolower(trim(preg_replace('/[^a-zA-Z0-9_\-]/','',$tag)));
                if (!$tag) continue;
                $db->prepare("INSERT OR IGNORE INTO tags (name) VALUES (?)")->execute([$tag]);
                $tst = $db->prepare("SELECT id FROM tags WHERE name=?");
                $tst->execute([$tag]);
                $tid = $tst->fetchColumn();
                $db->prepare("INSERT OR IGNORE INTO command_tags (command_id,tag_id) VALUES (?,?)")->execute([$id,$tid]);
            }
            $db->commit();
            echo json_encode(['ok'=>true,'id'=>$id]);
        } catch (Exception $e) {
            $db->rollBack();
            echo json_encode(['error'=>$e->getMessage()]);
        }
        exit;
    }

    // ── DELETE ──
    if ($action === 'delete') {
        csrf_check();
        $data = json_decode(file_get_contents('php://input'), true);
        $id   = (int)($data['id'] ?? 0);
        $st   = get_db()->prepare("DELETE FROM commands WHERE id=? AND user_id=?");
        $st->execute([$id,$uid]);
        echo json_encode(['ok'=> $st->rowCount() > 0]); exit;
    }

    // ── ALL TAGS ──
    if ($action === 'tags') {
        $st = get_db()->prepare("
            SELECT t.name, COUNT(ct.command_id) AS cnt
            FROM tags t JOIN command_tags ct ON ct.tag_id=t.id
            JOIN commands c ON c.id=ct.command_id
            WHERE c.user_id=?
            GROUP BY t.id ORDER BY cnt DESC LIMIT 50
        ");
        $st->execute([$uid]);
        echo json_encode($st->fetchAll()); exit;
    }

    // ── STATS ──
    if ($action === 'stats') {
        $db = get_db();
        $total = $db->prepare("SELECT COUNT(*) FROM commands WHERE user_id=?"); $total->execute([$uid]);
        $byos  = $db->prepare("SELECT os, COUNT(*) as cnt FROM commands WHERE user_id=? GROUP BY os"); $byos->execute([$uid]);
        $bytype= $db->prepare("SELECT type, COUNT(*) as cnt FROM commands WHERE user_id=? GROUP BY type"); $bytype->execute([$uid]);
        echo json_encode([
            'total'  => (int)$total->fetchColumn(),
            'by_os'  => $byos->fetchAll(),
            'by_type'=> $bytype->fetchAll(),
        ]); exit;
    }

    // ── PIN TOGGLE ──
    if ($action === 'pin') {
        csrf_check();
        $data = json_decode(file_get_contents('php://input'), true);
        $id   = (int)($data['id'] ?? 0);
        $st   = get_db()->prepare("UPDATE commands SET pinned=((pinned+1)%2) WHERE id=? AND user_id=?");
        $st->execute([$id, $uid]);
        $pinned = (int)get_db()->prepare("SELECT pinned FROM commands WHERE id=?")->execute([$id]) ? get_db()->prepare("SELECT pinned FROM commands WHERE id=?")->execute([$id]) : 0;
        $p2 = get_db()->prepare("SELECT pinned FROM commands WHERE id=?"); $p2->execute([$id]);
        echo json_encode(['ok'=>true,'pinned'=>(int)$p2->fetchColumn()]); exit;
    }

    // ── DUPLICATE ──
    if ($action === 'duplicate') {
        csrf_check();
        $data = json_decode(file_get_contents('php://input'), true);
        $id   = (int)($data['id'] ?? 0);
        $db   = get_db();
        $st   = $db->prepare("SELECT * FROM commands WHERE id=? AND user_id=?");
        $st->execute([$id, $uid]);
        $cmd  = $st->fetch();
        if (!$cmd) { echo json_encode(['error'=>'Not found']); exit; }
        $db->beginTransaction();
        try {
            $db->prepare("INSERT INTO commands (user_id,title,os,type,description) VALUES (?,?,?,?,?)")
               ->execute([$uid, $cmd['title'].' (copy)', $cmd['os'], $cmd['type'], $cmd['description']]);
            $newId = (int)$db->lastInsertId();
            $steps = $db->prepare("SELECT * FROM steps WHERE command_id=? ORDER BY step_order");
            $steps->execute([$id]);
            foreach ($steps->fetchAll() as $s) {
                $db->prepare("INSERT INTO steps (command_id,step_order,code,note) VALUES (?,?,?,?)")
                   ->execute([$newId, $s['step_order'], $s['code'], $s['note']]);
            }
            $tags = $db->prepare("SELECT tag_id FROM command_tags WHERE command_id=?");
            $tags->execute([$id]);
            foreach ($tags->fetchAll() as $t) {
                $db->prepare("INSERT OR IGNORE INTO command_tags (command_id,tag_id) VALUES (?,?)")
                   ->execute([$newId, $t['tag_id']]);
            }
            $db->commit();
            echo json_encode(['ok'=>true,'id'=>$newId]);
        } catch (Exception $e) { $db->rollBack(); echo json_encode(['error'=>$e->getMessage()]); }
        exit;
    }

    // ── EXPORT ──
    if ($action === 'export') {
        $db  = get_db();
        $st  = $db->prepare("
            SELECT c.*, GROUP_CONCAT(DISTINCT t.name) AS tags
            FROM commands c
            LEFT JOIN command_tags ct ON ct.command_id=c.id
            LEFT JOIN tags t ON t.id=ct.tag_id
            WHERE c.user_id=? GROUP BY c.id ORDER BY c.id
        ");
        $st->execute([$uid]);
        $cmds = $st->fetchAll();
        foreach ($cmds as &$cmd) {
            $s2 = $db->prepare("SELECT step_order,code,note FROM steps WHERE command_id=? ORDER BY step_order");
            $s2->execute([$cmd['id']]);
            $cmd['steps'] = $s2->fetchAll();
            $cmd['tags']  = array_filter(explode(',', $cmd['tags'] ?? ''));
            unset($cmd['user_id']);
        }
        header('Content-Disposition: attachment; filename="cmdwlt-export-'.date('Ymd').'.json"');
        echo json_encode(['version'=>1,'exported_at'=>date('c'),'commands'=>$cmds], JSON_PRETTY_PRINT);
        exit;
    }

    // ── IMPORT ──
    if ($action === 'import') {
        csrf_check();
        $raw  = file_get_contents('php://input');
        $data = json_decode($raw, true);
        if (!isset($data['commands']) || !is_array($data['commands'])) {
            echo json_encode(['error'=>'Invalid import file']); exit;
        }
        $db      = get_db();
        $valid_os   = ['linux','windows','macos','android','payload','snippet','other'];
        $valid_type = ['command','chain','payload','snippet','oneliner','other'];
        $imported = 0; $skipped = 0;
        $db->beginTransaction();
        try {
            foreach ($data['commands'] as $cmd) {
                $title = trim($cmd['title'] ?? '');
                $os    = in_array($cmd['os'] ?? '', $valid_os)   ? $cmd['os']   : 'other';
                $type  = in_array($cmd['type'] ?? '', $valid_type)? $cmd['type'] : 'other';
                $desc  = trim($cmd['description'] ?? '');
                $steps = $cmd['steps'] ?? [];
                $tags  = $cmd['tags']  ?? [];
                if (!$title || empty($steps)) { $skipped++; continue; }
                $db->prepare("INSERT INTO commands (user_id,title,os,type,description) VALUES (?,?,?,?,?)")
                   ->execute([$uid,$title,$os,$type,$desc]);
                $newId = (int)$db->lastInsertId();
                foreach ($steps as $i => $step) {
                    $code = trim($step['code'] ?? '');
                    if (!$code) continue;
                    $db->prepare("INSERT INTO steps (command_id,step_order,code,note) VALUES (?,?,?,?)")
                       ->execute([$newId, $i+1, $code, trim($step['note'] ?? '')]);
                }
                foreach ($tags as $tag) {
                    $tag = strtolower(trim(preg_replace('/[^a-zA-Z0-9_\-]/','',$tag)));
                    if (!$tag) continue;
                    $db->prepare("INSERT OR IGNORE INTO tags (name) VALUES (?)")->execute([$tag]);
                    $tst = $db->prepare("SELECT id FROM tags WHERE name=?"); $tst->execute([$tag]);
                    $tid = $tst->fetchColumn();
                    $db->prepare("INSERT OR IGNORE INTO command_tags (command_id,tag_id) VALUES (?,?)")->execute([$newId,$tid]);
                }
                $imported++;
            }
            $db->commit();
            echo json_encode(['ok'=>true,'imported'=>$imported,'skipped'=>$skipped]);
        } catch (Exception $e) { $db->rollBack(); echo json_encode(['error'=>$e->getMessage()]); }
        exit;
    }

    echo json_encode(['error'=>'Unknown action']); exit;
}
// ─── HTML SHELL ───────────────────────────────────────────────────────────────
$csrf = csrf_token();
$already_authed = authed();
$uname_display = h($_SESSION['uname'] ?? '');
$captcha_q = captcha_question();
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<meta name="googlebot" content="noindex, nofollow">
<title>cmdwlt</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' fill='%230a0a0a'/><text x='4' y='22' font-family='monospace' font-size='18' fill='%2322c55e'>$_</text></svg>">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  /* psvineet.me palette — pure black, Inter/system-sans, green accent */
  --bg:       #0a0a0a;
  --bg1:      #111111;
  --bg2:      #161616;
  --bg3:      #1c1c1c;
  --border:   #1f1f1f;
  --border2:  #2a2a2a;
  --accent:   #22c55e;
  --accent2:  #4ade80;
  --accent-dim:#166534;
  --red:      #ef4444;
  --yellow:   #eab308;
  --text:     #f1f5f9;
  --text2:    #94a3b8;
  --text3:    #475569;
  --text4:    #334155;
  --linux:    #22c55e; --linux-bg: #052e16;
  --windows:  #60a5fa; --windows-bg:#0c1a2e;
  --macos:    #a78bfa; --macos-bg: #1a0a2e;
  --android:  #84cc16; --android-bg:#1a2e05;
  --payload:  #ef4444; --payload-bg:#2e0505;
  --snippet:  #eab308; --snippet-bg:#2e2005;
  --other:    #475569; --other-bg:  #111;
}
html, body {
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter','Segoe UI','SF Pro Display',-apple-system,BlinkMacSystemFont,sans-serif;
  font-size: 13px;
  line-height: 1.6;
}
/* code areas keep monospace */
pre, code, textarea, .code-wrap pre, .step-ed textarea, .fg input, .fg textarea, .fg select,
.tfield input, .tb-search input { font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace; }

/* scrollbar */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-dim); }

/* ── AUTH SCREEN ── */
#auth-screen {
  display: flex; align-items: center; justify-content: center;
  min-height: 100vh; background: var(--bg);
  padding: 20px;
  background-image: repeating-linear-gradient(
    0deg, transparent, transparent 2px,
    rgba(255,255,255,.012) 2px, rgba(255,255,255,.012) 4px
  );
}
.auth-box { width: 100%; max-width: 420px; }

/* top status bar */
.auth-statusbar {
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 14px; background: var(--bg1);
  border: 1px solid var(--border); border-bottom: none;
  font-size: 10px; color: var(--text3); letter-spacing: .06em;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
}
.auth-statusbar .sb-left { display: flex; align-items: center; gap: 12px; }
.auth-statusbar .sb-right { display: flex; align-items: center; gap: 10px; color: var(--text4); }
.auth-statusbar .sb-right span { color: var(--accent-dim); }
.auth-statusbar .sb-dot {
  display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: var(--accent); margin-right: 7px;
  box-shadow: 0 0 8px var(--accent), 0 0 16px rgba(34,197,94,.3);
  animation: pulse-dot 2s infinite;
  flex-shrink: 0;
}
.auth-statusbar .sb-locked { color: var(--red); letter-spacing: .08em; }
@keyframes pulse-dot {
  0%,100% { opacity: 1; box-shadow: 0 0 8px var(--accent), 0 0 16px rgba(34,197,94,.3); }
  50% { opacity: .4; box-shadow: 0 0 4px var(--accent); }
}

.auth-banner {
  border: 1px solid var(--border);
  border-top: none; border-bottom: none;
  padding: 20px 20px 14px;
  background: var(--bg1);
  position: relative; overflow: hidden;
}
/* animated top accent line */
.auth-banner::before {
  content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background: linear-gradient(90deg, transparent 0%, var(--accent) 30%, var(--accent2) 60%, transparent 100%);
  animation: scan-line 3s ease-in-out infinite alternate;
}
@keyframes scan-line {
  0%   { opacity:.6; background-position: 0% 0%; }
  100% { opacity:1; background-position: 100% 0%; }
}
/* grid bg */
.auth-banner::after {
  content:''; position:absolute; inset:0; pointer-events:none;
  background-image:
    linear-gradient(rgba(34,197,94,.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(34,197,94,.04) 1px, transparent 1px);
  background-size: 24px 24px;
}
.auth-banner pre {
  color: #2a5c40;
  font-size: 9.5px; line-height: 1.2;
  white-space: pre; margin-bottom: 14px; overflow: hidden;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
  text-shadow: 0 0 12px rgba(34,197,94,.4);
  position: relative; z-index: 1;
}
.auth-banner .title-line {
  color: var(--accent); font-size: 13px; font-weight: 700;
  letter-spacing: .08em; font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
  position: relative; z-index: 1;
  text-shadow: 0 0 20px rgba(34,197,94,.5);
}
.auth-banner .title-line .tl-slash { color: var(--text4); font-weight: 400; }
.auth-banner .title-line .tl-author { color: var(--accent2); }
.auth-banner .sub-line {
  color: var(--text4); font-size: 10px; margin-top: 4px;
  letter-spacing: .04em; position: relative; z-index: 1;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
}
/* password toggle */
.pass-wrap { position: relative; }
.pass-wrap input { padding-right: 42px; }
.pass-toggle {
  position: absolute; right: 0; top: 0; bottom: 0; width: 38px;
  background: transparent; border: none; border-left: 1px solid var(--border);
  color: var(--text4); cursor: pointer; font-size: 11px;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
  transition: color .15s, background .15s;
}
.pass-toggle:hover { color: var(--accent); background: rgba(34,197,94,.06); }

.auth-form-box {
  border: 1px solid var(--border); border-top: none;
  background: var(--bg1); padding: 20px 24px 24px;
}

/* bottom hint bar */
.auth-hintbar {
  display: flex; justify-content: space-between;
  padding: 5px 14px; background: var(--bg);
  border: 1px solid var(--border); border-top: none;
  font-size: 10px; color: var(--text4); letter-spacing: .04em;
}

.auth-setup-badge {
  font-size: 11px; color: var(--accent2); border: 1px solid var(--accent-dim);
  background: rgba(34,197,94,.04); padding: 6px 10px; margin-bottom: 16px;
  letter-spacing: .03em;
}

.tfield { margin-bottom: 14px; }
.tfield label {
  display: flex; align-items: center; gap: 5px;
  color: var(--text4); font-size: 10px; margin-bottom: 5px;
  text-transform: uppercase; letter-spacing: .09em;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
}
.tfield label .prompt { color: var(--accent-dim); }
.tfield label .prompt-at { color: var(--accent); }
.tfield input {
  width: 100%; background: var(--bg); border: 1px solid var(--border2);
  padding: 9px 12px; color: var(--text);
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
  font-size: 13px; outline: none; transition: border-color .15s, box-shadow .15s;
}
.tfield input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 1px rgba(34,197,94,.12), inset 0 0 12px rgba(34,197,94,.03);
}
.tfield input::placeholder { color: var(--text4); }

/* captcha row */
.captcha-row {
  display: flex; gap: 8px; align-items: flex-start; margin-bottom: 14px;
}
.captcha-q {
  flex: 0 0 auto; background: var(--bg); border: 1px solid var(--border2);
  padding: 9px 14px; color: var(--accent); font-size: 13px;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
  letter-spacing: .04em; user-select: none; white-space: nowrap;
}
.captcha-row .tfield { flex: 1; margin-bottom: 0; }
.captcha-label {
  font-size: 10px; color: var(--text4); letter-spacing: .09em;
  text-transform: uppercase; margin-bottom: 5px; display: block;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
}

.tbtn {
  display: inline-flex; padding: 9px 20px;
  background: transparent; border: 1px solid var(--accent);
  color: var(--accent); font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
  font-size: 12px; cursor: pointer; text-align: left; letter-spacing: .06em;
  transition: background .15s, color .15s, box-shadow .15s;
  align-items: center; gap: 8px;
}
/* full-width only in modal footer */
.modal-footer .tbtn { width: auto; }
.tbtn::before { content: '▶'; font-size: 8px; opacity: .6; }
.tbtn:hover { background: var(--accent); color: #000; box-shadow: 0 0 16px rgba(34,197,94,.2); }
.tbtn:hover::before { opacity: 1; }
.tbtn-danger { border-color: var(--red); color: var(--red); }
.tbtn-danger:hover { background: var(--red); color: var(--bg); box-shadow: none; }
.tbtn-dim { border-color: var(--border2); color: var(--text3); }
.tbtn-dim:hover { border-color: var(--text3); color: var(--text2); background: transparent; box-shadow: none; }
.tbtn-dim::before { display: none; }
.tbtn-green { border-color: var(--accent2); color: var(--accent2); }
.tbtn-green:hover { background: var(--accent2); color: var(--bg); }

.auth-msg {
  font-size: 11px; padding: 8px 12px; margin-bottom: 14px;
  border-left: 2px solid; display: flex; align-items: center; gap: 8px;
  font-family: 'Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
}
.auth-msg::before { content:'#'; opacity:.5; flex-shrink:0; }
.auth-msg.err { border-color: var(--red); color: var(--red); background: rgba(239,68,68,.05); }
.auth-msg.ok  { border-color: var(--accent2); color: var(--accent2); background: rgba(74,222,128,.05); }

/* ── APP LAYOUT ── */
#app { display: none; height: 100dvh; flex-direction: column; }

/* topbar */
.topbar {
  display: flex; align-items: center;
  height: 36px; background: var(--bg1);
  border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.tb-logo {
  padding: 0 16px; color: var(--text); font-size: 13px; font-weight: 600;
  height: 100%; display: flex; align-items: center; white-space: nowrap; flex-shrink: 0;
  letter-spacing: -.01em;
}
.tb-hamburger {
  display: none; padding: 0 14px; background: transparent; border: none;
  color: var(--text2); cursor: pointer; height: 100%; align-items: center; flex-shrink: 0;
}
.tb-search {
  display: flex; align-items: center; flex: 1;
  height: 100%; padding: 0 12px; gap: 8px; min-width: 0;
}
.tb-search-icon { color: var(--text3); flex-shrink: 0; }
.tb-search input {
  flex: 1; background: transparent; border: none; color: var(--text);
  font-size: 13px; outline: none; min-width: 0;
}
.tb-search input::placeholder { color: var(--text4); }
.tb-right {
  display: flex; align-items: center; height: 100%; gap: 0; flex-shrink: 0;
  border-left: 1px solid var(--border);
}
.tb-user {
  padding: 0 14px; color: var(--text3); font-size: 12px;
  border-right: 1px solid var(--border); height: 100%; display: flex; align-items: center;
  white-space: nowrap;
}
.tb-btn {
  padding: 0 14px; background: transparent; border: none; border-right: 1px solid var(--border);
  color: var(--text3); font-family: inherit; font-size: 12px; cursor: pointer; height: 100%;
  transition: color .12s, background .12s; white-space: nowrap;
}
.tb-btn:hover { color: var(--text); background: var(--bg2); }
.tb-btn.new { color: var(--accent); font-weight: 500; }
.tb-btn.new:hover { background: var(--accent); color: #000; }
.tb-btn.logout:hover { color: var(--red); }

/* main */
.main { display: flex; flex: 1; overflow: hidden; position: relative; }

/* sidebar */
.sidebar {
  width: 196px; flex-shrink: 0; background: var(--bg1);
  border-right: 1px solid var(--border); display: flex; flex-direction: column;
  overflow-y: auto;
}
.sb-section-head {
  padding: 14px 12px 6px;
  color: var(--text4); font-size: 10px; text-transform: uppercase; letter-spacing: .1em;
}
.sb-item {
  display: flex; align-items: center; padding: 7px 12px;
  color: var(--text3); font-size: 12px; cursor: pointer;
  border: none; background: transparent; width: 100%; text-align: left;
  font-family: inherit; border-left: 2px solid transparent;
  transition: color .1s, background .1s;
}
.sb-item:hover { color: var(--text2); background: var(--bg2); }
.sb-item.active { color: var(--accent); background: rgba(34,197,94,.06); border-left-color: var(--accent); }
.sb-item .sb-key { display: none; }
.sb-cnt { margin-left: auto; color: var(--text4); font-size: 10px; }
.sb-item.active .sb-cnt { color: var(--accent-dim); }
.sb-divider { height: 1px; background: var(--border); margin: 6px 0; }

.sb-tags { padding: 4px 10px 10px; display: flex; flex-wrap: wrap; gap: 4px; }
.tag-btn {
  padding: 2px 8px; font-size: 11px; cursor: pointer;
  background: transparent; border: 1px solid var(--border); color: var(--text3);
  font-family: inherit; transition: all .1s; border-radius: 2px;
}
.tag-btn:hover { border-color: var(--border2); color: var(--text2); }
.tag-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(34,197,94,.06); }

/* content */
.content { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0; }
.content-head {
  padding: 6px 12px; border-bottom: 1px solid var(--border);
  font-size: 11px; color: var(--text3); flex-shrink: 0; background: var(--bg1);
  display: flex; align-items: center; justify-content: space-between;
}

/* mobile bottom action bar */
.mob-nav {
  display: none;
  position: fixed; bottom: 0; left: 0; right: 0; z-index: 30;
  background: var(--bg1); border-top: 1px solid var(--border);
  overflow-x: auto; -webkit-overflow-scrolling: touch;
  scrollbar-width: none;
}
.mob-nav::-webkit-scrollbar { display: none; }
.mob-nav-inner { display: flex; min-width: max-content; }
.mob-nav-btn {
  flex-shrink: 0; background: transparent; border: none;
  color: var(--text3); font-family: inherit; cursor: pointer;
  border-right: 1px solid var(--border); white-space: nowrap;
  transition: color .1s, background .1s;
}
.mob-nav-btn.mob-action {
  display: flex; flex-direction: column; align-items: center; gap: 3px;
  padding: 7px 14px; font-size: 10px; letter-spacing: .04em;
}
.mob-nav-btn.mob-action:hover { color: var(--accent); background: rgba(34,197,94,.06); }
.mob-nav-btn.mob-action svg { display: block; }
.mob-nav-btn.mob-danger { color: var(--text4); }
.mob-nav-btn.mob-danger:hover { color: var(--red); background: rgba(239,68,68,.06); }

.cmd-list { flex: 1; overflow-y: auto; }
.cmd-row {
  display: flex; align-items: center; padding: 8px 12px; gap: 8px;
  border-bottom: 1px solid var(--border); cursor: pointer;
  transition: background .1s;
}
.cmd-row:hover { background: var(--bg2); }
.cmd-row.selected { background: rgba(34,197,94,.05); border-left: 2px solid var(--accent); padding-left: 10px; }
.cmd-row.selected .cr-title { color: var(--accent); }
.cr-os {
  font-size: 10px; min-width: 60px; flex-shrink: 0;
  padding: 2px 5px; border: 1px solid;
  text-align: center; text-transform: uppercase; letter-spacing: .04em; border-radius: 1px;
}
.cr-os-linux   { color: var(--linux);   border-color: var(--linux-bg);   background: var(--linux-bg); }
.cr-os-windows { color: var(--windows); border-color: var(--windows-bg); background: var(--windows-bg); }
.cr-os-macos   { color: var(--macos);   border-color: var(--macos-bg);   background: var(--macos-bg); }
.cr-os-android { color: var(--android); border-color: var(--android-bg); background: var(--android-bg); }
.cr-os-payload { color: var(--payload); border-color: var(--payload-bg); background: var(--payload-bg); }
.cr-os-snippet { color: var(--yellow);  border-color: var(--snippet-bg); background: var(--snippet-bg); }
.cr-os-other   { color: var(--other);   border-color: var(--other-bg);   background: var(--other-bg); }
.cr-type { font-size: 10px; color: var(--text4); min-width: 46px; flex-shrink: 0; }
.cr-title { font-size: 12px; color: var(--text2); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cr-tags { font-size: 10px; color: var(--text4); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 110px; }
.cr-steps { font-size: 10px; color: var(--text4); white-space: nowrap; flex-shrink: 0; }

.empty-list {
  flex: 1; display: flex; flex-direction: column; align-items: center;
  justify-content: center; color: var(--text4); gap: 6px; padding: 40px; text-align: center;
}
.empty-list .e-sym { font-size: 22px; color: var(--border2); margin-bottom: 6px; }

/* detail */
.detail {
  width: 460px; flex-shrink: 0; background: var(--bg1);
  border-left: 1px solid var(--border); display: flex; flex-direction: column; overflow: hidden;
}
.detail-placeholder {
  flex: 1; display: flex; flex-direction: column;
  align-items: center; justify-content: center; color: var(--border2); gap: 5px;
}
.detail-placeholder .dp-sym { font-size: 18px; }
.detail-placeholder .dp-hint { font-size: 11px; color: var(--text4); }
#detail-content { display: none; flex-direction: column; height: 100%; }

.dh {
  padding: 12px 14px; border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.dh-title { color: var(--text); font-size: 13px; margin-bottom: 8px; }
.dh-meta { display: flex; gap: 7px; flex-wrap: wrap; align-items: center; }
.dh-os {
  font-size: 10px; padding: 2px 7px; border: 1px solid; text-transform: uppercase;
  letter-spacing: .04em;
}
.dh-type { font-size: 10px; color: var(--text3); }
.dh-tag { font-size: 10px; color: var(--accent-dim); }

.detail-body { flex: 1; overflow-y: auto; padding: 14px; }
.d-desc { font-size: 11px; color: var(--text3); margin-bottom: 12px; padding-bottom: 11px; border-bottom: 1px solid var(--border); }

.step-block { margin-bottom: 12px; }
.step-hdr {
  display: flex; align-items: center; gap: 8px; padding: 3px 0; margin-bottom: 5px;
  font-size: 11px; color: var(--text3);
}
.step-hdr .sn { color: var(--accent-dim); }
.step-hdr .snote { color: var(--text3); font-style: italic; }
.code-wrap {
  background: var(--bg); border: 1px solid var(--border);
  padding: 11px 14px; position: relative; overflow-x: auto;
}
.code-wrap:hover { border-color: var(--border2); }
.code-wrap pre {
  font-family: inherit; font-size: 12px; color: var(--accent2);
  white-space: pre-wrap; word-break: break-all;
}
.code-wrap .prompt-sym { color: var(--accent-dim); user-select: none; }
.copy-btn {
  position: absolute; top: 7px; right: 7px; padding: 2px 9px;
  background: var(--bg1); border: 1px solid var(--border);
  color: var(--text3); font-family: inherit; font-size: 10px; cursor: pointer;
  transition: all .1s;
}
.copy-btn:hover { border-color: var(--accent); color: var(--accent); }
.copy-btn.copied { border-color: var(--accent2); color: var(--accent2); }

.detail-actions {
  padding: 9px 13px; border-top: 1px solid var(--border);
  display: flex; gap: 7px; flex-shrink: 0;
}
.da-btn {
  padding: 5px 13px; background: transparent; border: 1px solid var(--border);
  color: var(--text3); font-family: inherit; font-size: 11px; cursor: pointer;
  transition: all .1s;
}
.da-btn:hover { border-color: var(--border2); color: var(--text2); background: var(--bg2); }
.da-btn.danger:hover { border-color: var(--red); color: var(--red); }
/* back button for mobile detail */
.da-btn.back { display: none; }

/* modal overlay */
.overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.8);
  display: flex; align-items: center; justify-content: center; z-index: 100; padding: 16px;
  backdrop-filter: blur(2px);
}
.modal {
  background: var(--bg1); border: 1px solid var(--border2);
  width: 700px; max-width: 100%; max-height: 92dvh;
  display: flex; flex-direction: column;
  box-shadow: 0 24px 64px rgba(0,0,0,.6);
}
.modal-hdr {
  padding: 11px 15px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between; flex-shrink: 0;
  background: var(--bg);
}
.modal-hdr-title { color: var(--accent); font-size: 12px; letter-spacing:.04em; }
.modal-close {
  background: transparent; border: none; color: var(--text3); font-size: 14px;
  cursor: pointer; font-family: inherit; padding: 0 4px; transition: color .1s;
}
.modal-close:hover { color: var(--red); }
.modal-body { padding: 18px; overflow-y: auto; flex: 1; }
.modal-footer {
  padding: 11px 15px; border-top: 1px solid var(--border);
  display: flex; gap: 9px; justify-content: flex-end; flex-shrink: 0;
  background: var(--bg);
}

.frow { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px; }
.fg { margin-bottom: 13px; }
.fg label {
  display: block; font-size: 10px; color: var(--text3); margin-bottom: 5px;
  text-transform: uppercase; letter-spacing: .07em;
}
.fg label .prompt { color: var(--accent2); }
.fg input, .fg textarea, .fg select {
  width: 100%; background: var(--bg); border: 1px solid var(--border);
  padding: 8px 10px; color: var(--text); font-family: inherit; font-size: 12px; outline: none;
  transition: border-color .15s;
}
.fg input:focus, .fg textarea:focus, .fg select:focus { border-color: var(--accent); }
.fg select option { background: var(--bg1); }
.fg textarea { resize: vertical; min-height: 60px; }

/* step editor */
.steps-editor { display: flex; flex-direction: column; gap: 7px; }
.step-ed {
  background: var(--bg); border: 1px solid var(--border); padding: 11px;
}
.step-ed-hdr { display: flex; align-items: center; gap: 8px; margin-bottom: 7px; }
.step-ed-num { color: var(--accent-dim); font-size: 11px; }
.step-ed-remove {
  margin-left: auto; background: transparent; border: none;
  color: var(--text4); cursor: pointer; font-size: 14px; font-family: inherit;
  transition: color .1s;
}
.step-ed-remove:hover { color: var(--red); }
.step-ed textarea {
  width: 100%; background: var(--bg1); border: 1px solid var(--border);
  padding: 8px 10px; color: var(--accent2); font-family: inherit; font-size: 12px;
  outline: none; resize: vertical; min-height: 52px; transition: border-color .15s;
}
.step-ed textarea:focus { border-color: var(--accent); }
.step-ed input.note-in {
  width: 100%; background: transparent; border: none; border-bottom: 1px solid var(--border);
  padding: 4px 0; color: var(--text3); font-family: inherit; font-size: 11px; outline: none; margin-top: 7px;
}
.step-ed input.note-in::placeholder { color: var(--text4); }
.add-step-btn {
  width: 100%; padding: 7px; background: transparent;
  border: 1px dashed var(--border); color: var(--text4);
  font-family: inherit; font-size: 11px; cursor: pointer; margin-top: 5px;
  transition: all .1s;
}
.add-step-btn:hover { border-color: var(--accent); color: var(--accent); }

/* tags input */
.tags-wrap {
  display: flex; flex-wrap: wrap; gap: 5px; padding: 7px 9px;
  background: var(--bg); border: 1px solid var(--border); min-height: 36px; cursor: text;
  transition: border-color .15s;
}
.tags-wrap:focus-within { border-color: var(--accent); }
.tag-pill {
  background: rgba(0,229,255,.06); border: 1px solid var(--accent-dim); color: var(--accent);
  padding: 0 7px; font-size: 11px; display: flex; align-items: center; gap: 4px;
}
.tag-pill button {
  background: transparent; border: none; color: var(--accent-dim); cursor: pointer; font-size: 12px; padding: 0;
  transition: color .1s;
}
.tag-pill button:hover { color: var(--red); }
#tag-input-field {
  background: transparent; border: none; color: var(--text);
  font-family: inherit; font-size: 12px; outline: none; min-width: 70px; flex: 1;
}
#tag-input-field::placeholder { color: var(--text4); }

/* toast */
.toast-wrap { position: fixed; bottom: 20px; right: 20px; display: flex; flex-direction: column; gap: 5px; z-index: 999; }
.toast {
  background: var(--bg1); border: 1px solid var(--border2); border-left: 2px solid;
  padding: 8px 15px; font-size: 11px; max-width: 300px;
  animation: tin .15s ease;
  box-shadow: 0 4px 16px rgba(0,0,0,.4);
}
.toast-ok  { border-left-color: var(--accent2); color: var(--accent2); }
.toast-err { border-left-color: var(--red);    color: var(--red); }
.toast-info{ border-left-color: var(--text3);  color: var(--text2); }
@keyframes tin { from { opacity: 0; transform: translateX(10px); } }

/* loading */
.loading { display: flex; align-items: center; justify-content: center; padding: 30px; color: var(--text4); font-size: 11px; gap: 8px; }

/* pin indicator on list row */
.cr-pin { color: var(--accent); font-size: 10px; flex-shrink: 0; opacity: .8; }
.cmd-row.pinned-row { border-left: 2px solid var(--accent-dim); }
.cmd-row.pinned-row.selected { border-left-color: var(--accent); }

/* copy-chain button in detail actions */
.da-btn.chain { color: var(--accent-dim); }
.da-btn.chain:hover { border-color: var(--accent); color: var(--accent); background: rgba(34,197,94,.06); }
.da-btn.pin-btn { }
.da-btn.pin-btn.pinned { color: var(--accent); border-color: var(--accent-dim); }

/* date meta in detail */
.dh-date { font-size: 10px; color: var(--text4); margin-top: 6px; letter-spacing: .02em; }

/* step drag handle */
.step-ed-hdr { cursor: default; }
.step-drag { cursor: grab; color: var(--text4); font-size: 12px; user-select: none; padding: 0 4px; }
.step-drag:active { cursor: grabbing; }
.step-ed.drag-over { border-color: var(--accent); background: rgba(34,197,94,.04); }

/* topbar extra buttons */
.tb-btn.export { }
.tb-btn.import-btn { }

/* import modal */
#import-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.8);
  display: none; align-items: center; justify-content: center; z-index: 100; padding: 16px;
  backdrop-filter: blur(2px);
}
#import-overlay.open { display: flex; }
.import-modal {
  background: var(--bg1); border: 1px solid var(--border2);
  width: 480px; max-width: 100%;
  box-shadow: 0 24px 64px rgba(0,0,0,.6);
}
.import-drop {
  border: 1px dashed var(--border2); margin: 16px;
  padding: 32px 16px; text-align: center;
  color: var(--text4); font-size: 12px; cursor: pointer;
  transition: border-color .15s, color .15s;
}
.import-drop:hover, .import-drop.drag-active { border-color: var(--accent); color: var(--accent); }
.import-drop input[type=file] { display: none; }

/* chain copy separator selector */
.chain-sep {
  display: inline-flex; gap: 0; margin-left: auto;
}
.chain-sep button {
  padding: 3px 8px; background: transparent; border: 1px solid var(--border);
  color: var(--text4); font-family: inherit; font-size: 10px; cursor: pointer;
  transition: all .1s;
}
.chain-sep button:first-child { border-right: none; }
.chain-sep button:last-child { border-left: none; }
.chain-sep button.active { background: var(--bg2); border-color: var(--border2); color: var(--text2); }
.chain-sep button:hover { color: var(--accent); border-color: var(--accent-dim); }

/* sidebar overlay for mobile */
.sb-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.55); z-index: 49; }

/* ── RESPONSIVE ── */
@media (max-width: 1100px) {
  .detail { width: 360px; }
}
@media (max-width: 820px) {
  .detail { display: none; }
  .detail.mobile-open { display: flex; position: fixed; inset: 0; bottom: 52px; width: 100%; z-index: 40; }
  .da-btn.back { display: inline-block; }
}
@media (max-width: 600px) {
  /* sidebar becomes drawer */
  .sidebar {
    position: fixed; left: 0; top: 0; bottom: 0; z-index: 50;
    transform: translateX(-100%); transition: transform .22s ease;
    width: 220px;
  }
  .sidebar.open { transform: translateX(0); }
  .sb-overlay.open { display: block; }
  /* topbar simplify — actions move to bottom bar */
  .tb-hamburger { display: flex; }
  .tb-logo { padding: 0 12px; }
  .tb-user { display: none; }
  .tb-btn.logout { display: none; }
  .tb-btn.export { display: none; }
  .tb-btn.import-btn { display: none; }
  .tb-btn.new { display: none; }
  /* mobile bottom action bar */
  .mob-nav { display: flex; }
  /* pad content above bottom bar */
  .main { padding-bottom: 52px; }
  .detail.mobile-open { bottom: 52px; }
  /* modal full screen */
  .frow { grid-template-columns: 1fr; }
  .toast-wrap { bottom: 64px; right: 12px; left: 12px; }
  .toast { max-width: 100%; }
  /* detail actions scroll on mobile */
  .detail-actions { overflow-x: auto; flex-wrap: nowrap; gap: 5px; }
  .detail-actions .da-btn { flex-shrink: 0; font-size: 10px; padding: 5px 10px; }
}
</style>
</head>
<body>

<!-- AUTH -->
<div id="auth-screen" <?= $already_authed ? 'style="display:none"' : '' ?>>
  <div class="auth-box">
    <div class="auth-statusbar">
      <span class="sb-left"><span class="sb-dot"></span>CMDWLT v<?= APP_VERSION ?></span>
      <span class="sb-right"><span class="sb-locked"><svg width="9" height="10" viewBox="0 0 9 10" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle;margin-right:5px"><rect x="1" y="4.5" width="7" height="5" rx=".75" fill="currentColor" opacity=".9"/><path d="M2.5 4.5V3a2 2 0 0 1 4 0v1.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>AUTH:REQUIRED</span></span>
    </div>
    <div class="auth-banner">
<pre>
  ______           _ _   __          _ _
 / _____)         | | | \ \        / | | |
| /      ____   _ | | |  \ \  /\  / /| | |_
| |     / _  | / || | |   \ \/  \/ / | |  _)
| \____( ( | || |_| | |    \  /\  /  | | |__
 \______\_||_| \____|_|     \/  \/   |_|____)
</pre>
      <div class="title-line"><svg width="13" height="13" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle;margin-right:7px;flex-shrink:0"><polyline points="2,4 6,7 2,10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/><line x1="8" y1="10" x2="12" y2="10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>cmdwlt <span class="tl-slash">//</span> <span class="tl-author">psvineet.me</span></div>
      <div class="sub-line">linux &middot; windows &middot; macos &middot; android &middot; payloads &middot; snippets</div>
    </div>
    <div class="auth-form-box">
      <div id="auth-msg-wrap"></div>
      <!-- LOGIN FORM -->
      <div id="login-form">
        <div class="tfield">
          <label><span class="prompt">vault</span><span class="prompt-at">@</span><span class="prompt">local</span>:~# username</label>
          <input id="l-user" type="text" placeholder="enter username" autocomplete="username" onkeydown="if(event.key==='Enter')document.getElementById('l-pass').focus()">
        </div>
        <div class="tfield">
          <label><span class="prompt">vault</span><span class="prompt-at">@</span><span class="prompt">local</span>:~# password</label>
          <div class="pass-wrap">
            <input id="l-pass" type="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')document.getElementById('l-cap').focus()">
            <button type="button" class="pass-toggle" onclick="togglePass('l-pass',this)" tabindex="-1" title="Show/hide password">show</button>
          </div>
        </div>
        <div class="captcha-row">
          <div>
            <span class="captcha-label">verify // solve</span>
            <div class="captcha-q" id="captcha-display"><?= h($captcha_q) ?> = ?</div>
          </div>
          <div class="tfield">
            <label class="captcha-label">answer</label>
            <input id="l-cap" type="text" inputmode="numeric" pattern="[0-9]*" placeholder="?" autocomplete="off" maxlength="4" onkeydown="if(event.key==='Enter')doLogin()">
          </div>
        </div>
        <button class="tbtn" onclick="doLogin()">authenticate</button>
      </div>
      <!-- FIRST-RUN SETUP (shown instead of login when vault is empty) -->
      <div id="setup-form" style="display:none">
        <div class="auth-setup-badge">&gt; first run — initialize vault</div>
        <div class="tfield">
          <label><span class="prompt">setup</span>:~# username</label>
          <input id="r-user" type="text" placeholder="choose username" autocomplete="username">
        </div>
        <div class="tfield">
          <label><span class="prompt">setup</span>:~# password (min 8)</label>
          <div class="pass-wrap">
            <input id="r-pass" type="password" placeholder="••••••••" autocomplete="new-password" onkeydown="if(event.key==='Enter')document.getElementById('r-pass2').focus()">
            <button type="button" class="pass-toggle" onclick="togglePass('r-pass',this)" tabindex="-1" title="Show/hide">show</button>
          </div>
        </div>
        <div class="tfield">
          <label><span class="prompt">setup</span>:~# confirm password</label>
          <div class="pass-wrap">
            <input id="r-pass2" type="password" placeholder="••••••••" autocomplete="new-password" onkeydown="if(event.key==='Enter')doSetup()">
            <button type="button" class="pass-toggle" onclick="togglePass('r-pass2',this)" tabindex="-1" title="Show/hide">show</button>
          </div>
        </div>
        <button class="tbtn" onclick="doSetup()">initialize vault</button>
      </div>
    </div>
    <div class="auth-hintbar">
      <span>dev: Vineet Pratap Singh</span>
      <span>psvineet.me</span>
    </div>
  </div>
</div>

<!-- APP -->
<div id="app" <?= $already_authed ? 'style="display:flex"' : '' ?>>
  <!-- topbar -->
  <div class="topbar">
    <button class="tb-hamburger" onclick="toggleSidebar()" title="Menu" aria-label="Menu">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect y="2" width="16" height="1.5" rx=".75" fill="currentColor"/><rect y="7" width="16" height="1.5" rx=".75" fill="currentColor"/><rect y="12" width="16" height="1.5" rx=".75" fill="currentColor"/></svg>
    </button>
    <div class="tb-logo"><svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle;margin-right:6px;flex-shrink:0"><polyline points="2,4 6,7 2,10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/><line x1="8" y1="10" x2="12" y2="10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>cmdwlt</div>
    <div class="tb-search">
      <svg class="tb-search-icon" width="13" height="13" viewBox="0 0 16 16" fill="none"><circle cx="6.5" cy="6.5" r="5" stroke="currentColor" stroke-width="1.5"/><path d="M10.5 10.5L14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
      <input type="text" id="search-input" placeholder="search commands..." oninput="debounceSearch()">
    </div>
    <div class="tb-right">
      <span class="tb-user" id="uname-display">--</span>
      <button class="tb-btn new" onclick="openAddModal()" title="New entry (N)">+ new</button>
      <button class="tb-btn export" onclick="doExport()" title="Export all as JSON">[export]</button>
      <button class="tb-btn import-btn" onclick="openImport()" title="Import from JSON">[import]</button>
      <button class="tb-btn logout" onclick="doLogout()" title="Logout (Q)">logout</button>
    </div>
  </div>

  <div class="sb-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>
  <!-- mobile bottom action bar (replaces redundant OS filter duplicate) -->
  <div class="mob-nav" id="mob-nav">
    <div class="mob-nav-inner">
      <button class="mob-nav-btn mob-action" onclick="openAddModal()">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><line x1="7" y1="2" x2="7" y2="12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><line x1="2" y1="7" x2="12" y2="7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        new
      </button>
      <button class="mob-nav-btn mob-action" onclick="copyChain()" id="mob-btn-chain">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><rect x="1" y="5" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.3"/><path d="M5 4V3a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-1" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
        chain
      </button>
      <button class="mob-nav-btn mob-action" onclick="togglePin()" id="mob-btn-pin">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><path d="M5 2h4l-1 4 2 2H4l2-2L5 2Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><line x1="7" y1="8" x2="7" y2="13" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
        pin
      </button>
      <button class="mob-nav-btn mob-action" onclick="editSelected()">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><path d="M2 10L9.5 2.5a1.5 1.5 0 0 1 2 2L4 12H2v-2Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/></svg>
        edit
      </button>
      <button class="mob-nav-btn mob-action" onclick="duplicateSelected()">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><rect x="4" y="4" width="8" height="8" rx="1" stroke="currentColor" stroke-width="1.3"/><path d="M2 10V3a1 1 0 0 1 1-1h7" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
        dup
      </button>
      <button class="mob-nav-btn mob-action" onclick="doExport()">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><path d="M7 2v7M4 6l3 3 3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 11h10" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
        export
      </button>
      <button class="mob-nav-btn mob-action" onclick="openImport()">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><path d="M7 9V2M4 5l3-3 3 3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 11h10" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
        import
      </button>
      <button class="mob-nav-btn mob-action mob-danger" onclick="deleteSelected()">
        <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><path d="M2 4h10M5 4V2h4v2M5.5 7v4M8.5 7v4M3 4l.8 8h6.4L11 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
        del
      </button>
    </div>
  </div>
  <div class="main">
    <!-- sidebar -->
    <div class="sidebar">
      <div class="sb-section-head">Platform</div>
      <button class="sb-item active" onclick="setOsFilter('')" data-os-sb="">all<span class="sb-cnt" id="cnt-all">0</span></button>
      <button class="sb-item" onclick="setOsFilter('linux')" data-os-sb="linux">linux<span class="sb-cnt" id="cnt-linux">0</span></button>
      <button class="sb-item" onclick="setOsFilter('windows')" data-os-sb="windows">windows<span class="sb-cnt" id="cnt-windows">0</span></button>
      <button class="sb-item" onclick="setOsFilter('macos')" data-os-sb="macos">macos<span class="sb-cnt" id="cnt-macos">0</span></button>
      <button class="sb-item" onclick="setOsFilter('android')" data-os-sb="android">android<span class="sb-cnt" id="cnt-android">0</span></button>
      <button class="sb-item" onclick="setOsFilter('payload')" data-os-sb="payload">payload<span class="sb-cnt" id="cnt-payload">0</span></button>
      <button class="sb-item" onclick="setOsFilter('snippet')" data-os-sb="snippet">snippet<span class="sb-cnt" id="cnt-snippet">0</span></button>
      <button class="sb-item" onclick="setOsFilter('other')" data-os-sb="other">other<span class="sb-cnt" id="cnt-other">0</span></button>
      <div class="sb-divider"></div>
      <div class="sb-section-head">Tags</div>
      <div class="sb-tags" id="tags-cloud"></div>
    </div>

    <!-- list -->
    <div class="content">
      <div class="content-head" id="list-count">-- loading --</div>
      <div class="cmd-list" id="cmd-list">
        <div class="loading">loading vault...</div>
      </div>
    </div>

    <!-- detail -->
    <div class="detail" id="detail-panel">
      <div class="detail-placeholder" id="detail-empty">
        <div class="dp-sym">[ ]</div>
        <div class="dp-hint">select entry to view</div>
        <div class="dp-hint" style="margin-top:8px;line-height:1.9;text-align:left;font-size:10px;color:var(--text4)">
          [n] new &nbsp; [e] edit &nbsp; [d] delete<br>
          [c] copy chain &nbsp; [p] pin &nbsp; [u] duplicate<br>
          [/] search &nbsp; [q] logout &nbsp; [esc] close
        </div>
      </div>
      <div id="detail-content">
        <div class="dh">
          <div class="dh-title" id="d-title"></div>
          <div class="dh-meta" id="d-meta"></div>
        </div>
        <div class="detail-body" id="d-body"></div>
        <div class="detail-actions">
          <button class="da-btn back" onclick="closeMobileDetail()">← back</button>
          <button class="da-btn chain" id="btn-copy-chain" onclick="copyChain()" title="Copy all steps joined (C)">[c] copy chain</button>
          <button class="da-btn pin-btn" id="btn-pin" onclick="togglePin()" title="Pin to top">[p] pin</button>
          <button class="da-btn" onclick="duplicateSelected()" title="Duplicate entry">[dup]</button>
          <button class="da-btn" onclick="editSelected()" title="Edit (E)">[e] edit</button>
          <button class="da-btn danger" onclick="deleteSelected()" title="Delete (D)">[d] del</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- MODAL -->
<div class="overlay" id="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-hdr">
      <span class="modal-hdr-title" id="modal-title">&gt;_ new entry</span>
      <button class="modal-close" onclick="closeModal()">[x]</button>
    </div>
    <div class="modal-body">
      <input type="hidden" id="edit-id">
      <div class="frow">
        <div class="fg">
          <label><span class="prompt">&gt;</span> title *</label>
          <input type="text" id="f-title" placeholder="e.g. list open ports">
        </div>
        <div class="fg">
          <label><span class="prompt">&gt;</span> description</label>
          <input type="text" id="f-desc" placeholder="short note">
        </div>
      </div>
      <div class="frow">
        <div class="fg">
          <label><span class="prompt">&gt;</span> platform</label>
          <select id="f-os">
            <option value="linux">linux</option>
            <option value="windows">windows</option>
            <option value="macos">macos</option>
            <option value="android">android (adb)</option>
            <option value="payload">payload / exploit</option>
            <option value="snippet">code snippet</option>
            <option value="other">other</option>
          </select>
        </div>
        <div class="fg">
          <label><span class="prompt">&gt;</span> type</label>
          <select id="f-type">
            <option value="command">single command</option>
            <option value="chain">chain (multi-step)</option>
            <option value="payload">payload</option>
            <option value="snippet">code snippet</option>
            <option value="oneliner">one-liner</option>
            <option value="other">other</option>
          </select>
        </div>
      </div>
      <div class="fg">
        <label><span class="prompt">&gt;</span> tags (Enter or comma to add)</label>
        <div class="tags-wrap" id="tags-wrap" onclick="document.getElementById('tag-input-field').focus()">
          <input type="text" id="tag-input-field" placeholder="add tag..." onkeydown="handleTagInput(event)">
        </div>
      </div>
      <div class="fg">
        <label><span class="prompt">&gt;</span> steps / commands</label>
        <div class="steps-editor" id="steps-editor"></div>
        <button class="add-step-btn" onclick="addStep()">+ add step</button>
      </div>
    </div>
    <div class="modal-footer">
      <button class="tbtn tbtn-dim" style="width:auto;padding:5px 16px" onclick="closeModal()">cancel</button>
      <button class="tbtn" style="width:auto;padding:5px 16px" onclick="saveCommand()">&gt; save</button>
    </div>
  </div>
</div>

<!-- IMPORT MODAL -->
<div id="import-overlay" onclick="if(event.target===this)closeImport()">
  <div class="import-modal">
    <div class="modal-hdr">
      <span class="modal-hdr-title">&gt;_ import vault</span>
      <button class="modal-close" onclick="closeImport()">[x]</button>
    </div>
    <div class="import-drop" id="import-drop" onclick="document.getElementById('import-file').click()"
         ondragover="event.preventDefault();this.classList.add('drag-active')"
         ondragleave="this.classList.remove('drag-active')"
         ondrop="handleImportDrop(event)">
      <input type="file" id="import-file" accept=".json" onchange="handleImportFile(event)">
      <div style="font-size:22px;color:var(--border2);margin-bottom:8px">[&nbsp;+&nbsp;]</div>
      <div>drop JSON export file here or click to browse</div>
      <div style="margin-top:6px;font-size:11px;color:var(--text4)">only cmdwlt export files accepted</div>
    </div>
    <div id="import-status" style="margin:0 16px 16px;font-size:11px;color:var(--text3);display:none"></div>
    <div class="modal-footer">
      <button class="tbtn tbtn-dim" style="width:auto;padding:5px 16px" onclick="closeImport()">cancel</button>
    </div>
  </div>
</div>

<div class="toast-wrap" id="toasts"></div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const OS_LABELS = {linux:'linux',windows:'win',macos:'macos',android:'adb',payload:'payload',snippet:'snippet',other:'other'};
const TYPE_LABELS = {command:'cmd',chain:'chain',payload:'payload',snippet:'snippet',oneliner:'1liner',other:'other'};

let state = {
  os:'', tag:'', q:'', selectedId:null,
  commands:[], tags:[],
  searchTimer:null
};

// ─── AUTH ───────────────────────────────────────────────────────────────────
async function initAuth() {
  const r = await api('setup_needed');
  if (r.needed) {
    document.getElementById('login-form').style.display='none';
    document.getElementById('setup-form').style.display='';
  } else {
    document.getElementById('login-form').style.display='';
    document.getElementById('setup-form').style.display='none';
  }
}
async function doLogin() {
  const u=document.getElementById('l-user').value.trim();
  const p=document.getElementById('l-pass').value;
  const cap=document.getElementById('l-cap').value.trim();
  if(!u||!p){authMsg('# missing username or password','err');return;}
  if(!cap){authMsg('# solve the verification question','err');return;}
  const r=await apiPost('login',{username:u,password:p,captcha:cap});
  if(r.ok){document.getElementById('uname-display').textContent=r.username;showApp();}
  else {
    authMsg('# '+r.error,'err');
    if(r.captcha_refresh) refreshCaptcha();
    else if(r.error && r.error.includes('attempts')) {
      /* rate limited — nothing to retry */
    }
    document.getElementById('l-cap').value='';
    // reset show/hide state on password field
    const lp=document.getElementById('l-pass');
    lp.type='password';
    const ptbtn=lp.parentElement&&lp.parentElement.querySelector('.pass-toggle');
    if(ptbtn) ptbtn.textContent='show';
    document.getElementById('l-cap').focus();
  }
}
async function refreshCaptcha(){
  const r=await fetch('?api=captcha');
  const d=await r.json();
  if(d.q) document.getElementById('captcha-display').textContent=d.q+' = ?';
}
async function doSetup() {
  const u=document.getElementById('r-user').value.trim();
  const p=document.getElementById('r-pass').value;
  const p2=document.getElementById('r-pass2').value;
  if(!u||!p){authMsg('fill all fields','err');return;}
  if(p!==p2){authMsg('passwords do not match','err');return;}
  if(p.length<8){authMsg('password min 8 chars','err');return;}
  const r=await apiPost('register',{username:u,password:p});
  if(r.ok){
    // show login form — captcha required for login, user must complete it
    authMsg('# vault initialized — please log in','ok');
    document.getElementById('r-user').value='';
    document.getElementById('r-pass').value='';
    document.getElementById('r-pass2').value='';
    document.getElementById('setup-form').style.display='none';
    document.getElementById('login-form').style.display='';
    document.getElementById('l-user').value=u;
    await refreshCaptcha();
    document.getElementById('l-pass').focus();
  } else authMsg('error: '+r.error,'err');
}
function togglePass(id,btn){
  const el=document.getElementById(id);
  const show=el.type==='password';
  el.type=show?'text':'password';
  btn.textContent=show?'hide':'show';
}
function authMsg(msg,type){
  const d=document.createElement('div');
  d.className='auth-msg '+type;
  d.textContent=msg;
  const w=document.getElementById('auth-msg-wrap');
  w.innerHTML='';
  w.appendChild(d);
}
async function doLogout(){
  if(!confirm('logout?')) return;
  await apiPost('logout',{});
  location.reload();
}
function showApp(){
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app').style.display='flex';
  loadAll();
}

// ─── DATA ───────────────────────────────────────────────────────────────────
async function loadAll(){
  await Promise.all([loadCommands(), loadTags(), loadStats()]);
}
async function loadCommands(){
  document.getElementById('cmd-list').innerHTML='<div class="loading"><div class="spinner"></div> Loading…</div>';
  let url='?api=list';
  if(state.os)  url+=`&os=${encodeURIComponent(state.os)}`;
  if(state.tag) url+=`&tag=${encodeURIComponent(state.tag)}`;
  if(state.q)   url+=`&q=${encodeURIComponent(state.q)}`;
  const r=await fetch(url);
  state.commands=await r.json();
  renderList();
}
async function loadTags(){
  const r=await fetch('?api=tags');
  state.tags=await r.json();
  renderTags();
}
async function loadStats(){
  const r=await fetch('?api=stats');
  const s=await r.json();
  const stEl=document.getElementById('s-total'); if(stEl) stEl.textContent=s.total;
  const counts={};
  (s.by_os||[]).forEach(x=>counts[x.os]=x.cnt);
  document.getElementById('cnt-all').textContent=s.total;
  ['linux','windows','macos','android','payload','snippet','other'].forEach(os=>{
    const el=document.getElementById('cnt-'+os);
    if(el) el.textContent=counts[os]||0;
  });
  const osParts=(s.by_os||[]).filter(x=>x.cnt>0).map(x=>`${x.os}:<span>${x.cnt}</span>`);
  const soEl=document.getElementById('s-os-parts'); if(soEl) soEl.innerHTML=osParts.join(' &nbsp; ');
}

function renderList(){
  const list=document.getElementById('cmd-list');
  const cmds=state.commands;
  document.getElementById('list-count').textContent=`-- ${cmds.length} result${cmds.length!==1?'s':''} --`;
  if(!cmds.length){
    list.innerHTML=`<div class="empty-list"><div class="e-sym">[ empty ]</div><div>no entries found</div><div style="font-size:11px;margin-top:4px">press [n] to add new</div></div>`;
    return;
  }
  list.innerHTML=cmds.map(c=>{
    const tags=(c.tags||'').split(',').filter(Boolean).map(t=>`#${t}`).join(' ');
    const sel=state.selectedId===c.id?'selected':'';
    const pinCls=c.pinned?'pinned-row':'';
    return `<div class="cmd-row ${sel} ${pinCls}" onclick="selectCmd(${c.id})" data-id="${c.id}">
      ${c.pinned?'<span class="cr-pin" title="Pinned">*</span>':''}
      <span class="cr-os cr-os-${c.os}">${OS_LABELS[c.os]||c.os}</span>
      <span class="cr-type">${TYPE_LABELS[c.type]||c.type}</span>
      <span class="cr-title">${esc(c.title)}</span>
      <span class="cr-tags">${esc(tags)}</span>
      <span class="cr-steps">[${c.step_count}]</span>
    </div>`;
  }).join('');
}

function renderTags(){
  const cloud=document.getElementById('tags-cloud');
  if(!state.tags.length){cloud.innerHTML='<span style="font-size:11px;color:#1e1e1e">-- none --</span>';return;}
  cloud.innerHTML=state.tags.map(t=>`<button class="tag-btn${state.tag===t.name?' active':''}" onclick="setTagFilter('${esc(t.name)}')">#${esc(t.name)}(${t.cnt})</button>`).join('');
}

async function selectCmd(id){
  state.selectedId=id;
  document.querySelectorAll('.cmd-row').forEach(c=>c.classList.toggle('selected',parseInt(c.dataset.id)===id));
  const r=await fetch(`?api=get&id=${id}`);
  const cmd=await r.json();
  if(cmd.error){toast(cmd.error,'err');return;}
  renderDetail(cmd);
  // open detail panel on mobile
  if(window.innerWidth<=860){
    document.getElementById('detail-panel').classList.add('mobile-open');
  }
}

let _currentCmd = null;
let _chainSep = '&&';

function renderDetail(cmd){
  _currentCmd = cmd;
  document.getElementById('detail-empty').style.display='none';
  const dc=document.getElementById('detail-content');
  dc.style.display='flex'; dc.style.flexDirection='column';
  document.getElementById('d-title').textContent='> '+cmd.title;

  const tags=(cmd.tags||[]).map(t=>`<span class="dh-tag">#${esc(t)}</span>`).join(' ');
  const updated = cmd.updated_at ? new Date(cmd.updated_at*1000).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) : '';
  const created = cmd.created_at ? new Date(cmd.created_at*1000).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) : '';
  document.getElementById('d-meta').innerHTML=`
    <span class="dh-os cr-os-${cmd.os}">${OS_LABELS[cmd.os]||cmd.os}</span>
    <span class="dh-type">${TYPE_LABELS[cmd.type]||cmd.type}</span>
    ${tags}
    <div class="dh-date" style="width:100%;margin-top:5px">created ${created} &nbsp;&middot;&nbsp; updated ${updated}</div>
  `;

  // pin button state
  const pinBtn = document.getElementById('btn-pin');
  if(pinBtn){ pinBtn.classList.toggle('pinned', !!cmd.pinned); pinBtn.textContent=cmd.pinned?'[p] unpin':'[p] pin'; }

  // show copy-chain only for multi-step
  const chainBtn = document.getElementById('btn-copy-chain');
  const steps=cmd.steps||[];
  if(chainBtn) chainBtn.style.display = steps.length > 1 ? '' : 'none';

  let body='';
  if(cmd.description) body+=`<div class="d-desc"># ${esc(cmd.description)}</div>`;

  // chain copy bar (only multi-step)
  if(steps.length>1){
    body+=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;font-size:11px;color:var(--text4)">
      <span>join steps as:</span>
      <div class="chain-sep">
        <button id="sep-and" class="${_chainSep==='&&'?'active':''}" onclick="setSep('&&')">&amp;&amp;</button>
        <button id="sep-nl"  class="${_chainSep==='\n'?'active':''}"  onclick="setSep('\\n')">newline</button>
        <button id="sep-semi" class="${_chainSep===';'?'active':''}" onclick="setSep(';')">;</button>
      </div>
    </div>`;
  }

  if(!steps.length) body+='<div style="color:#2a2a2a;font-size:11px">(no steps)</div>';
  const multi=steps.length>1;
  steps.forEach((s)=>{
    body+=`<div class="step-block">
      ${multi?`<div class="step-hdr"><span class="sn">-- step ${s.step_order} --</span>${s.note?`<span class="snote"> # ${esc(s.note)}</span>`:''}</div>`:''}
      <div class="code-wrap">
        <pre><span class="prompt-sym">$ </span>${esc(s.code)}</pre>
        <button class="copy-btn" onclick="copyCode(this,'${btoa(unescape(encodeURIComponent(s.code)))}')">[copy]</button>
      </div>
    </div>`;
  });
  document.getElementById('d-body').innerHTML=body;
}

function copyCode(btn,b64){
  let code;
  try { code=decodeURIComponent(escape(atob(b64))); } catch(e){ code=atob(b64); }
  navigator.clipboard.writeText(code).then(()=>{
    btn.textContent='[ok]'; btn.classList.add('copied');
    setTimeout(()=>{btn.textContent='[copy]';btn.classList.remove('copied');},2000);
  });
}

// ─── FILTERS ────────────────────────────────────────────────────────────────
function setOsFilter(os){
  state.os=os; state.tag=''; state.selectedId=null;
  document.querySelectorAll('[data-os-sb]').forEach(c=>c.classList.toggle('active',c.dataset.osSb===os));
  document.querySelectorAll('.tag-btn').forEach(t=>t.classList.remove('active'));
  clearDetail();
  loadCommands(); loadTags();
  if(window.innerWidth<=600) closeSidebar();
}
function toggleSidebar(){
  const sb=document.querySelector('.sidebar');
  const ov=document.getElementById('sb-overlay');
  sb.classList.toggle('open');
  ov.classList.toggle('open');
}
function closeSidebar(){
  document.querySelector('.sidebar').classList.remove('open');
  document.getElementById('sb-overlay').classList.remove('open');
}
function closeMobileDetail(){
  document.getElementById('detail-panel').classList.remove('mobile-open');
  state.selectedId=null;
}
function setTagFilter(tag){
  state.tag=state.tag===tag?'':tag;
  document.querySelectorAll('.tag-btn').forEach(t=>t.classList.toggle('active',t.textContent.trim().startsWith('#'+tag)));
  clearDetail();
  loadCommands();
}
function debounceSearch(){
  clearTimeout(state.searchTimer);
  state.searchTimer=setTimeout(()=>{
    state.q=document.getElementById('search-input').value.trim();
    clearDetail(); loadCommands();
  },300);
}
function clearDetail(){
  state.selectedId=null;
  document.getElementById('detail-empty').style.display='flex';
  document.getElementById('detail-content').style.display='none';
  document.getElementById('detail-content').style.flexDirection='';
}

// ─── MODAL ──────────────────────────────────────────────────────────────────
let editTags=[];
function openAddModal(cmd=null){
  document.getElementById('modal-title').textContent=cmd?'>_ edit entry':'>_ new entry';
  document.getElementById('edit-id').value=cmd?cmd.id:'';
  document.getElementById('f-title').value=cmd?cmd.title:'';
  document.getElementById('f-desc').value=cmd?cmd.description:'';
  document.getElementById('f-os').value=cmd?cmd.os:'linux';
  document.getElementById('f-type').value=cmd?cmd.type:'command';
  editTags=cmd?[...(cmd.tags||[])]:[];
  renderTagPills();
  // steps
  const steps=cmd?cmd.steps:[{code:'',note:''}];
  document.getElementById('steps-editor').innerHTML='';
  steps.forEach(s=>addStep(s));
  document.getElementById('modal-overlay').style.display='flex';
  setTimeout(()=>document.getElementById('f-title').focus(),50);
}
function closeModal(){document.getElementById('modal-overlay').style.display='none';}

async function editSelected(){
  if(!state.selectedId)return;
  const r=await fetch(`?api=get&id=${state.selectedId}`);
  const cmd=await r.json();
  if(cmd.error){toast(cmd.error,'err');return;}
  openAddModal(cmd);
}

let stepCount=0;
function addStep(data=null){
  stepCount++;
  const id='step-'+stepCount;
  const div=document.createElement('div');
  div.className='step-ed';
  div.id=id;
  div.innerHTML=`<div class="step-ed-hdr">
      <span class="step-ed-num">-- step ${document.querySelectorAll('.step-ed').length+1} --</span>
      <button class="step-ed-remove" onclick="removeStep('${id}')">[x]</button>
    </div>
    <textarea placeholder="$ command or code..." rows="3">${data?esc(data.code):''}</textarea>
    <input class="note-in" type="text" placeholder="# optional note..." value="${data?esc(data.note||''):''}">`;
  document.getElementById('steps-editor').appendChild(div);
  reNumberSteps();
}
function removeStep(id){
  const el=document.getElementById(id);
  if(el) el.remove();
  reNumberSteps();
}
function reNumberSteps(){
  document.querySelectorAll('.step-ed').forEach((el,i)=>{
    el.querySelector('.step-ed-num').textContent=`-- step ${i+1} --`;
  });
}

function handleTagInput(e){
  if(e.key==='Enter'||e.key===','||e.key===' '){
    e.preventDefault();
    const val=e.target.value.replace(/,/g,'').trim().toLowerCase().replace(/[^a-z0-9_\-]/g,'');
    if(val&&!editTags.includes(val)){editTags.push(val);renderTagPills();}
    e.target.value='';
  } else if(e.key==='Backspace'&&!e.target.value&&editTags.length){
    editTags.pop(); renderTagPills();
  }
}
function removeTag(t){editTags=editTags.filter(x=>x!==t);renderTagPills();}
function renderTagPills(){
  const wrap=document.getElementById('tags-wrap');
  const input=document.getElementById('tag-input-field');
  wrap.innerHTML='';
  editTags.forEach(t=>{
    const pill=document.createElement('span');
    pill.className='tag-pill';
    pill.innerHTML=`#${t} <button onclick="removeTag('${t}')">×</button>`;
    wrap.appendChild(pill);
  });
  wrap.appendChild(input);
}

async function saveCommand(){
  const id=document.getElementById('edit-id').value;
  const title=document.getElementById('f-title').value.trim();
  const desc=document.getElementById('f-desc').value.trim();
  const os=document.getElementById('f-os').value;
  const type=document.getElementById('f-type').value;
  if(!title){toast('error: title required','err');return;}
  const steps=[];
  document.querySelectorAll('.step-ed').forEach(el=>{
    const code=el.querySelector('textarea').value.trim();
    const note=el.querySelector('.note-in').value.trim();
    if(code) steps.push({code,note});
  });
  if(!steps.length){toast('error: add at least one step','err');return;}
  const body={title,description:desc,os,type,steps,tags:editTags};
  if(id) body.id=parseInt(id);
  const r=await fetch('?api=save',{
    method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
    body:JSON.stringify(body)
  });
  const res=await r.json();
  if(res.ok){
    toast(id?'entry updated.':'entry saved.','ok');
    closeModal();
    await loadAll();
    selectCmd(res.id);
  } else toast('error: '+(res.error||'save failed'),'err');
}

async function deleteSelected(){
  if(!state.selectedId)return;
  if(!confirm('delete this entry? cannot be undone.'))return;
  const r=await fetch('?api=delete',{
    method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
    body:JSON.stringify({id:state.selectedId})
  });
  const res=await r.json();
  if(res.ok){toast('entry deleted.','ok');clearDetail();loadAll();}
  else toast('error: '+(res.error||'delete failed'),'err');
}

// ─── CHAIN COPY ─────────────────────────────────────────────────────────────
function setSep(sep){
  _chainSep = sep === '\\n' ? '\n' : sep;
  document.querySelectorAll('.chain-sep button').forEach(b=>b.classList.remove('active'));
  const map={'&&':'sep-and','\n':'sep-nl',';':'sep-semi'};
  const el=document.getElementById(map[_chainSep]||'sep-and');
  if(el) el.classList.add('active');
}
function copyChain(){
  if(!_currentCmd) return;
  const steps=(_currentCmd.steps||[]).map(s=>s.code).filter(Boolean);
  if(!steps.length){toast('no steps to copy','err');return;}
  const joined = steps.join(_chainSep);
  navigator.clipboard.writeText(joined).then(()=>{
    toast(`chain copied (${steps.length} steps, joined with "${_chainSep==='\n'?'\\n':_chainSep}")`, 'ok');
  });
}

// ─── PIN ────────────────────────────────────────────────────────────────────
async function togglePin(){
  if(!state.selectedId) return;
  const r=await fetch('?api=pin',{
    method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
    body:JSON.stringify({id:state.selectedId})
  });
  const res=await r.json();
  if(res.ok){
    toast(res.pinned?'entry pinned.':'entry unpinned.','ok');
    if(_currentCmd) _currentCmd.pinned=res.pinned;
    const pinBtn=document.getElementById('btn-pin');
    if(pinBtn){pinBtn.classList.toggle('pinned',!!res.pinned);pinBtn.textContent=res.pinned?'[p] unpin':'[p] pin';}
    await loadCommands();
  } else toast('error: '+(res.error||'pin failed'),'err');
}

// ─── DUPLICATE ──────────────────────────────────────────────────────────────
async function duplicateSelected(){
  if(!state.selectedId) return;
  const r=await fetch('?api=duplicate',{
    method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
    body:JSON.stringify({id:state.selectedId})
  });
  const res=await r.json();
  if(res.ok){toast('entry duplicated.','ok');await loadAll();selectCmd(res.id);}
  else toast('error: '+(res.error||'duplicate failed'),'err');
}

// ─── EXPORT ─────────────────────────────────────────────────────────────────
async function doExport(){
  const r=await fetch('?api=export');
  const blob=await r.blob();
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=url;
  a.download='cmdwlt-export-'+new Date().toISOString().slice(0,10)+'.json';
  a.click();
  URL.revokeObjectURL(url);
  toast('export downloaded.','ok');
}

// ─── IMPORT ─────────────────────────────────────────────────────────────────
function openImport(){ document.getElementById('import-overlay').classList.add('open'); }
function closeImport(){
  document.getElementById('import-overlay').classList.remove('open');
  document.getElementById('import-status').style.display='none';
  document.getElementById('import-status').textContent='';
  document.getElementById('import-file').value='';
}
function handleImportDrop(e){
  e.preventDefault();
  document.getElementById('import-drop').classList.remove('drag-active');
  const file=e.dataTransfer.files[0];
  if(file) processImportFile(file);
}
function handleImportFile(e){ const file=e.target.files[0]; if(file) processImportFile(file); }
async function processImportFile(file){
  if(!file.name.endsWith('.json')){toast('only .json files accepted','err');return;}
  const text=await file.text();
  let data;
  try{ data=JSON.parse(text); }catch(e){toast('invalid JSON file','err');return;}
  if(!data.commands){toast('not a cmdwlt export file','err');return;}
  const st=document.getElementById('import-status');
  st.style.display='block'; st.textContent='importing...';
  const r=await fetch('?api=import',{
    method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
    body:JSON.stringify(data)
  });
  const res=await r.json();
  if(res.ok){
    st.textContent=`imported ${res.imported} entries${res.skipped?`, skipped ${res.skipped}`:''}.`;
    toast(`imported ${res.imported} entries.`,'ok');
    await loadAll();
    setTimeout(closeImport, 1800);
  } else { st.textContent='error: '+(res.error||'import failed'); toast('import failed','err'); }
}

// ─── HELPERS ────────────────────────────────────────────────────────────────
async function api(action){const r=await fetch(`?api=${action}`);return r.json();}
async function apiPost(action,data){
  return fetch(`?api=${action}`,{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({...data,_csrf:CSRF})
  }).then(r=>r.json());
}
function esc(s){
  if(!s)return'';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function toast(msg,type='info'){
  const w=document.getElementById('toasts');
  const t=document.createElement('div');
  t.className=`toast toast-${type}`;
  t.textContent=msg;
  w.appendChild(t);
  setTimeout(()=>t.remove(),3000);
}

// ─── KEYBOARD ───────────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.target.tagName==='SELECT') return;
  if(e.key==='n'||e.key==='N'){ e.preventDefault(); openAddModal(); }
  if(e.key==='/'){ e.preventDefault(); document.getElementById('search-input').focus(); }
  if(e.key==='e'||e.key==='E'){ e.preventDefault(); editSelected(); }
  if(e.key==='d'||e.key==='D'){ e.preventDefault(); deleteSelected(); }
  if(e.key==='c'||e.key==='C'){ e.preventDefault(); copyChain(); }
  if(e.key==='p'||e.key==='P'){ e.preventDefault(); togglePin(); }
  if(e.key==='u'||e.key==='U'){ e.preventDefault(); duplicateSelected(); }
  if(e.key==='q'||e.key==='Q'){ e.preventDefault(); doLogout(); }
  if(e.key==='Escape'){
    // close modal first, then mobile detail, then sidebar
    const modal=document.getElementById('modal-overlay');
    if(modal.style.display!=='none'){ closeModal(); return; }
    const detail=document.getElementById('detail-panel');
    if(detail.classList.contains('mobile-open')){ closeMobileDetail(); return; }
    closeSidebar();
  }
});

// ─── BOOT ───────────────────────────────────────────────────────────────────
const _serverAuthed = <?= $already_authed ? 'true' : 'false' ?>;
if(_serverAuthed){
  document.getElementById('uname-display').textContent='<?= $uname_display ?>';
  loadAll();
} else {
  initAuth();
}
</script>
</body>
</html>
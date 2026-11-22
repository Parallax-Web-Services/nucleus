<?php
declare(strict_types=1);

const NEBULA_PORTAL_CONFIG = '/etc/parallax/nebula-cpanel/portal.json';

function pathMetadata(string $path): array
{
    clearstatcache(true, $path);
    $metadata = @lstat($path);
    if (!is_array($metadata)) {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    return $metadata;
}

function sameMetadata(array $first, array $second, bool $directory = false): bool
{
    $fields = $directory ? ['dev', 'ino', 'mode', 'uid', 'gid'] : ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtime', 'ctime'];
    foreach ($fields as $field) {
        if (!array_key_exists($field, $first) || !array_key_exists($field, $second) || $first[$field] !== $second[$field]) {
            return false;
        }
    }
    return true;
}

function portalOrigin(): string
{
    $path = NEBULA_PORTAL_CONFIG;
    if ($path === '' || $path[0] !== '/' || str_contains($path, "\0")) {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    $parts = explode('/', substr($path, 1));
    $file = array_pop($parts);
    if ($file === '' || $file === '.' || $file === '..') {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    $ancestors = [];
    $directory = '/';
    foreach (array_merge([''], $parts) as $part) {
        if ($part !== '') {
            if ($part === '.' || $part === '..') {
                throw new RuntimeException('Portal configuration unavailable.');
            }
            $directory = rtrim($directory, '/') . '/' . $part;
        } elseif ($directory !== '/') {
            throw new RuntimeException('Portal configuration unavailable.');
        }
        $metadata = pathMetadata($directory);
        if (($metadata['mode'] & 0170000) !== 0040000 || !(($metadata['mode'] & 07777) === 0755 || ($directory === '/' && ($metadata['mode'] & 07777) === 0555)) || $metadata['uid'] !== 0 || $metadata['gid'] !== 0) {
            throw new RuntimeException('Portal configuration unavailable.');
        }
        $ancestors[$directory] = $metadata;
    }
    $before = pathMetadata($path);
    if (($before['mode'] & 0170000) !== 0100000 || ($before['mode'] & 07777) !== 0644 ||
        $before['uid'] !== 0 || $before['gid'] !== 0 || $before['size'] < 1 || $before['size'] > 4096) {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    try {
        $opened = fstat($handle);
        if (!is_array($opened) || !sameMetadata($before, $opened)) {
            throw new RuntimeException('Portal configuration unavailable.');
        }
        $raw = stream_get_contents($handle, 4097);
        $after = fstat($handle);
        if (!is_string($raw) || strlen($raw) !== $before['size'] || strlen($raw) > 4096 ||
            !is_array($after) || !sameMetadata($before, $after) || !sameMetadata($before, pathMetadata($path))) {
            throw new RuntimeException('Portal configuration unavailable.');
        }
    } finally {
        fclose($handle);
    }
    foreach ($ancestors as $ancestor => $metadata) {
        if (!sameMetadata($metadata, pathMetadata($ancestor), true)) {
            throw new RuntimeException('Portal configuration unavailable.');
        }
    }
    $space = '[ \t\r\n]*';
    $jsonString = '"(?:[^"\\\\\x00-\x1f]|\\\\(?:["\\\\/bfnrt]|u[0-9a-fA-F]{4}))*"';
    $schema = '"schema_version"' . $space . ':' . $space . '1';
    $portal = '"portal_url"' . $space . ':' . $space . $jsonString;
    $entry = '(?:' . $schema . $space . ',' . $space . $portal . '|' . $portal . $space . ',' . $space . $schema . ')';
    if (preg_match('~\A' . $space . '\{' . $space . $entry . $space . '\}' . $space . '\z~D', $raw) !== 1) {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    $configuration = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
    if (!is_array($configuration) || count($configuration) !== 2 || ($configuration['schema_version'] ?? null) !== 1 || !is_string($configuration['portal_url'] ?? null)) {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    $origin = $configuration['portal_url'];
    $label = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
    if (strlen($origin) > 261 || preg_match('~\Ahttps://(' . $label . '(?:\.' . $label . ')+)\z~D', $origin, $matches) !== 1 ||
        strlen($matches[1]) > 253 || preg_match('/(?:\A|\.)(?:[0-9]+|0x[0-9a-f]*)\z/D', $matches[1]) === 1) {
        throw new RuntimeException('Portal configuration unavailable.');
    }
    return $origin;
}

function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$origin = null;
try {
    $origin = portalOrigin();
} catch (Throwable $error) {
    http_response_code(503);
}
header('Content-Type: text/html; charset=utf-8');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, private, max-age=0');
header('Pragma: no-cache');

$html = <<<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{color-scheme:dark;--bg:#09070f;--panel:#15101f;--line:rgba(196,181,253,.16);--text:#f6f2ff;--muted:#bbb2ca;--purple:#c4a7ff}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 15% 0%,#28143e 0%,transparent 55%),var(--bg);color:var(--text);font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(100% - 40px,760px);margin:0 auto;padding:clamp(28px,7vh,76px) 0 36px}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:52px}.brand svg{flex:none}
.wordmark{font-size:16px;font-weight:750;letter-spacing:.22em;line-height:1.3}.byline{color:var(--muted);font-size:12px;letter-spacing:.06em;margin-top:3px}
.eyebrow{margin:0 0 12px;color:var(--purple);font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}
h1{font-size:clamp(30px,6vw,46px);line-height:1.14;letter-spacing:-.04em;margin:0 0 18px;max-width:640px}
.lead{color:var(--muted);font-size:17px;max-width:590px;margin:0}
.panel{margin-top:32px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(120deg,rgba(196,167,255,.06),transparent 65%),var(--panel);padding:clamp(22px,5vw,36px)}
.label{color:#e6dcf7;font-size:12px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;margin:0 0 4px}
.address{color:var(--muted);font-size:14px;overflow-wrap:anywhere;margin:0 0 24px}
.button{display:inline-flex;min-height:48px;align-items:center;justify-content:center;gap:18px;border:1px solid transparent;border-radius:11px;padding:12px 23px;background:linear-gradient(110deg,#b18afa,#d2b5ff);color:#1a1029;font-size:15px;font-weight:750;text-decoration:none;box-shadow:0 6px 28px rgba(156,94,232,.14)}
a.button:hover{filter:brightness(1.08)}a.button:focus-visible{outline:3px solid #f5e9ff;outline-offset:5px}.unavailable{background:#2a2237;border-color:var(--line);color:#c4b9d1;box-shadow:none}
.note{margin:18px 0 0;color:var(--muted);font-size:13px;max-width:550px}
footer{border-top:1px solid var(--line);margin-top:36px;padding-top:20px;color:#978aa8;font-size:12px}
@media(max-width:480px){main{width:calc(100% - 32px)}.brand{margin-bottom:38px}.button{width:100%}.panel{border-radius:18px}}
@media(prefers-reduced-motion:no-preference){a.button{transition:filter .15s ease}}
</style>
</head>
<body>
<main>
<header class="brand"><svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48" fill="none"><rect x="1" y="1" width="46" height="46" rx="14" fill="#171022" stroke="#a78bfa" stroke-opacity=".42"/><path d="M13 15 24 24l12-11M24 24l11 12M24 24 12 35" stroke="#bca3ff" stroke-width="1.8" stroke-linecap="round"/><circle cx="24" cy="24" r="6" fill="#a78bfa"/><circle cx="13" cy="15" r="3" fill="#ede9fe"/><circle cx="36" cy="13" r="3" fill="#d8b4fe"/><circle cx="35" cy="36" r="3" fill="#ede9fe"/><circle cx="12" cy="35" r="3" fill="#d8b4fe"/></svg><div><div class="wordmark">NEBULA</div><div class="byline">by Parallax</div></div></header>
<p class="eyebrow">__PANEL__</p>
<h1>__HEADING__</h1>
<p class="lead">__LEAD__</p>
<section class="panel" aria-label="NEBULA portal">
<p class="label">NEBULA portal</p>
<p class="address">__ADDRESS__</p>
__ACTION__
<p class="note">__NOTE__</p>
</section>
<footer>Access is checked in NEBULA after NEXUS sign-in.</footer>
</main>
</body>
</html>
HTML;
$ready = $origin !== null;
echo strtr($html, [
    '__TITLE__' => 'NEBULA portal &middot; cPanel',
    '__PANEL__' => 'From cPanel',
    '__HEADING__' => $ready ? 'Continue to NEBULA.' : 'Portal link unavailable.',
    '__LEAD__' => $ready ? 'Sign in with NEXUS to access the organizations available to you.' : 'A server administrator can check the portal configuration for this server.',
    '__ADDRESS__' => $ready ? escapeHtml($origin) : 'The portal link is currently unavailable.',
    '__ACTION__' => $ready ? '<a class="button" href="' . escapeHtml($origin) . '" target="_blank" rel="noopener noreferrer">Open NEBULA <span aria-hidden="true">&nearr;</span></a>' : '<span class="button unavailable">Portal unavailable</span>',
    '__NOTE__' => $ready ? 'Opens the configured portal in a new tab. Sign in and choose an organization there.' : 'Try again after the server configuration has been updated.',
]);

#!/usr/local/cpanel/3rdparty/bin/perl
use strict;
use warnings;
use JSON::PP;
use Fcntl qw(O_RDONLY O_NOFOLLOW O_NONBLOCK S_ISREG S_ISDIR);

my $config_path = '/etc/parallax/nebula-cpanel/portal.json';

sub same_metadata {
    my ($first, $second, $directory) = @_;
    my @fields = $directory ? (0, 1, 2, 4, 5) : (0, 1, 2, 3, 4, 5, 7, 9, 10);
    for my $index (@fields) {
        return 0 if !defined($first->[$index]) || !defined($second->[$index]) || $first->[$index] != $second->[$index];
    }
    return 1;
}

sub portal_origin {
    die "Portal unavailable\n" if $> == 0;
    my ($path) = @_;
    die "Portal unavailable\n" if $path !~ m{\A/} || $path =~ /\0/;
    my @parts = split m{/}, substr($path, 1), -1;
    my $filename = pop @parts;
    die "Portal unavailable\n" if !defined($filename) || $filename eq '' || $filename eq '.' || $filename eq '..';
    my @ancestors;
    my $directory = '/';
    for my $part ('', @parts) {
        if ($part ne '') {
            die "Portal unavailable\n" if $part eq '.' || $part eq '..';
            $directory =~ s{/\z}{};
            $directory .= '/' . $part;
        } else {
            die "Portal unavailable\n" if $directory ne '/';
        }
        my @metadata = lstat($directory);
        die "Portal unavailable\n" unless @metadata && S_ISDIR($metadata[2]) && (($metadata[2] & 07777) == 0755 || ($directory eq '/' && ($metadata[2] & 07777) == 0555)) && $metadata[4] == 0 && $metadata[5] == 0;
        push @ancestors, [$directory, \@metadata];
    }
    my @before = lstat($path);
    die "Portal unavailable\n" unless @before && S_ISREG($before[2]) && ($before[2] & 07777) == 0644 && $before[4] == 0 && $before[5] == 0 && $before[7] >= 1 && $before[7] <= 4096;
    sysopen(my $handle, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or die "Portal unavailable\n";
    binmode($handle);
    my @opened = stat($handle);
    die "Portal unavailable\n" unless same_metadata(\@before, \@opened, 0);
    my $raw = '';
    while (length($raw) <= 4096) {
        my $read = sysread($handle, my $buffer, 4097 - length($raw));
        die "Portal unavailable\n" unless defined($read);
        last if $read == 0;
        $raw .= $buffer;
    }
    my @after = stat($handle);
    close($handle);
    my @current = lstat($path);
    die "Portal unavailable\n" unless length($raw) == $before[7] && length($raw) <= 4096 && same_metadata(\@before, \@after, 0) && same_metadata(\@before, \@current, 0);
    for my $ancestor (@ancestors) {
        my @metadata = lstat($ancestor->[0]);
        die "Portal unavailable\n" unless same_metadata($ancestor->[1], \@metadata, 1);
    }
    my $space = qr/[ \t\r\n]*/;
    my $json_string = qr/"(?:[^"\\\x00-\x1f]|\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4}))*"/;
    my $schema = qr/"schema_version"$space:$space 1/x;
    my $portal = qr/"portal_url"$space:$space$json_string/;
    die "Portal unavailable\n" unless $raw =~ /\A$space\{$space(?:$schema$space,$space$portal|$portal$space,$space$schema)$space\}$space\z/;
    my $configuration = JSON::PP->new->utf8->max_size(4096)->max_depth(4)->decode($raw);
    die "Portal unavailable\n" unless ref($configuration) eq 'HASH' && keys(%$configuration) == 2 && defined($configuration->{portal_url}) && !ref($configuration->{portal_url});
    my $origin = $configuration->{portal_url};
    my $label = qr/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/;
    die "Portal unavailable\n" unless length($origin) <= 261 && $origin =~ m{\Ahttps://($label(?:\.$label)+)\z};
    my $host = $1;
    die "Portal unavailable\n" if length($host) > 253 || $host =~ /(?:\A|\.)(?:[0-9]+|0x[0-9a-f]*)\z/;
    return $origin;
}

sub escape_html {
    my ($value) = @_;
    $value =~ s/&/&amp;/g;
    $value =~ s/</&lt;/g;
    $value =~ s/>/&gt;/g;
    $value =~ s/"/&quot;/g;
    $value =~ s/'/&#39;/g;
    return $value;
}

my $origin = eval { portal_origin($config_path) };
my $ready = defined($origin);
print "Status: 503 Service Unavailable\r\n" unless $ready;
print "Content-Type: text/html; charset=utf-8\r\n";
print "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'\r\n";
print "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store, private, max-age=0\r\nPragma: no-cache\r\n\r\n";

my $html = <<'HTML';
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
HTML
my %values = (
    '__TITLE__' => 'NEBULA portal &middot; WHM',
    '__PANEL__' => 'From WHM',
    '__HEADING__' => $ready ? 'Continue to NEBULA.' : 'Portal link unavailable.',
    '__LEAD__' => $ready ? 'Sign in with NEXUS to access the organizations available to you.' : 'A server administrator can check the portal configuration for this server.',
    '__ADDRESS__' => $ready ? escape_html($origin) : 'The portal link is currently unavailable.',
    '__ACTION__' => $ready ? '<a class="button" href="' . escape_html($origin) . '" target="_blank" rel="noopener noreferrer">Open NEBULA <span aria-hidden="true">&nearr;</span></a>' : '<span class="button unavailable">Portal unavailable</span>',
    '__NOTE__' => $ready ? 'Opens the configured portal in a new tab. Sign in and choose an organization there.' : 'Try again after the server configuration has been updated.',
);
$html =~ s/(__TITLE__|__PANEL__|__HEADING__|__LEAD__|__ADDRESS__|__ACTION__|__NOTE__)/$values{$1}/ge;
print $html;

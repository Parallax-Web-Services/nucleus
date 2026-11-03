use strict;use warnings;use Test::More;use FindBin;use File::Temp qw(tempdir);use File::Path qw(make_path remove_tree);use IPC::Open3;use Symbol qw(gensym);use IO::Select;use JSON::PP;
plan skip_all=>'Run isolated render fixtures as Linux root' unless $>==0;
my $php=(grep {-x $_} qw(/usr/bin/php8.5 /usr/bin/php8.4 /usr/bin/php))[0];die 'Existing PHP CLI required; do not install host packages' unless $php;
my @n=getpwnam('nobody');die 'Unprivileged test user required' unless @n && $n[2]>0;
umask 0022;my $root=tempdir('nebula-cpanel-test-XXXXXXXX',DIR=>'/run',CLEANUP=>0);chmod 0755,$root;my $dir="$root/etc/parallax/nebula-cpanel";make_path($dir,{mode=>0755});
sub put {my($p,$b,$mode)=@_;open my$f,'>',$p or die $!;binmode$f;print {$f}$b;close$f;chmod $mode,$p;}
my @renderers;
for my $spec (['whm','payload/whm/index.cgi','index.cgi'],['cpanel','payload/cpanel/index.live.php','index.live.php']){open my$f,'<',"$FindBin::RealBin/../$spec->[1]" or die $!;local$/;my$b=<$f>;close$f;$b=~s{\Q/etc/parallax/nebula-cpanel/portal.json\E}{$dir/portal.json}g;my$p="$root/$spec->[2]";put($p,$b,0644);push @renderers,[$spec->[0],$p];}
sub capture {
 my(@cmd)=@_;my$err=gensym;my$pid=open3(my$in,my$out,$err,@cmd);close$in;my$sel=IO::Select->new($out,$err);my%kind=(fileno($out)=>'out',fileno($err)=>'err');my%data=(out=>'',err=>'');while($sel->count){for my$f($sel->can_read(5)){my$n=sysread($f,my$b,16384);die 'Read failure' unless defined$n;if(!$n){$sel->remove($f);close$f;next;}$data{$kind{fileno($f)}}.=$b;}}waitpid($pid,0);die 'Renderer process failed' if $?;return \%data;
}
sub render {
 my($spec,$asroot)=@_;my@cmd=$spec->[0] eq 'whm'?('/usr/bin/perl',$spec->[1]):($php,'-r','include $argv[1];fwrite(STDERR,"STATUS=".http_response_code());',$spec->[1]);@cmd=('/usr/sbin/runuser','-u','nobody','--',@cmd) unless $asroot;local$ENV{QUERY_STRING}='portal_url=https%3A%2F%2Fevil.example&team_id=secret-team';local$ENV{REMOTE_USER}='never-disclose-account';return capture(@cmd);
}
sub check_case {
 my($label,$bytes,$ready)=@_;unlink "$dir/portal.json" if -e "$dir/portal.json" || -l "$dir/portal.json";put("$dir/portal.json",$bytes,0644) if defined$bytes;
 for my$s(@renderers){my$d=render($s,0);if($ready){like($d->{out},qr/href="https:\/\/nebula\.example"/,$s->[0]." $label canonical portal link");unlike($d->{out}.$d->{err},qr/503|Service Unavailable/,$s->[0]." $label ready");}else{unlike($d->{out},qr/<a\b[^>]*href=/,$s->[0]." $label has no outbound action");like($d->{out}.$d->{err},qr/503|Service Unavailable/,$s->[0]." $label fails closed");}unlike($d->{out},qr/never-disclose-account|secret-team|evil\.example|<script>/,$s->[0]." $label ignores identity/query inputs");}
}
check_case('valid','{"schema_version":1,"portal_url":"https://nebula.example"}',1);
check_case('reordered','{"portal_url":"https:\\/\\/nebula.example","schema_version":1}',1);
check_case('missing',undef,0);
check_case('duplicate keys','{"schema_version":1,"portal_url":"https://evil.example","portal_url":"https://nebula.example"}',0);
check_case('unknown keys','{"schema_version":1,"portal_url":"https://nebula.example","team_id":"secret-team"}',0);
check_case('HTML payload','{"schema_version":1,"portal_url":"https://nebula.example\\\"><script>"}',0);
check_case('userinfo','{"schema_version":1,"portal_url":"https://user:pass@nebula.example"}',0);
check_case('numeric alternate host','{"schema_version":1,"portal_url":"https://0x7f.0.0.1"}',0);
check_case('wrong schema','{"schema_version":2,"portal_url":"https://nebula.example"}',0);
check_case('oversize','x'x4097,0);
put("$dir/portal.json",'{"schema_version":1,"portal_url":"https://nebula.example"}',0664);
for my$s(@renderers){my$d=render($s,0);like($d->{out}.$d->{err},qr/503|Service Unavailable/,"$s->[0] writable config refused");}
chmod 0644,"$dir/portal.json";rename("$dir/portal.json","$dir/real.json");symlink("$dir/real.json","$dir/portal.json") or die$!;
for my$s(@renderers){my$d=render($s,0);like($d->{out}.$d->{err},qr/503|Service Unavailable/,"$s->[0] symlink config refused");}
unlink "$dir/portal.json";rename("$dir/real.json","$dir/portal.json");chown $n[2],$n[3],"$dir/portal.json";
for my$s(@renderers){my$d=render($s,0);like($d->{out}.$d->{err},qr/503|Service Unavailable/,"$s->[0] nonroot config owner refused");}
chown 0,0,"$dir/portal.json";chmod 0775,$dir;
for my$s(@renderers){my$d=render($s,0);like($d->{out}.$d->{err},qr/503|Service Unavailable/,"$s->[0] writable ancestor refused");}
chmod 0755,$dir;my$d=render($renderers[0],1);like($d->{out},qr/Status: 503/,'WHM renderer refuses root execution');
$d=render($renderers[0],0);like($d->{out},qr/Referrer-Policy: no-referrer/,'WHM prevents outgoing referrer leakage');like($d->{out},qr/Content-Security-Policy: default-src 'none'/,'WHM has restrictive CSP');like($d->{out},qr/Sign in with NEXUS/,'NEBULA authenticates through its central portal');unlike($d->{out},qr/connected account|Kubernetes token|Positronic/i,'navigation makes no local account/platform binding claim');

# Instrument only metadata returned for literal / in isolated copies of the actual
# installed renderer source. Never chmod or replace the real filesystem root.
my@original_renderers=@renderers;
for my$case (['root0555',0040555,0,0,1],['root0755',0040755,0,0,1],['writable root',0040775,0,0,0],['nonroot root owner',0040755,65534,0,0],['nonroot root group',0040755,0,65534,0],['symlink root',0120755,0,0,0],['other root mode',0040711,0,0,0]){
 @renderers=();for my$spec(@original_renderers){open my$f,'<',$spec->[1] or die$!;local$/;my$b=<$f>;close$f;my($mode,$uid,$gid)=@$case[1,2,3];
  if($spec->[0] eq 'whm'){my$n=($b=~s/\blstat\(/fixture_lstat(/g);die'WHM fixture injection failed' unless$n==4;my$stub='sub fixture_lstat { my ($path)=@_; my @metadata=CORE::lstat($path); if ($path eq \'/\') { @metadata[2,4,5]=('.$mode.','.$uid.','.$gid.'); } return @metadata; }';$b.=qq{\n$stub\n};}
  else{my$needle='$metadata = @lstat($path);';my$injection=$needle.' if ($path === \'/\') { $metadata[\'mode\'] = '.$mode.'; $metadata[\'uid\'] = '.$uid.'; $metadata[\'gid\'] = '.$gid.'; }';my$n=($b=~s/\Q$needle\E/$injection/);die'PHP fixture injection failed' unless$n==1;}
  my$p=$spec->[1].'.root-metadata';put($p,$b,0644);push@renderers,[$spec->[0],$p];
 }
 check_case($case->[0],'{"schema_version":1,"portal_url":"https://nebula.example"}',$case->[4]);
}
@renderers=@original_renderers;chmod 0555,"$root/etc";
check_case('non-root ancestor0555','{"schema_version":1,"portal_url":"https://nebula.example"}',0);
chmod 0755,"$root/etc";
die 'Unsafe fixture cleanup' unless $root=~m{\A/run/nebula-cpanel-test-[A-Za-z0-9_]+\z} && !-l$root && (stat($root))[4]==0;remove_tree($root,{safe=>1});done_testing();

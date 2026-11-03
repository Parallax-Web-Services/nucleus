package Parallax::NebulaCPanel::Installer;
use strict; use warnings; use POSIX qw(WNOHANG);
use Fcntl qw(:DEFAULT :flock :mode O_NOFOLLOW); use Cwd qw(abs_path); use File::Basename qw(dirname); use File::Temp qw(tempdir); use JSON::PP; use Digest::SHA qw(sha256_hex); use IO::Handle; use IPC::Open3; use IO::Select; use Symbol qw(gensym); use Time::HiRes qw(time stat lstat);
our $VERSION='0.1.3-dev';
my $JSON=JSON::PP->new->canonical->utf8;
my $ID='parallax_nebula';
my @REQUIRED_VENDOR_SOURCES=qw(/usr/local/cpanel/Cpanel/AppConfig/Register.pm /usr/local/cpanel/Cpanel/Plugin/Install.pm /usr/local/cpanel/Cpanel/Themes/Serializer/DynamicUI.pm);
my %HELPERS=(register=>'/usr/local/cpanel/bin/register_appconfig',unregister=>'/usr/local/cpanel/bin/unregister_appconfig',registered=>'/usr/local/cpanel/bin/is_registered_with_appconfig',install=>'/usr/local/cpanel/scripts/install_plugin',uninstall=>'/usr/local/cpanel/scripts/uninstall_plugin');
sub new {
 my($class,%a)=@_; die "Run as root\n" unless $>==0;
 my $prefix=$a{fixture_root}//'';
 if(length $prefix){die "Fixture root must be an existing isolated /run directory\n" unless $a{fixture} && $prefix=~m{\A/run/nebula-cpanel-test-[A-Za-z0-9_]+\z} && -d $prefix && !-l $prefix;}
 my $self=bless {prefix=>$prefix,package=>abs_path($a{package}//'.'),created_files=>{},created_dirs=>{},known_regs=>{},runner=>$a{runner}},$class;
 $self->{state_dir}=$self->path('/var/lib/parallax-nebula-cpanel');$self->{manifest}=$self->{state_dir}.'/state.json';
 $self->{base_dirs}=[qw(/etc/parallax /etc/parallax/nebula-cpanel /usr/local/cpanel/whostmgr/docroot/cgi/parallax-nebula /usr/local/cpanel/base/frontend/jupiter/parallax-nebula /usr/local/cpanel/3rdparty/parallax-nebula)];
 $self->{helper_timeout}=length($prefix)?($a{fixture_timeout}//60):60;die "Invalid fixture helper timeout\n" unless $self->{helper_timeout}>0 && $self->{helper_timeout}<=60;return $self;
}
sub path {my($s,$p)=@_;return $s->{prefix}.$p;}
sub json {return $JSON->encode($_[1]);}
sub canonical_origin {
 my($s,$url)=@_;die "Portal must be a canonical HTTPS origin\n" unless defined($url) && length($url)<=253+8 && $url!~/[\x00-\x20\x7f]/;
 $url=~s{:443\z}{};
 die "Portal must be a canonical HTTPS DNS origin without a path\n" unless $url=~m{\Ahttps://([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\z};
 my $host=$1;my @labels=split /\./,$host;die "Numeric or alternate-IP host refused\n" if $labels[-1]=~/\A(?:[0-9]+|0x[0-9a-f]+)\z/;die "Portal hostname requires valid DNS labels\n" unless $host=~/\./ && length($host)<=253 && $host!~/\.\./ && $host!~/\A[0-9.]+\z/;
 for(split /\./,$host){die "Portal hostname requires valid DNS labels\n" unless length($_)<=63 && /\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/;}
 return $url;
}
sub record {
 my($s,$p)=@_;my @a=lstat($p);return {type=>'absent'} unless @a;die "Symlink refused: $p\n" if S_ISLNK($a[2]);
 my $r={type=>S_ISDIR($a[2])?'dir':S_ISREG($a[2])?'file':'other',device=>$a[0],inode=>$a[1],mode=>S_IMODE($a[2]),uid=>$a[4],gid=>$a[5]};
 die "Special file refused: $p\n" if $r->{type} eq 'other';
 if($r->{type} eq 'file'){
  die "File exceeds bounded size: $p\n" if $a[7]>1024*1024;
  sysopen(my $fh,$p,O_RDONLY|O_NOFOLLOW) or die "Cannot read $p\n";binmode($fh);my @f=stat($fh);die "Concurrent open refused\n" unless join(':',@f[0,1,2,4,5,7,9,10]) eq join(':',@a[0,1,2,4,5,7,9,10]);
  local $/;my $data=<$fh>//'';my @after=stat($fh);close($fh);my @last=lstat($p);die "Concurrent read refused\n" unless @last && join(':',@after[0,1,2,4,5,7,9,10]) eq join(':',@a[0,1,2,4,5,7,9,10]) && join(':',@last[0,1,2,4,5,7,9,10]) eq join(':',@a[0,1,2,4,5,7,9,10]);
  @$r{qw(size mtime ctime sha256)}=($a[7],$a[9],$a[10],sha256_hex($data));
 }
 return $r;
}
sub same {my($s,$a,$b)=@_;return $s->json($a) eq $s->json($b);}
sub read_safe {
 my($s,$p,$mode)=@_;$s->ancestors($p);my $r=$s->record($p);die "Root-owned regular file required: $p\n" unless $r->{type} eq 'file' && $r->{uid}==0 && $r->{gid}==0 && (!defined($mode) ? ($r->{mode}&0022)==0 : $r->{mode}==$mode);
 sysopen(my $f,$p,O_RDONLY|O_NOFOLLOW) or die "Cannot read $p\n";binmode($f);local $/;my $d=<$f>//'';close $f;die "File changed: $p\n" unless $s->same($r,$s->record($p));return($d,$r);
}
sub ancestors {
 my($s,$p)=@_;die "Absolute normalized path required\n" unless $p=~m{\A/} && $p!~m{//|/\.\.?/|/\.\.?\z};
 my $d=dirname($p);while(1){my $r=$s->record($d);my $vendor=length($s->{prefix}) ? (index($d,$s->{prefix}.'/')==0 ? substr($d,length($s->{prefix})) : '') : $d;
  if($vendor=~m{\A/usr/local/cpanel(?:/|\z)} && $vendor!~m{(?:\A|/)parallax[-_]nebula(?:/|\z)}){
   my $pin=$s->{vendor_profile}{vendor_parents}{$vendor};die "Unreviewed vendor ancestor: $vendor\n" unless ref($pin) eq 'HASH';
   die "Reviewed vendor ancestor differs: $vendor\n" unless $r->{type} eq 'dir' && $r->{uid}==0 && ($r->{mode}&0022)==0 && defined(abs_path($d)) && abs_path($d) eq $d && $r->{gid}==$pin->{gid} && $r->{mode}==$pin->{mode};
   die "Vendor ancestor changed during operation: $vendor\n" if $s->{vendor_parent_records}{$d} && !$s->same($s->{vendor_parent_records}{$d},$r);
  }else{die "Unsafe parent directory: $d\n" unless $r->{type} eq 'dir' && $r->{uid}==0 && $r->{gid}==0 && ($r->{mode}&0022)==0;}
  last if $d eq '/';$d=dirname($d);
 }
}
sub make_dir {
 my($s,$p,$mode)=@_;my $r=$s->record($p);if($r->{type} ne 'absent'){die "Directory collision: $p\n" unless $r->{type} eq 'dir' && $r->{uid}==0 && $r->{gid}==0 && $r->{mode}==$mode;return;}
 $s->ancestors($p);mkdir($p,$mode) or die "Cannot create $p\n";chmod($mode,$p)==1 or die "Cannot set directory mode\n";$r=$s->record($p);die "Created directory ownership differs\n" unless $r->{uid}==0 && $r->{gid}==0 && $r->{mode}==$mode;$s->{created_dirs}{$p}=$r;
}
sub create_file {
 my($s,$p,$data,$mode)=@_;$s->ancestors($p);die "Existing target refused: $p\n" unless $s->record($p)->{type} eq 'absent';sysopen(my $f,$p,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,$mode) or die "Cannot create $p\n";binmode($f);print {$f} $data or die "Cannot write $p\n";chmod($mode,$f)==1 or die "Cannot set file mode\n";$f->flush;$f->sync or die "Cannot sync file\n";close($f) or die "Cannot close file\n";my $r=$s->record($p);die "Created file differs\n" unless $r->{uid}==0 && $r->{gid}==0 && $r->{mode}==$mode && $r->{sha256} eq sha256_hex($data);$s->{created_files}{$p}=$r;return $r;
}
sub payload {
 my($s,$portal)=@_;my %files;my $pkg=$s->{package};
 for my $spec (["payload/whm/index.cgi",'/usr/local/cpanel/whostmgr/docroot/cgi/parallax-nebula/index.cgi',0755],["payload/cpanel/index.live.php",'/usr/local/cpanel/base/frontend/jupiter/parallax-nebula/index.live.php',0644],["payload/registration/install.json",'/usr/local/cpanel/3rdparty/parallax-nebula/install.json',0644],["payload/shared/nebula.svg",'/usr/local/cpanel/3rdparty/parallax-nebula/parallax_nebula.svg',0644]){
  my($src,$dst,$mode)=@$spec;my($bytes)=$s->read_safe($pkg.'/'.$src,undef);$files{$s->path($dst)}={bytes=>$bytes,mode=>$mode};
 }
 my $registration=$JSON->decode($files{$s->path('/usr/local/cpanel/3rdparty/parallax-nebula/install.json')}{bytes});my $expected_registration=[{id=>$ID,key=>$ID,name=>'NEBULA',description=>'Open the NEBULA panel',type=>'link',group_id=>'software',order=>9500,uri=>'parallax-nebula/index.live.php',icon=>'parallax_nebula.svg',target=>'_self',featuremanager=>1,feature=>$ID}];die "Jupiter metadata must contain only the NEBULA navigation feature\n" unless $s->json($registration) eq $s->json($expected_registration);
 my $conf="name=$ID\nservice=whostmgr\nuser=nobody\nurl=/cgi/parallax-nebula/index.cgi\nentryurl=/cgi/parallax-nebula/index.cgi\ndisplayname=NEBULA\nacls=list-accts\ntarget=_self\n";
 my($source_conf)=$s->read_safe($pkg.'/payload/whm/parallax_nebula.conf',undef);die "WHM configuration must retain its unprivileged exact namespace\n" unless $source_conf eq $conf;
 $files{$s->path('/usr/local/cpanel/3rdparty/parallax-nebula/parallax_nebula.conf')}={bytes=>$conf,mode=>0644};
 $files{$s->path('/etc/parallax/nebula-cpanel/portal.json')}={bytes=>$s->json({schema_version=>1,portal_url=>$portal})."\n",mode=>0644};return \%files;
}
sub vendor_parents {
 my($s,$p)=@_;my $pins=$p->{vendor_parents};die "Reviewed vendor ancestor pins are required\n" unless ref($pins) eq 'HASH' && keys(%$pins)>=1 && keys(%$pins)<=64 && exists $pins->{'/usr/local/cpanel'};my %records;
 for my $path(sort keys %$pins){
  die "Vendor ancestor outside existing vendor namespace\n" unless $path=~m{\A/usr/local/cpanel(?:/[A-Za-z0-9_.-]+)*\z} && $path!~m{//|/\.\.?(?:/|\z)|(?:\A|/)parallax[-_]nebula(?:/|\z)};
  my $v=$pins->{$path};die "Malformed vendor ancestor pin\n" unless ref($v) eq 'HASH' && join(',',sort keys %$v) eq 'gid,mode,uid' && $JSON->encode($v->{uid}) eq '0' && $JSON->encode($v->{gid})=~/\A(?:0|[1-9][0-9]*)\z/ && $JSON->encode($v->{mode})=~/\A(?:0|[1-9][0-9]*)\z/ && $v->{mode}<=07777 && ($v->{mode}&0022)==0;
  my $d=$s->path($path);my $r=$s->record($d);die "Reviewed vendor ancestor differs: $path\n" unless $r->{type} eq 'dir' && $r->{uid}==0 && ($r->{mode}&0022)==0 && defined(abs_path($d)) && abs_path($d) eq $d && $r->{gid}==$v->{gid} && $r->{mode}==$v->{mode};$records{$d}=$r;
 }
 $s->{vendor_profile}=$p;$s->{vendor_parent_records}=\%records;
}
sub vendor_guard {
 my($s,$profile)=@_;$profile||=$s->{profile};$s->guard_records($s->{vendor_parent_records}) if $s->{vendor_parent_records};my $sources=$profile->{vendor_sources};die "Reviewed vendor sources are required\n" unless ref($sources) eq 'HASH' && keys(%$sources)>=3 && keys(%$sources)<=32;
 for my $path(@REQUIRED_VENDOR_SOURCES){die "Required vendor implementation pin is missing\n" unless exists $sources->{$path};}
 for my $path(sort keys %$sources){die "Public vendor source path is outside the reviewed namespace\n" unless $path=~m{\A/usr/local/cpanel/(?:Cpanel|Whostmgr)/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+\.pm\z} || $path eq '/usr/local/cpanel/bin/sprite_generator' || $path eq '/usr/local/cpanel/scripts/verify_api_spec_files' || $path eq '/usr/local/cpanel/3rdparty/perl/536/cpanel-lib/File/Copy/Recursive.pm';die "Invalid vendor source digest\n" unless ($sources->{$path}//'')=~/\A[a-f0-9]{64}\z/;my $p=$s->path($path);$s->ancestors($p);my $r=$s->record($p);die "Reviewed vendor implementation differs\n" unless $r->{type} eq 'file' && $r->{uid}==0 && $r->{gid}==0 && ($r->{mode}&0022)==0 && $r->{sha256} eq $sources->{$path};}
}
sub profile {
 my($s,$path)=@_;die "Reviewed host profile is required\n" unless $path;my($bytes,$record)=$s->read_safe($path,0600);my $p=eval{$JSON->decode($bytes)};die "Invalid host profile\n" unless ref($p) eq 'HASH' && $JSON->encode($p->{schema_version}) eq '2' && ($p->{app_id}//'') eq $ID && ref($p->{helpers}) eq 'HASH' && ref($p->{outputs}) eq 'HASH';
 die "Profile must record the normal new-registration notification\n" unless ref($p->{registration_notification}) eq 'JSON::PP::Boolean' && $p->{registration_notification};$s->vendor_parents($p);$s->vendor_guard($p);
 die "Profile must identify every helper\n" unless join(',',sort keys %{$p->{helpers}}) eq join(',',sort keys %HELPERS);
 for my $k(keys %HELPERS){die "Invalid helper digest\n" unless ($p->{helpers}{$k}//'')=~/\A[a-f0-9]{64}\z/;my $f=$s->record($s->path($HELPERS{$k}));$s->ancestors($s->path($HELPERS{$k}));die "Reviewed cPanel helper differs: $k\n" unless $f->{type} eq 'file' && $f->{uid}==0 && $f->{gid}==0 && ($f->{mode}&0022)==0 && ($f->{mode}&0111) && $f->{sha256} eq $p->{helpers}{$k};}
 die "Profile needs separate WHM and cPanel outputs\n" unless join(',',sort keys %{$p->{outputs}}) eq 'cpanel,whm' && ref($p->{outputs}{whm}) eq 'ARRAY' && @{$p->{outputs}{whm}}==1 && ref($p->{outputs}{cpanel}) eq 'ARRAY' && @{$p->{outputs}{cpanel}}>0 && @{$p->{outputs}{cpanel}}<=16;
 my %seen;for my $group(qw(whm cpanel)){for my $o(@{$p->{outputs}{$group}}){die "Invalid registration output\n" unless ref($o) eq 'HASH' && ($o->{sha256}//'')=~/\A[a-f0-9]{64}\z/ && defined($o->{mode}) && ($o->{mode}==0600 || $o->{mode}==0644);my $path=$o->{path}//'';die "Output outside exact own namespace\n" unless $group eq 'whm' ? $path eq '/var/cpanel/apps/parallax_nebula.conf' : ($path eq '/usr/local/cpanel/whostmgr/addonfeatures/parallax_nebula' || $path=~m{\A/usr/local/cpanel/base/frontend/jupiter/(?:[a-zA-Z0-9_-]+/)*(?:dynamicui_)?parallax_nebula\.(?:conf|svg|png)\z});die "Duplicate output path\n" if $seen{$path}++;$s->ancestors($s->path($path));}}
 $s->{profile}=$p;$s->{profile_record}=$record;$s->{profile_path}=$path;return $p;
}
sub stop_child {
 my($s,$pid)=@_;my $owned=sub{my $v=waitpid($pid,WNOHANG);die "Helper is no longer an owned child; signals refused\n" if $v<0;return $v==0;};return unless $owned->();
 kill 'TERM',$pid;my $end=time()+1;
 while(time()<$end){return unless $owned->();select undef,undef,undef,0.05;}
 return unless $owned->();kill 'KILL',$pid;$end=time()+2;
 while(time()<$end){return unless $owned->();select undef,undef,undef,0.05;}
 die "Installer-started helper could not be reaped; manual recovery required\n";
}
sub control_guard {
 my($s)=@_;$s->vendor_guard if $s->{profile};die "Reviewed profile changed during operation\n" if $s->{profile_record} && !$s->same($s->{profile_record},$s->record($s->{profile_path}));die "Installed manifest changed during operation\n" if $s->{manifest_record} && !$s->same($s->{manifest_record},$s->record($s->{manifest}));
}
sub config_parents {
 my($s)=@_;my $d=$s->path('/etc/parallax/nebula-cpanel');
 while(1){my $r=$s->record($d);if($r->{type} eq 'absent'){die "Missing configuration ancestor\n" unless $d eq $s->path('/etc/parallax/nebula-cpanel') || $d eq $s->path('/etc/parallax');}else{die "Portal configuration ancestors must be root-owned0755\n" unless $r->{type} eq 'dir' && $r->{uid}==0 && $r->{gid}==0 && ($r->{mode}==0755 || ($d eq '/' && $r->{mode}==0555));}last if $d eq '/';$d=dirname($d);}
}
sub command {
 my($s,$key,@args)=@_;$s->control_guard;my $path=$s->path($HELPERS{$key});$s->ancestors($path);my $r=$s->record($path);die "Helper changed\n" unless $r->{sha256} eq $s->{profile}{helpers}{$key};
 return $s->{runner}->($key,@args) if $s->{runner};
 my $err=gensym;my $pid=open3(my $in,my $out,$err,$path,@args);close $in;my $sel=IO::Select->new($out,$err);my %stream=(fileno($out)=>'stdout',fileno($err)=>'stderr');my %result=(stdout=>'',stderr=>'');my $deadline=time()+$s->{helper_timeout};
 while($sel->count){if(time()>$deadline){$s->stop_child($pid);die "Vendor helper timed out; manual recovery may be required\n";}for my $f($sel->can_read(0.05)){my $n=sysread($f,my $buf,8192);die "Cannot read helper response\n" unless defined $n;if(!$n){$sel->remove($f);close $f;next;}my $k=$stream{fileno($f)};$result{$k}.=$buf;if(length($result{$k})>65536){$s->stop_child($pid);die "Vendor helper response exceeds limit\n";}}}
 my $status;while(1){my $done=waitpid($pid,WNOHANG);if($done==$pid){$status=$?;last;}die "Installer-started helper disappeared\n" if $done<0;if(time()>$deadline){$s->stop_child($pid);die "Vendor helper timed out after closing streams; manual recovery may be required\n";}select undef,undef,undef,0.05;}
 $result{code}=($status&127)?255:($status>>8);return \%result;
}
sub registered {
 my($s)=@_;my $r=$s->command('registered','whostmgr',$ID);die "Cannot check exact WHM registration\n" unless $r->{code}==0 && $r->{stdout}=~/\A\s*([01])\s*\z/;return 0+$1;
}
sub outputs {
 my($s,$group,$required)=@_;my %result;for my $o(@{$s->{profile}{outputs}{$group}}){my $p=$s->path($o->{path});my $r=$s->record($p);if($r->{type} eq 'absent'){die "Registration output missing: $p\n" if $required;}else{die "Unknown registration output: $p\n" unless $r->{type} eq 'file' && $r->{uid}==0 && $r->{gid}==0 && $r->{mode}==$o->{mode} && $r->{sha256} eq $o->{sha256};}$result{$p}=$r;}return \%result;
}
sub guard_records {my($s,$records)=@_;for my $p(sort keys %$records){die "Concurrent target change refused: $p\n" unless $s->same($records->{$p},$s->record($p));}}
sub verify_created {
 my($s)=@_;$s->control_guard;$s->config_parents;$s->guard_records($s->{created_files});$s->guard_records($s->{created_dirs});
 my @paths=(keys %{$s->{created_files}},keys %{$s->{created_dirs}},map {map {$s->path($_->{path})} @{$s->{profile}{outputs}{$_}}} qw(whm cpanel));
 for my $d(keys %{$s->{created_dirs}}){next if $d eq $s->path('/etc/parallax');my %allowed=map {my $p=$_;dirname($p) eq $d ? (substr($p,length($d)+1)=>1):()} @paths;opendir(my $h,$d) or die "Cannot inspect own directory\n";my @entries=grep {$_ ne '.' && $_ ne '..'} readdir($h);closedir $h;die "Unknown file in plugin directory preserved\n" if grep {!$allowed{$_}} @entries;}
}
sub marker {return "NEBULA cPanel navigation package 0.1.3-dev\n";}
sub state_lock {
 my($s)=@_;my $d=$s->{state_dir};if($s->record($d)->{type} eq 'absent'){$s->make_dir($d,0700);$s->create_file($d.'/OWNER',$s->marker,0600);}else{my($owner)=$s->read_safe($d.'/OWNER',0600);die "Private state namespace is foreign\n" unless $owner eq $s->marker;die "Private state directory mode differs\n" unless $s->record($d)->{mode}==0700;}
 my $p=$d.'/.lock';if($s->record($p)->{type} eq 'absent'){$s->create_file($p,'',0600);}my($bytes,$rec)=$s->read_safe($p,0600);die "Foreign lock file\n" unless $bytes eq '';sysopen(my $f,$p,O_RDWR|O_NOFOLLOW) or die "Cannot open own lock\n";flock($f,LOCK_EX|LOCK_NB) or die "Another NEBULA plugin operation is active\n";$s->{lock}=$f;delete $s->{created_files}{$p};delete $s->{created_files}{$d.'/OWNER'};delete $s->{created_dirs}{$d};
}
sub receipt {
 my($s,$result)=@_;my $d=tempdir('operation-XXXXXXXX',DIR=>$s->{state_dir},CLEANUP=>0);chmod 0700,$d;$s->create_file($d.'/receipt.json',$s->json($result)."\n",0600);delete $s->{created_files}{$d.'/receipt.json'};return $d.'/receipt.json';
}
sub preflight {
 my($s,$files)=@_;$s->config_parents;my @n=getpwnam('nobody');die "Unprivileged nobody account is unavailable\n" unless @n && $n[2]>0;
 for my $p(qw(/usr/local/cpanel /usr/local/cpanel/base/frontend/jupiter /usr/local/cpanel/base/frontend/jupiter/dynamicui /usr/local/cpanel/whostmgr/docroot/cgi /usr/local/cpanel/3rdparty /var/cpanel/apps /var/lib /etc)){$s->ancestors($s->path($p).'/placeholder');}
 for my $p(keys %$files){die "Existing source target refused: $p\n" unless $s->record($p)->{type} eq 'absent';}
 for my $d(@{$s->{base_dirs}}){my $p=$s->path($d);next if $d eq '/etc/parallax' && $s->record($p)->{type} eq 'dir';die "Existing plugin directory refused: $p\n" unless $s->record($p)->{type} eq 'absent';}
 for my $g(qw(whm cpanel)){my $r=$s->outputs($g,0);die "Existing registration target refused\n" if grep {$_->{type} ne 'absent'} values %$r;}
 die "Existing WHM registration refused\n" if $s->registered;
}
sub plan {
 my($s,%a)=@_;my $url=$s->canonical_origin($a{portal_url});my $p=$a{profile};if(!$p){return {status=>'review-required',version=>$VERSION,portal_url=>$url,required_profile=>JSON::PP::true,changes=>JSON::PP::false};}
 $s->profile($p);my $files=$s->payload($url);$s->preflight($files);return {status=>'ready',version=>$VERSION,portal_url=>$url,changes=>JSON::PP::false,registration_notification=>JSON::PP::true,source_paths=>[sort keys %$files],registration_outputs=>[map {map {$_->{path}} @{$s->{profile}{outputs}{$_}}} qw(whm cpanel)]};
}
sub remove_created {
 my($s)=@_;$s->verify_created;for my $p(sort keys %{$s->{created_files}}){$s->verify_created;unlink($p) or die "Cannot remove own file\n";delete $s->{created_files}{$p};}
 for my $p(sort {length($b)<=>length($a)} keys %{$s->{created_dirs}}){$s->verify_created;rmdir($p) or die "Own directory is not empty; preserved\n";delete $s->{created_dirs}{$p};}
}
sub rollback {
 my($s)=@_;$s->verify_created;my %current;for my $g(qw(whm cpanel)){$current{$g}=$s->outputs($g,0);$s->guard_records($s->{known_regs}{$g}) if $s->{known_regs}{$g};die "Unowned concurrent registration preserved\n" if !$s->{registration_started}{$g} && grep {$_->{type} ne 'absent'} values %{$current{$g}};}
 for my $g(qw(cpanel whm)){
  next unless grep {$_->{type} ne 'absent'} values %{$current{$g}};
  $s->verify_created;$s->guard_records($current{whm});$s->guard_records($current{cpanel});
  my $r=$g eq 'cpanel'?$s->command('uninstall',$s->path('/usr/local/cpanel/3rdparty/parallax-nebula'),'--theme=jupiter'):$s->command('unregister',$ID);
  die "Registration rollback helper failed\n" unless $r->{code}==0;$current{$g}=$s->outputs($g,0);die "Own registration remains after rollback\n" if grep {$_->{type} ne 'absent'} values %{$current{$g}};
 }
 die "WHM registration remains\n" if $s->registered;$s->remove_created;
}
sub install {
 my($s,%a)=@_;die "New registration sends an administrative notification; explicit acknowledgement is required\n" unless $a{acknowledge_registration_notification};umask 0077;my $url=$s->canonical_origin($a{portal_url});$s->profile($a{profile});my $files=$s->payload($url);
 if($s->record($s->{manifest})->{type} ne 'absent'){my($d)=$s->read_safe($s->{manifest},0600);my $m=$JSON->decode($d);die "Installed package differs\n" unless $m->{version} eq $VERSION && $m->{portal_url} eq $url && $m->{profile_sha256} eq $s->{profile_record}{sha256};$s->guard_records($m->{files});$s->guard_records($m->{dirs});$s->guard_records($m->{registrations});die "WHM registration missing\n" unless $s->registered;return {status=>'already-installed',version=>$VERSION};}
 $s->preflight($files);$s->state_lock;my $result;eval{
  for my $d(@{$s->{base_dirs}}){$s->make_dir($s->path($d),0755);}
  for my $p(sort keys %$files){$s->create_file($p,$files->{$p}{bytes},$files->{$p}{mode});}
  $s->verify_created;die "Concurrent WHM registration refused\n" if $s->registered || grep {$_->{type} ne 'absent'} values %{$s->outputs('whm',0)};$s->{registration_started}{whm}=1;my $r=$s->command('register',$s->path('/usr/local/cpanel/3rdparty/parallax-nebula/parallax_nebula.conf'));$s->{known_regs}{whm}=$s->outputs('whm',0);die "WHM registration helper failed\n" unless $r->{code}==0 && $s->registered;$s->{known_regs}{whm}=$s->outputs('whm',1);
  $s->verify_created;$s->guard_records($s->{known_regs}{whm});die "Concurrent Jupiter registration refused\n" if grep {$_->{type} ne 'absent'} values %{$s->outputs('cpanel',0)};$s->{registration_started}{cpanel}=1;$r=$s->command('install',$s->path('/usr/local/cpanel/3rdparty/parallax-nebula'),'--theme=jupiter');$s->{known_regs}{cpanel}=$s->outputs('cpanel',0);die "Jupiter registration helper failed\n" unless $r->{code}==0;$s->{known_regs}{cpanel}=$s->outputs('cpanel',1);
  $s->verify_created;$s->guard_records($s->{known_regs}{whm});$s->guard_records($s->{known_regs}{cpanel});
  my %regs=(%{$s->{known_regs}{whm}},%{$s->{known_regs}{cpanel}});my $m={schema_version=>1,version=>$VERSION,portal_url=>$url,profile_sha256=>$s->{profile_record}{sha256},files=>$s->{created_files},dirs=>$s->{created_dirs},registrations=>\%regs};$s->create_file($s->{manifest},$s->json($m)."\n",0600);delete $s->{created_files}{$s->{manifest}};$result={status=>'installed',version=>$VERSION,portal_url=>$url};1;
 } or do {my $error=$@||'Unknown installation failure';my $rolled=eval{$s->rollback;1};my $receipt=$s->receipt({status=>$rolled?'rolled-back':'manual-recovery',error=>$error,recovery_error=>$rolled?'':$@,created_files=>$s->{created_files},created_dirs=>$s->{created_dirs}});die "Installation failed; ".($rolled?'known changes rolled back':'unknown state preserved').". Receipt: $receipt\n";};
 $result->{receipt}=$s->receipt($result);return $result;
}
sub uninstall {
 my($s,%a)=@_;umask 0077;$s->profile($a{profile});$s->state_lock;my($bytes,$manifest_record)=$s->read_safe($s->{manifest},0600);$s->{manifest_record}=$manifest_record;my $m=$JSON->decode($bytes);die "Unknown installed manifest\n" unless $m->{schema_version}==1 && $m->{version} eq $VERSION && $m->{profile_sha256} eq $s->{profile_record}{sha256};
 my $files=$s->payload($s->canonical_origin($m->{portal_url}));die "Unexpected installed file set\n" unless join(',',sort keys %$files) eq join(',',sort keys %{$m->{files}});for my $p(keys %$files){die "Installed file is not this package\n" unless $m->{files}{$p}{sha256} eq sha256_hex($files->{$p}{bytes}) && $m->{files}{$p}{mode}==$files->{$p}{mode};}
 my %allowed_dirs=map {$s->path($_)=>1} @{$s->{base_dirs}};die "Unexpected installed directory set\n" if grep {!$allowed_dirs{$_}} keys %{$m->{dirs}};my %allowed_regs=map {map {$s->path($_->{path})=>1} @{$s->{profile}{outputs}{$_}}} qw(whm cpanel);die "Unexpected registration path set\n" unless join(',',sort keys %allowed_regs) eq join(',',sort keys %{$m->{registrations}});$s->{created_files}=$m->{files};$s->{created_dirs}=$m->{dirs};$s->verify_created;$s->guard_records($m->{registrations});my %regs=%{$m->{registrations}};
 eval{
  for my $g(qw(cpanel whm)){$s->verify_created;$s->guard_records(\%regs);my $r=$g eq 'cpanel'?$s->command('uninstall',$s->path('/usr/local/cpanel/3rdparty/parallax-nebula'),'--theme=jupiter'):$s->command('unregister',$ID);die "Unregistration helper failed\n" unless $r->{code}==0;for my $o(@{$s->{profile}{outputs}{$g}}){my $p=$s->path($o->{path});die "Registration target was not removed\n" unless $s->record($p)->{type} eq 'absent';$regs{$p}={type=>'absent'};}}
  die "WHM registration remains\n" if $s->registered;$s->verify_created;$s->guard_records(\%regs);my $mr=$s->record($s->{manifest});$s->remove_created;die "Manifest changed during removal\n" unless $s->same($mr,$s->record($s->{manifest}));unlink($s->{manifest}) or die "Cannot remove own manifest\n";1;
 } or do {my $receipt=$s->receipt({status=>'manual-recovery',operation=>'uninstall',error=>$@});die "Uninstall stopped; unknown state preserved. Receipt: $receipt\n";};
 return {status=>'uninstalled',version=>$VERSION,receipt=>$s->receipt({status=>'uninstalled',version=>$VERSION})};
}
1;

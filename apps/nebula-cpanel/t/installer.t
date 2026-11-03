use strict;use warnings;use Test::More;use FindBin;use lib "$FindBin::RealBin/../lib";use Parallax::NebulaCPanel::Installer;use File::Temp qw(tempdir);use File::Path qw(make_path remove_tree);use File::Copy qw(copy);use File::Find;use Digest::SHA qw(sha256_hex);use JSON::PP;use Fcntl qw(:mode);
plan skip_all=>'Run the isolated fixtures as Linux root' unless $>==0;
my $J=JSON::PP->new->canonical;my @roots;my $package="$FindBin::RealBin/..";
sub write_file {my($p,$b,$mode)=@_;open my $f,'>',$p or die $!;binmode $f;print {$f} $b;close $f;chmod($mode//$mode,$p) if defined $mode;}
sub fixture {
 umask 0022;my $root=tempdir('nebula-cpanel-test-XXXXXXXX',DIR=>'/run',CLEANUP=>0);chmod 0755,$root;push @roots,$root;
 for my $p(qw(/usr/local/cpanel/bin /usr/local/cpanel/scripts /usr/local/cpanel/base/frontend/jupiter/dynamicui /usr/local/cpanel/whostmgr/docroot/cgi /usr/local/cpanel/whostmgr/addonfeatures /usr/local/cpanel/Cpanel/AppConfig /usr/local/cpanel/Cpanel/Plugin /usr/local/cpanel/Cpanel/Themes/Serializer /usr/local/cpanel/3rdparty /var/cpanel/apps /var/lib /etc /pkg/payload/whm /pkg/payload/cpanel /pkg/payload/shared /pkg/payload/registration)){make_path($root.$p,{mode=>0755});}
 for my $f(qw(payload/whm/index.cgi payload/whm/parallax_nebula.conf payload/cpanel/index.live.php payload/shared/nebula.svg payload/registration/install.json)){copy($package.'/'.$f,$root.'/pkg/'.$f) or die $!;chmod 0644,$root.'/pkg/'.$f;}
 my $stub=<<'STUB';
#!/usr/bin/perl
use strict;use warnings;use JSON::PP;use File::Basename qw(basename);
my $root='FIXTURE_ROOT';my $key=basename($0);my $spec={};if(-f "$root/scenario.json"){open my $f,'<',"$root/scenario.json" or die;local $/;$spec=decode_json(<$f>);close $f;}
open my $log,'>>',"$root/calls.jsonl" or die;print {$log} encode_json([$key,@ARGV])."\n";close $log;
my $whm="$root/var/cpanel/apps/parallax_nebula.conf";my $cp="$root/usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_parallax_nebula.conf";my $feature="$root/usr/local/cpanel/whostmgr/addonfeatures/parallax_nebula";
sub put {my($p,$b,$m)=@_;open my $f,'>',$p or die;print {$f} $b;close $f;chmod $m,$p;}
if(($spec->{hang}//'') eq $key){$SIG{TERM}='IGNORE';close STDOUT;close STDERR;sleep 20;exit 0;}
if($key eq 'is_registered_with_appconfig'){die unless join('|',@ARGV) eq 'whostmgr|parallax_nebula';print((-f $whm?1:0)."\n");exit 0;}
if($key eq 'register_appconfig'){die unless @ARGV==1 && $ARGV[0] eq "$root/usr/local/cpanel/3rdparty/parallax-nebula/parallax_nebula.conf";open my $f,'<',$ARGV[0] or die;local $/;my $b=<$f>;close $f;put($whm,$b,0600);}
elsif($key eq 'install_plugin'){die unless join('|',@ARGV) eq "$root/usr/local/cpanel/3rdparty/parallax-nebula|--theme=jupiter";put($cp,$spec->{unknown_output}?"foreign post state\n":"fixture own Jupiter registration\n",0644);put($feature,"parallax_nebula:NEBULA\n",0600);if($spec->{replace_whm_inode}){open my $f,'<',$whm or die;local $/;my $b=<$f>;close $f;rename($whm,"$root/old-whm-operator-copy") or die;put($whm,$b,0600);}if($spec->{mutate_source}){put("$root/etc/parallax/nebula-cpanel/portal.json","operator edit\n",0644);}}
elsif($key eq 'unregister_appconfig'){die unless join('|',@ARGV) eq 'parallax_nebula';unlink $whm or die;}
elsif($key eq 'uninstall_plugin'){die unless join('|',@ARGV) eq "$root/usr/local/cpanel/3rdparty/parallax-nebula|--theme=jupiter";unlink $cp or die;unlink $feature or die;if($spec->{mutate_manifest}){put("$root/var/lib/parallax-nebula-cpanel/state.json","operator manifest edit\n",0600);}}
else{die 'unexpected helper';}
exit(($spec->{fail}//'') eq $key?1:0);
STUB
 $stub=~s/FIXTURE_ROOT/$root/g; # variable replacement, no shell
 my %helpers=(register=>'register_appconfig',unregister=>'unregister_appconfig',registered=>'is_registered_with_appconfig',install=>'install_plugin',uninstall=>'uninstall_plugin');my %digests;
 for my $k(keys %helpers){my $path=$root.'/usr/local/cpanel/'.($k=~/^(?:un)?install$/?'scripts/':'bin/').$helpers{$k};write_file($path,$stub,0755);$digests{$k}=sha256_hex($stub);}
 my $s=Parallax::NebulaCPanel::Installer->new(package=>$root.'/pkg',fixture=>1,fixture_root=>$root);my $files=$s->payload('https://nebula.example');my $conf=$files->{$root.'/usr/local/cpanel/3rdparty/parallax-nebula/parallax_nebula.conf'}{bytes};
 my %vendor_sources;for my $path(qw(/usr/local/cpanel/Cpanel/AppConfig/Register.pm /usr/local/cpanel/Cpanel/Plugin/Install.pm /usr/local/cpanel/Cpanel/Themes/Serializer/DynamicUI.pm)){my $bytes="# Original offline vendor stub: $path\n";write_file($root.$path,$bytes,0644);$vendor_sources{$path}=sha256_hex($bytes);}
 my %vendor_parents;find({no_chdir=>1,wanted=>sub{my $path=$File::Find::name;return unless -d $path;my @st=lstat($path);my $key=substr($path,length($root));$vendor_parents{$key}={uid=>0,gid=>$st[5],mode=>S_IMODE($st[2])};}},$root.'/usr/local/cpanel');
 my $profile={schema_version=>2,app_id=>'parallax_nebula',helpers=>\%digests,vendor_sources=>\%vendor_sources,vendor_parents=>\%vendor_parents,registration_notification=>JSON::PP::true,outputs=>{whm=>[{path=>'/var/cpanel/apps/parallax_nebula.conf',sha256=>sha256_hex($conf),mode=>0600}],cpanel=>[{path=>'/usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_parallax_nebula.conf',sha256=>sha256_hex("fixture own Jupiter registration\n"),mode=>0644},{path=>'/usr/local/cpanel/whostmgr/addonfeatures/parallax_nebula',sha256=>sha256_hex("parallax_nebula:NEBULA\n"),mode=>0600}]}};
 write_file($root.'/profile.json',$J->encode($profile),0600);return($root,$s,$root.'/profile.json');
}
sub calls {my($r)=@_;return [] unless -f "$r/calls.jsonl";open my $f,'<',"$r/calls.jsonl";my @a=map {decode_json($_)} <$f>;close $f;return \@a;}
sub run_install {my($s,$p)=@_;return $s->install(portal_url=>'https://nebula.example',profile=>$p,acknowledge_registration_notification=>1);}
{
 my($r,$s,$p)=fixture();my $plan=$s->plan(portal_url=>'https://nebula.example:443',profile=>$p);is($plan->{status},'ready','preflight ready with canonical443 normalization');ok(!-e "$r/var/lib/parallax-nebula-cpanel",'plan performs no state write');my $result=run_install($s,$p);is($result->{status},'installed','real local stub helpers install both separate entries');is((stat "$r/etc/parallax/nebula-cpanel/portal.json")[2]&0777,0644,'public nonsecret config0644');my $conf=do{open my$f,'<',"$r/var/cpanel/apps/parallax_nebula.conf";local$/;<$f>};like($conf,qr/^user=nobody$/m,'WHM execution explicitly unprivileged');like($conf,qr/^acls=list-accts$/m,'WHM limited reseller ACL');unlike($conf,qr/^user=root$/m,'no root CGI default');my $again=Parallax::NebulaCPanel::Installer->new(package=>"$r/pkg",fixture=>1,fixture_root=>$r);is(run_install($again,$p)->{status},'already-installed','exact installed state is idempotent');undef $s;my $un=Parallax::NebulaCPanel::Installer->new(package=>"$r/pkg",fixture=>1,fixture_root=>$r);is($un->uninstall(profile=>$p)->{status},'uninstalled','exact known files and both entries uninstall');ok(!-e "$r/etc/parallax/nebula-cpanel" && !-e "$r/var/cpanel/apps/parallax_nebula.conf",'only owned app/config removed');ok(-d "$r/usr/local/cpanel/base/frontend/jupiter/dynamicui",'vendor directory preserved');my $c=calls($r);ok((grep {$_->[0] eq 'install_plugin' && $_->[2] eq '--theme=jupiter'} @$c),'explicit Jupiter vendor invocation');
}
{
 my($r,$s,$p)=fixture();for my $u('http://nebula.example','https://user:pass@nebula.example','https://nebula.example/dashboard','https://nebula.example?x=1','https://nebula.example#x','https://NEBULA.example',"https://nebula.example\n",'https://127.0.0.1','https://0x7f.0.0.1','https://127.1','https://nebula..example','https://-bad.example','https://nebula.example:444'){ok(!eval{$s->canonical_origin($u);1},'unsafe/noncanonical portal rejected');}is($s->canonical_origin('https://nebula.example'),'https://nebula.example','canonical origin accepted');
}
{
 my($r,$s,$p)=fixture();make_path("$r/etc/parallax/nebula-cpanel");write_file("$r/etc/parallax/nebula-cpanel/portal.json","foreign\n",0644);ok(!eval{run_install($s,$p);1},'foreign config collision refused');is_deeply(calls($r),[],'no vendor call on foreign source collision');
}
{
 my($r,$s,$p)=fixture();symlink('/tmp',"$r/etc/parallax") or die $!;ok(!eval{run_install($s,$p);1},'symlinked own parent refused before helper');is_deeply(calls($r),[],'symlink refusal has no registration side effects');
}
{
 my($r,$s,$p)=fixture();write_file("$r/scenario.json",$J->encode({fail=>'install_plugin'}),0600);ok(!eval{run_install($s,$p);1},'failed Jupiter registration reported');like($@,qr/known changes rolled back/,'known registration failure rolls back');ok(!-e "$r/var/cpanel/apps/parallax_nebula.conf" && !-e "$r/usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_parallax_nebula.conf" && !-e "$r/etc/parallax/nebula-cpanel/portal.json",'only known new registration/files removed');
}
{
 my($r,$s,$p)=fixture();write_file("$r/scenario.json",$J->encode({fail=>'install_plugin',unknown_output=>1}),0600);ok(!eval{run_install($s,$p);1},'unknown partial registration rejected');like($@,qr/unknown state preserved/,'unknown registration requires manual recovery');ok(-f "$r/var/cpanel/apps/parallax_nebula.conf" && -f "$r/etc/parallax/nebula-cpanel/portal.json",'no partial rollback when output ownership unknown');ok(!(grep {$_->[0]=~/^(?:uninstall_plugin|unregister_appconfig)$/} @{calls($r)}),'unknown entry never unregistered');
}
{
 my($r,$s,$p)=fixture();write_file("$r/scenario.json",$J->encode({fail=>'install_plugin',mutate_source=>1}),0600);ok(!eval{run_install($s,$p);1},'concurrent source edit interrupts rollback');like($@,qr/unknown state preserved/,'concurrent state left for review');open my$f,'<',"$r/etc/parallax/nebula-cpanel/portal.json";is(<$f>,"operator edit\n",'operator edit preserved');close$f;ok(-f "$r/var/cpanel/apps/parallax_nebula.conf",'no registration removed before combined source preflight');
}
{
 my($r,$s,$p)=fixture();run_install($s,$p);undef $s;write_file("$r/usr/local/cpanel/base/frontend/jupiter/parallax-nebula/operator-note.txt","leave me\n",0644);my $u=Parallax::NebulaCPanel::Installer->new(package=>"$r/pkg",fixture=>1,fixture_root=>$r);ok(!eval{$u->uninstall(profile=>$p);1},'uninstall refuses unknown directory entry before mutation');ok(-f "$r/var/cpanel/apps/parallax_nebula.conf" && -f "$r/etc/parallax/nebula-cpanel/portal.json",'registration and own source retained on unknown directory preflight');
}
{
 my($r,$s,$p)=fixture();write_file("$r/usr/local/cpanel/scripts/install_plugin","foreign helper\n",0755);ok(!eval{run_install($s,$p);1},'changed vendor helper pin refused');is_deeply(calls($r),[],'changed helper causes no calls');
}
{
 my($r,$s,$p)=fixture();write_file("$r/scenario.json",$J->encode({fail=>'install_plugin',replace_whm_inode=>1}),0600);ok(!eval{run_install($s,$p);1},'same-content registration replacement stops rollback');like($@,qr/unknown state preserved/,'registration inode replacement preserved');ok(-f "$r/etc/parallax/nebula-cpanel/portal.json" && -f "$r/var/cpanel/apps/parallax_nebula.conf",'no partial source or registration rollback after inode replacement');ok(!(grep {$_->[0]=~/^(?:uninstall_plugin|unregister_appconfig)$/} @{calls($r)}),'no unregister called after known registration inode changed');
}
{
 my($r,$s,$p)=fixture();write_file("$r/scenario.json",$J->encode({hang=>'is_registered_with_appconfig'}),0600);my $fast=Parallax::NebulaCPanel::Installer->new(package=>"$r/pkg",fixture=>1,fixture_root=>$r,fixture_timeout=>0.15);my $t=Time::HiRes::time();ok(!eval{$fast->plan(portal_url=>'https://nebula.example',profile=>$p);1},'helper closing streams and ignoring TERM times out');cmp_ok(Time::HiRes::time()-$t,'<',4,'own helper timeout including KILL/reap is bounded');ok(!-e "$r/var/lib/parallax-nebula-cpanel",'timed out plan creates no install state');
}
{
 my($r,$s,$p)=fixture();ok(!eval{$s->stop_child($$);1},'signals refused for a PID that is not an owned child');like($@,qr/signals refused/,'nonchild PID refusal is explicit');
}
{
 my($r,$s,$p)=fixture();write_file("$r/pkg/payload/registration/install.json",'[{"id":"foreign_plugin"}]',0644);ok(!eval{run_install($s,$p);1},'Jupiter metadata cannot register another plugin');is_deeply(calls($r),[],'foreign metadata never reaches vendor helpers');
}
{
 my($r,$s,$p)=fixture();write_file("$r/pkg/payload/whm/parallax_nebula.conf","name=parallax_nebula\nuser=root\n",0644);ok(!eval{run_install($s,$p);1},'WHM payload cannot change execution to root');is_deeply(calls($r),[],'root CGI mutation never reaches helpers');
}
{
 my($r,$s,$p)=fixture();make_path("$r/etc/parallax");chmod 0700,"$r/etc/parallax";ok(!eval{$s->plan(portal_url=>'https://nebula.example',profile=>$p);1},'check refuses unreadable configuration ancestor');is_deeply(calls($r),[],'config readability mismatch refused before any helper');
}
{
 my($r,$s,$p)=fixture();run_install($s,$p);undef$s;write_file("$r/scenario.json",$J->encode({mutate_manifest=>1}),0600);my$u=Parallax::NebulaCPanel::Installer->new(package=>"$r/pkg",fixture=>1,fixture_root=>$r);ok(!eval{$u->uninstall(profile=>$p);1},'concurrent installed manifest edit stops later mutations');ok(-f "$r/var/cpanel/apps/parallax_nebula.conf" && -f "$r/etc/parallax/nebula-cpanel/portal.json",'WHM registration and application files retained after manifest edit');ok(!(grep {$_->[0] eq 'unregister_appconfig'} @{calls($r)}),'foreign manifest edit prevents WHM unregister');
}
{
 my($r,$s,$p)=fixture();ok(!eval{$s->install(portal_url=>'https://nebula.example',profile=>$p);1},'future install requires explicit normal-registration notification acknowledgement');like($@,qr/explicit acknowledgement/,'notification side effect is stated before mutations');is_deeply(calls($r),[],'missing acknowledgement performs no vendor calls');ok(!-e "$r/var/lib/parallax-nebula-cpanel",'missing acknowledgement creates no state');
}
{
 my($r,$s,$p)=fixture();write_file("$r/usr/local/cpanel/Cpanel/Plugin/Install.pm","operator changed public module\n",0644);ok(!eval{run_install($s,$p);1},'changed public implementation pin refused');is_deeply(calls($r),[],'module mismatch performs no vendor calls');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};delete$v->{vendor_sources}{'/usr/local/cpanel/Cpanel/Plugin/Install.pm'};write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'missing required implementation pin refused');is_deeply(calls($r),[],'missing module pin performs no calls');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};$v->{outputs}{cpanel}[1]{path}='/usr/local/cpanel/whostmgr/addonfeatures/foreign';write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'addonfeatures exception allows only the exact own filename');is_deeply(calls($r),[],'foreign Feature Manager name never reaches helper');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};$v->{vendor_sources}{'/etc/foreign.pm'}='a'x64;write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'vendor source pins cannot read arbitrary configuration paths');is_deeply(calls($r),[],'foreign source path causes no calls');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};$v->{registration_notification}=JSON::PP::false;write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'profile cannot hide this vendor notification behavior');is_deeply(calls($r),[],'false notification declaration causes no calls');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};my$d="$r/usr/local/cpanel";chown(0,12345,$d)==1 or die$!;chmod 0711,$d;$v->{vendor_parents}{'/usr/local/cpanel'}={uid=>0,gid=>12345,mode=>0711};write_file($p,$J->encode($v),0600);
 is($s->plan(portal_url=>'https://nebula.example',profile=>$p)->{status},'ready','exact reviewed root:nonroot0711 vendor directory accepted');is((stat$d)[5],12345,'vendor group unchanged by check');is((stat$d)[2]&07777,0711,'vendor mode unchanged by check');is(run_install($s,$p)->{status},'installed','own plugin installs beneath protected reviewed vendor group');is((stat"$d/3rdparty/parallax-nebula")[5],0,'new own target retains root group');is((stat"$r/etc/parallax/nebula-cpanel")[2]&07777,0755,'portal directory remains exact0755');undef$s;my$u=Parallax::NebulaCPanel::Installer->new(package=>"$r/pkg",fixture=>1,fixture_root=>$r);is($u->uninstall(profile=>$p)->{status},'uninstalled','known scoped vendor layout uninstalls only own entry');is((stat$d)[5],12345,'vendor group preserved after removal');is((stat$d)[2]&07777,0711,'vendor mode preserved after removal');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};chmod 0771,"$r/usr/local/cpanel";$v->{vendor_parents}{'/usr/local/cpanel'}{mode}=0771;write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'writable vendor ancestor refused even when profile matches');is_deeply(calls($r),[],'writable vendor parent causes no helper call');
}
{
 my($r,$s,$p)=fixture();chown(65534,0,"$r/usr/local/cpanel")==1 or die$!;ok(!eval{run_install($s,$p);1},'nonroot vendor directory owner refused');is_deeply(calls($r),[],'nonroot vendor parent causes no helper call');
}
{
 my($r,$s,$p)=fixture();rename("$r/usr/local/cpanel","$r/usr/local/cpanel-original")or die$!;symlink("$r/usr/local/cpanel-original","$r/usr/local/cpanel")or die$!;ok(!eval{run_install($s,$p);1},'symlink vendor ancestor refused');is_deeply(calls($r),[],'vendor symlink causes no helper call');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};$v->{vendor_parents}{'/usr/local/cpanel'}{gid}=12345;write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'profile vendor-GID drift refused');is_deeply(calls($r),[],'GID mismatch causes no helper call');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};$v->{vendor_parents}{'/usr/local/cpanel'}{mode}=0711;write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'profile vendor-mode drift refused');is_deeply(calls($r),[],'mode mismatch causes no helper call');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};delete$v->{vendor_parents}{'/usr/local/cpanel/Cpanel/Plugin'};write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'unreviewed vendor ancestor cannot fall back to generic safe-mode check');is_deeply(calls($r),[],'missing ancestor pin causes no helper call');
}
{
 my($r,$s,$p)=fixture();$s->profile($p);chmod 0711,"$r/usr/local/cpanel";ok(!eval{$s->control_guard;1},'live vendor parent mode edit fails operation guard');is_deeply(calls($r),[],'live parent edit invokes no helper');
}
{
 my($r,$s,$p)=fixture();make_path("$r/etc/parallax",{mode=>0755});chown(0,12345,"$r/etc/parallax")==1 or die$!;ok(!eval{run_install($s,$p);1},'vendor exception does not weaken portal root-group requirement');is_deeply(calls($r),[],'foreign portal group causes no helper call');
}
{
 my($r,$s,$p)=fixture();my$v=do{open my$f,'<',$p;local$/;decode_json(<$f>)};$v->{vendor_parents}{'/usr/local/cpanel/3rdparty/parallax-nebula'}={uid=>0,gid=>12345,mode=>0711};write_file($p,$J->encode($v),0600);ok(!eval{run_install($s,$p);1},'profile cannot convert own namespace into a vendor exception');is_deeply(calls($r),[],'own-namespace exception performs no helper call');
}

{
 package RootMetadataFixture;our @ISA=('Parallax::NebulaCPanel::Installer');
 sub record {my($s,$p)=@_;my$r=$s->SUPER::record($p);return $p eq '/' ? {%$r,%{$s->{root_metadata}}} : $r;}
 package main;
 my($r,$s,$p)=fixture();bless$s,'RootMetadataFixture';$s->{root_metadata}={mode=>0555};
 is($s->plan(portal_url=>'https://nebula.example',profile=>$p)->{status},'ready','canonical root0555 accepts the full installer preflight');
 is(run_install($s,$p)->{status},'installed','canonical root0555 supports own installation without changing root');
 is((stat"$r/etc")[2]&07777,0755,'root555 exception leaves etc0755');
 is((stat"$r/etc/parallax/nebula-cpanel")[2]&07777,0755,'root555 exception leaves own portal0755');
 undef$s;my$u=RootMetadataFixture->new(package=>"$r/pkg",fixture=>1,fixture_root=>$r);$u->{root_metadata}={mode=>0555};
 is($u->uninstall(profile=>$p)->{status},'uninstalled','canonical root0555 supports known own uninstall');
 for my$case (['writable',{mode=>0775}],['nonroot owner',{uid=>65534}],['nonroot group',{gid=>65534}],['symlink',{type=>'symlink'}],['other mode',{mode=>0711}]){
  $u->{root_metadata}=$case->[1];ok(!eval{$u->config_parents;1},"canonical root $case->[0] refused");
 }
 $u->{root_metadata}={mode=>0555};chmod 0555,"$r/etc";
 ok(!eval{$u->config_parents;1},'root555 exception does not permit etc0555');chmod 0755,"$r/etc";
}
for my $r(@roots){die 'Unsafe fixture cleanup' unless $r=~m{\A/run/nebula-cpanel-test-[A-Za-z0-9_]+\z} && !-l $r && (stat($r))[4]==0;remove_tree($r,{safe=>1});}
done_testing();

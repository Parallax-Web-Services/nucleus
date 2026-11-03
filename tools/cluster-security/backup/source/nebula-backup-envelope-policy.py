#!/usr/bin/env python3
"""Pure backup-envelope policy/command construction. NO subprocess, key generation or I/O.
The eventual snapshot/crypto executor must supply verified metadata from isolated GPG,
hold input/output FDs, preserve private receipts, and enforce all original cluster guards.
"""
from __future__ import annotations
import hashlib,json,re
from pathlib import PurePosixPath
MAX_SNAPSHOT=512*1024**2
MAX_OTHER=128*1024**2
MAX_CIPHERTEXT=1024**3
COMBINED_TARRAGON_BUDGET=40*1024**3
TARGETS=('Tarragon','Slipstream')
class Refused(RuntimeError):pass
def need(ok,code):
 if not ok:raise Refused(code)
def fingerprint(value):
 need(type(value) is str and re.fullmatch(r'[A-F0-9]{40}',value) is not None,'exact_public_fingerprint_required')
 return value
def pins(value):
 need(type(value) is dict and set(value)==set(TARGETS),'two_owned_recovery_recipients_required')
 result={}
 for target in TARGETS:
  p=value[target];need(type(p) is dict and set(p)=={'primary_fingerprint','encryption_subkey_fingerprint'},'recipient_pin_fields')
  result[target]={k:fingerprint(v) for k,v in p.items()}
 primary={v['primary_fingerprint'] for v in result.values()};sub={v['encryption_subkey_fingerprint'] for v in result.values()}
 need(len(primary)==len(sub)==2 and primary.isdisjoint(sub),'recipients_must_be_independent_distinct_keys')
 return result
def parsed_key(colons,expected,now):
 """Parse public GPG --with-colons metadata; never accept secret records or aliases."""
 need(type(colons) is str and len(colons)<=65536 and type(now) is int,'bounded_public_key_metadata_required')
 primary=fingerprint(expected['primary_fingerprint']);subkey=fingerprint(expected['encryption_subkey_fingerprint'])
 rows=[line.split(':') for line in colons.splitlines() if line]
 allowed={'pub','uid','sub','fpr','grp','tru'}
 need(all(r[0] in allowed for r in rows),'secret_or_unrecognized_key_record')
 key_rows=[r for r in rows if r[0] in ['pub','sub']]
 need([r[0] for r in key_rows]==['pub','sub'],'one_primary_and_one_encryption_subkey_required')
 current=None;found={}
 for row in rows:
  kind=row[0]
  if kind in ['pub','sub']:
   need(len(row)>11 and row[1] not in ['r','e','d','i'],'recipient_key_unusable')
   need(row[2] in ['255','256'] and row[3]==('22' if kind=='pub' else '18'),'reviewed_ed25519_cv25519_profile_required')
   need(row[5].isdecimal() and int(row[5])<=now,'recipient_key_created_in_future')
   need(row[6].isdecimal() and int(row[6])>now+30*86400,'recipient_key_expiry_margin_required')
   need(row[11] and 'D' not in row[11],'disabled_recipient_key')
   if kind=='sub':need('e' in row[11].lower(),'encryption_capable_subkey_required')
   current=kind
  elif kind=='fpr':
   need(current is not None and len(row)>9 and current not in found,'unexpected_public_key_fingerprint')
   found[current]=fingerprint(row[9]);current=None
 need(found=={'pub':primary,'sub':subkey},'recipient_public_key_pin_mismatch')
 return {'primary_fingerprint':primary,'encryption_subkey_fingerprint':subkey}
def public_key_file(raw):
 need(type(raw) is bytes and 0<len(raw)<=65536,'bounded_public_key_file_required')
 need(raw.count(b'-----BEGIN PGP PUBLIC KEY BLOCK-----')==1 and raw.count(b'-----END PGP PUBLIC KEY BLOCK-----')==1,'one_public_key_block_required')
 need(b'PRIVATE KEY' not in raw and b'SECRET KEY' not in raw,'no_private_key_import_on_guest')
 return hashlib.sha256(raw).hexdigest()
def gpg_prefix(private_home):
 need(type(private_home) is str and PurePosixPath(private_home).is_absolute() and '..' not in PurePosixPath(private_home).parts,'isolated_absolute_gpg_home_required')
 return ['/usr/bin/gpg','--no-options','--homedir',private_home,'--batch','--no-tty','--no-auto-key-retrieve','--auto-key-locate','clear','--no-encrypt-to','--no-groups']
def inspect_args(private_home,public_file):
 need(type(public_file) is str and PurePosixPath(public_file).is_absolute() and '..' not in PurePosixPath(public_file).parts,'pinned_public_key_file_required')
 return gpg_prefix(private_home)+['--with-colons','--with-fingerprint','--with-subkey-fingerprint','--import-options','show-only','--dry-run','--import',public_file]
def encrypt_args(private_home,recipients):
 verified=pins(recipients);args=gpg_prefix(private_home)+['--trust-model','always','--cipher-algo','AES256','--compress-algo','none','--output','-']
 for target in TARGETS:
  # Full pinned subkey fingerprint + ! prevents alias/group/automatic-subkey selection.
  args+=['--recipient',verified[target]['encryption_subkey_fingerprint']+'!']
 return args+['--encrypt']
def archive_member(name,kind,size):
 need(type(name) is str and '\x00' not in name and '\\' not in name and not name.startswith('/'),'relative_archive_member_required')
 path=PurePosixPath(name);need(str(path)==name and '..' not in path.parts and name not in ['','.'],'archive_path_escape')
 need(kind in ['regular','directory'] and type(size) is int and size>=0,'only_regular_files_and_directories')
 if kind=='directory':need(size==0,'directory_size_must_be_zero')
 allowed_prefixes=('etc/kubernetes/pki/','etc/kubernetes/nebula/','etc/kubernetes/manifests/','restore-inputs/')
 allowed_exact={'snapshot.db','restore-manifest.json','etc/kubernetes/admin.conf','etc/kubernetes/super-admin.conf','etc/kubernetes/kubelet.conf','var/lib/kubelet/config.yaml'}
 need(name in allowed_exact or any(name.startswith(prefix) for prefix in allowed_prefixes),'unapproved_archive_input')
 if name=='snapshot.db':need(0<size<=MAX_SNAPSHOT,'snapshot_size_bound')
 else:need(size<=MAX_OTHER,'archive_member_size_bound')
 return {'name':name,'kind':kind,'size':size}
def archive_inventory(members):
 need(type(members) is list and 1<=len(members)<=4096,'archive_inventory_bound')
 checked=[archive_member(v['name'],v['kind'],v['size']) for v in members]
 need(len({v['name'] for v in checked})==len(checked),'duplicate_archive_path')
 need(sum(v['name']=='snapshot.db' and v['kind']=='regular' for v in checked)==1,'exactly_one_verified_snapshot_required')
 need(sum(v['name']=='restore-manifest.json' and v['kind']=='regular' for v in checked)==1,'restore_manifest_required')
 need(sum(v['size'] for v in checked if v['name']!='snapshot.db')<=MAX_OTHER,'other_archive_total_bound')
 return checked
def ciphertext_manifest(backup_id,cipher_sha,cipher_bytes,recipients,signer_public_sha,created_at):
 need(type(backup_id) is str and re.fullmatch('[a-f0-9]{32}',backup_id),'backup_id_required')
 need(type(cipher_sha) is str and re.fullmatch('[a-f0-9]{64}',cipher_sha),'ciphertext_digest_required')
 need(type(signer_public_sha) is str and re.fullmatch('[a-f0-9]{64}',signer_public_sha),'independently_pinned_signer_required')
 need(type(cipher_bytes) is int and 0<cipher_bytes<=MAX_CIPHERTEXT,'ciphertext_size_bound')
 need(type(created_at) is int and created_at>0,'creation_time_required')
 data={'schema_version':1,'domain':'nebula-backup-v1','backup_id':backup_id,'created_at':created_at,'ciphertext':{'name':'backup.tar.gpg','sha256':cipher_sha,'bytes':cipher_bytes},'recipients':pins(recipients),'signer_public_sha256':signer_public_sha}
 return (json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode()
def validate_received_manifest(raw,expected_pins,expected_signer,expected_backup_id):
 need(type(raw) is bytes and 0<len(raw)<=8192,'manifest_size_bound')
 try:v=json.loads(raw)
 except Exception:raise Refused('invalid_manifest') from None
 need(type(v) is dict and type(v.get('ciphertext')) is dict,'manifest_object_required')
 # Exact canonical schema prevents extra archive paths, URLs, commands or public-key replacement.
 expected=ciphertext_manifest(expected_backup_id,v.get('ciphertext',{}).get('sha256'),v.get('ciphertext',{}).get('bytes'),expected_pins,expected_signer,v.get('created_at'))
 need(raw==expected,'manifest_schema_or_pin_mismatch')
 return v
def decrypt_args(private_home,output_fd,plaintext_bound):
 need(type(output_fd) is int and output_fd>=3,'exclusive_plaintext_output_fd_required')
 need(type(plaintext_bound) is int and 0<plaintext_bound<=MAX_SNAPSHOT+MAX_OTHER+16*1024**2,'plaintext_output_bound')
 # Caller verifies detached signature+digest BEFORE this, holds new root0600 output FD,
 # checks every GPG exit/status and never exposes plaintext stdout.
 return gpg_prefix(private_home)+['--max-output',str(plaintext_bound),'--output','/proc/self/fd/'+str(output_fd),'--decrypt']

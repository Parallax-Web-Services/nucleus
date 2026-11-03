"""Safe fleet-health reducer and explicit local publisher; no bundled transport.

A separately reviewed adapter supplies observations/proof in memory. This module
never reads sessions, inventories, credentials, logs or installation receipts.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from foundation.framework import require_context

FIELDS={'schema_version','checked_at_unix','registered_node_count','known_online_count','same_fabric','managed_relay_binary_matches','managed_relay_process_unchanged'}
class Refused(RuntimeError):pass
def need(ok,code):
    if not ok:raise Refused(code)
def expected_nodes(expected):
    need(isinstance(expected,dict)and set(expected)=={'fabric_id','nodes'},'explicit_expected_fabric_required')
    need(isinstance(expected['fabric_id'],str)and re.fullmatch(r'[a-f0-9]{64}',expected['fabric_id']),'expected_fabric_id')
    nodes=expected['nodes'];need(isinstance(nodes,list)and 1<=len(nodes)<=128,'bounded_expected_members')
    need(all(isinstance(n,dict)and set(n)=={'node_id'}and isinstance(n['node_id'],str)
             and re.fullmatch(r'[a-f0-9]{64}',n['node_id'])for n in nodes),'expected_member_schema')
    ids={n['node_id']for n in nodes};need(len(ids)==len(nodes),'duplicate_expected_member');return ids

def reduce_views(owner,member,expected,now_ms=None):
    known=expected_nodes(expected)
    def view(value):
        need(isinstance(value,dict)and isinstance(value.get('nodes'),list)and 1<=len(value['nodes'])<=128,'bounded_fabric_view')
        if now_ms is not None:
            stamp=value.get('collected_at_ms');need(type(value.get('schema_version'))is int and value['schema_version']==1 and type(stamp)is int and -5000<=now_ms-stamp<=60000,'stale_source_observation')
        result={}
        for node in value['nodes']:
            need(isinstance(node,dict)and isinstance(node.get('node_id'),str)and re.fullmatch(r'[a-f0-9]{64}',node['node_id'])
                 and node['node_id']not in result and node.get('status')in['online','offline','awaiting'],'member_observation_schema')
            result[node['node_id']]=node
        return result
    a,b=view(owner),view(member)
    return {'registered_node_count':len(a),'known_online_count':sum(a.get(n,{}).get('status')=='online'and b.get(n,{}).get('status')=='online'for n in known),
            'same_fabric':owner.get('fabric_id')==member.get('fabric_id')==expected['fabric_id']and set(a)==set(b)==known}

def validate(value,now):
    need(isinstance(value,dict)and set(value)==FIELDS and type(value['schema_version'])is int and value['schema_version']==1,'health_schema')
    need(type(value['checked_at_unix'])is int and 0<=now-value['checked_at_unix']<=60,'fresh_health_required')
    need(all(type(value[k])is bool for k in['same_fabric','managed_relay_binary_matches','managed_relay_process_unchanged']),'health_boolean_schema')
    need(all(type(value[k])is int and 0<=value[k]<=128 for k in['registered_node_count','known_online_count']),'health_count_schema')
    need(value['known_online_count']<=value['registered_node_count'],'health_counts_inconsistent');return value

def payload(owner_fetcher,member_fetcher,expected,relay_probe,clock=time.time):
    expected_nodes(expected)
    need(all(callable(f)for f in[owner_fetcher,member_fetcher,relay_probe]),'explicit_reviewed_transport_callbacks_required')
    result={'schema_version':1,'checked_at_unix':int(clock()),'registered_node_count':0,'known_online_count':0,
            'same_fabric':False,'managed_relay_binary_matches':False,'managed_relay_process_unchanged':False}
    try:result.update(reduce_views(owner_fetcher(),member_fetcher(),expected,now_ms=int(clock()*1000)))
    except Exception:pass
    try:
        proof=relay_probe();need(isinstance(proof,dict)and set(proof)=={'managed_relay_binary_matches','managed_relay_process_unchanged'}
          and all(type(x)is bool for x in proof.values()),'explicit_relay_proof_required');result.update(proof)
    except Exception:pass
    result['checked_at_unix']=int(clock());return validate(result,int(clock()))

def record(path):
    if not os.path.lexists(path):return None
    need(path.resolve()==path,'health_symlink');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    fields=lambda s:tuple(getattr(s,k)for k in['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'])
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4096,'private_health_file')
        raw=os.read(fd,4097);need(len(raw)<=4096 and fields(s)==fields(os.fstat(fd))==fields(path.lstat()),'health_changed_during_read')
        return {'identity':fields(s),'sha256':hashlib.sha256(raw).hexdigest()}
    finally:os.close(fd)

def store(context,value,expected_record=None):
    context=require_context(context,'host');validate(value,int(time.time()))
    work=context.path('host_state_root')/('plan-'+context.inputs['run_id']);path=work/'external-health.json'
    need(work.resolve()==work,'private_operation_required');s=work.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'private_operation_required')
    lock=work/'health-write.lock';fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        held=os.fstat(fd);need(stat.S_ISREG(held.st_mode)and held.st_uid==0 and held.st_nlink==1 and stat.S_IMODE(held.st_mode)==0o600,'health_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        context.guard();need(record(path)==expected_record,'health_concurrent_change')
        raw=(json.dumps(value,separators=(',',':'))+'\n').encode();out,temp=tempfile.mkstemp(prefix='.health-',dir=work);owned=os.fstat(out);known=None
        try:
            with os.fdopen(out,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            known=record(Path(temp));context.guard();need((lock.lstat().st_dev,lock.lstat().st_ino)==(held.st_dev,held.st_ino)and record(path)==expected_record,'health_concurrent_change')
            if expected_record is None:os.link(temp,path,follow_symlinks=False);os.unlink(temp)
            else:os.replace(temp,path)
            post=record(path);need(post['identity'][0:2]==(owned.st_dev,owned.st_ino)and post['sha256']==hashlib.sha256(raw).hexdigest(),'health_unknown_post_state');return post
        finally:
            try:
                if known is not None and record(Path(temp))==known:os.unlink(temp)
            except FileNotFoundError:pass
    finally:os.close(fd)

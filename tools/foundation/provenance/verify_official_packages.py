#!/usr/bin/env python3
"""Offline read-only verification of the frozen official Kubernetes package bundle.
Does not install packages, change APT trust, execute package contents or contact a host.
"""
import argparse,gzip,hashlib,json,os,subprocess,tempfile
from pathlib import Path
FINGERPRINT="DE15B14486CD377B9E876E1A234654DA9A296436"
KEY_SHA256='7627818cf7bae52f9008c93e8b1f961f53dea11d40891778de216fb1b43be54d'
PACKAGES=[{'package': 'cri-tools', 'version': '1.37.0-1.1', 'filename': 'amd64/cri-tools_1.37.0-1.1_amd64.deb', 'sha256': 'a8eeede0deadc3d9e8f72859732441bfc86fbe60688926ef5410f01338927b71', 'size': 16558740}, {'package': 'kubeadm', 'version': '1.37.1-1.1', 'filename': 'amd64/kubeadm_1.37.1-1.1_amd64.deb', 'sha256': 'b7f399d83fcb8c619927042b4dcd06ba68757fb74f9d2baabc358a0e22032f92', 'size': 12594060}, {'package': 'kubectl', 'version': '1.37.1-1.1', 'filename': 'amd64/kubectl_1.37.1-1.1_amd64.deb', 'sha256': 'f2a1d6e1d2adf5c5c80d3518917a28b66a423698a553c4be4d181df8ddbdde94', 'size': 12076284}, {'package': 'kubelet', 'version': '1.37.1-1.1', 'filename': 'amd64/kubelet_1.37.1-1.1_amd64.deb', 'sha256': 'a0692776f7f026ff17de0ede1b97f11c657300f586cc7939766c395f64c2e6d9', 'size': 13461432}, {'package': 'kubernetes-cni', 'version': '1.9.1-1.1', 'filename': 'amd64/kubernetes-cni_1.9.1-1.1_amd64.deb', 'sha256': '4cd72d8cef4499d3dc410874287b40e8b4241e0772938c5820cbee37986c1d93', 'size': 38991216}]
def require(ok,message):
 if not ok:raise SystemExit(message)
def read(root,name):
 path=root/name;require(path.is_file() and not path.is_symlink() and path.resolve()==path,"Nonordinary public bundle file")
 return path.read_bytes()
def sha(data):return hashlib.sha256(data).hexdigest()
def run(args):
 result=subprocess.run(args,capture_output=True,text=True)
 require(result.returncode==0,"Public signature or package metadata verification failed")
 return result.stdout
parser=argparse.ArgumentParser();parser.add_argument("directory",type=Path);args=parser.parse_args();root=args.directory.resolve(strict=True)
require(sha(read(root,"Release.key"))==KEY_SHA256,"Official key artifact pin differs")
with tempfile.TemporaryDirectory(prefix="nebula-k8s-verify-") as directory:
 home=Path(directory);os.chmod(home,0o700)
 listing=run(["gpg","--no-options","--homedir",str(home),"--batch","--with-colons","--show-keys",str(root/"Release.key")])
 fingerprints=[line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
 require(fingerprints==[FINGERPRINT],"Official primary key fingerprint differs")
 ring=home/"keyring.gpg";run(["gpg","--no-options","--homedir",str(home),"--batch","--dearmor","--output",str(ring),str(root/"Release.key")])
 for name in ["InRelease","Release","Release.gpg"]:read(root,name)
 status=run(["gpgv","--homedir",str(home),"--keyring",str(ring),"--status-fd","1","--output",str(home/"VerifiedRelease"),str(root/"InRelease")])
 detached=run(["gpgv","--homedir",str(home),"--keyring",str(ring),"--status-fd","1",str(root/"Release.gpg"),str(root/"Release")])
 require(any(line.startswith("[GNUPG:] VALIDSIG "+FINGERPRINT+" ") for line in status.splitlines()) and any(line.startswith("[GNUPG:] VALIDSIG "+FINGERPRINT+" ") for line in detached.splitlines()),"Unexpected metadata signer")
 require((home/"VerifiedRelease").read_bytes()==read(root,"Release"),"Signed release variants differ")
 release=read(root,"Release").decode();section=None;pins={}
 for line in release.splitlines():
  if not line.startswith(" "):section=line.rstrip(":")
  elif section=="SHA256":value,size,name=line.split();pins[name]=(value,int(size))
 compressed=read(root,"Packages.gz");packages=gzip.decompress(compressed)
 for name,data in [("Packages.gz",compressed),("Packages",packages)]:require(name in pins and (sha(data),len(data))==pins[name],"Signed package index digest differs")
 entries={}
 for block in packages.decode().strip().split("\n\n"):
  fields={};last=None
  for line in block.splitlines():
   if line[:1].isspace():fields[last]+="\n"+line[1:]
   else:last,value=line.split(": ",1);fields[last]=value
  entries[(fields["Package"],fields["Version"],fields["Architecture"])]=fields
 for item in PACKAGES:
  identity=(item["package"],item["version"],"amd64");require(identity in entries,"Pinned package missing from signed index");entry=entries[identity]
  require(entry["Filename"]==item["filename"] and entry["SHA256"]==item["sha256"] and int(entry["Size"])==item["size"],"Signed package pin differs")
  data=read(root,item["filename"]);require(len(data)==item["size"] and sha(data)==item["sha256"],"Public package artifact digest differs")
  for field,value in [("Package",item["package"]),("Version",item["version"]),("Architecture","amd64")]:require(run(["dpkg-deb","--field",str(root/item["filename"]),field]).strip()==value,"Package control identity differs")
print(json.dumps({"status":"passed","fingerprint":FINGERPRINT,"packages":len(PACKAGES),"installed":False,"network_used":False}))

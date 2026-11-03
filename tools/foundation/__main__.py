"""Read-only source-kit inspection. Operational phases are not a public CLI."""
import argparse,json
from pathlib import Path
from foundation.framework import Bundle,PROFILE,Refused,decode

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['verify','profile']);p.add_argument('--manifest-sha256',required=True);a=p.parse_args()
 bundle=Bundle.open(Path(__file__).resolve().parent,a.manifest_sha256)
 if a.command=='verify':print(json.dumps({'status':'source_verified','files':len(bundle.entries),'live_operations_performed':False,'public_installer':False}))
 else:print(json.dumps(decode(bundle.bytes(PROFILE)),indent=2,sort_keys=True))
if __name__=='__main__':
 try:main()
 except Refused as e:raise SystemExit(str(e))

#!/usr/bin/env python3
from pathlib import Path
import importlib.util, sys, ssl
ROOT=Path(sys.argv[1]).resolve()
spec=importlib.util.spec_from_file_location('sb', ROOT/'scripts/server-backup-helper.py')
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
base={'id':'ftp1','type':'ftp','host':'backup.example','username':'backup','remote_path':'backups'}
ftp=h.validate_destination(base, {})
assert ftp['tls_mode']=='explicit', ftp
assert ftp['allow_insecure_transport'] is False
try:
    h.validate_destination({**base,'tls_mode':'none'}, {})
except RuntimeError as exc:
    assert 'plaintext FTP is disabled' in str(exc)
else:
    raise AssertionError('plaintext FTP accepted without explicit override')
ftp_plain=h.validate_destination({**base,'tls_mode':'none','allow_insecure_transport':True}, {})
assert ftp_plain['tls_mode']=='none' and ftp_plain['allow_insecure_transport'] is True
web={'id':'w1','type':'webdav','url':'https://backup.example/dav','remote_path':'backups'}
secure=h.validate_destination(web,{})
assert secure['allow_insecure_transport'] is False
try:
    h.validate_destination({**web,'url':'http://backup.example/dav'}, {})
except RuntimeError as exc:
    assert 'plaintext WebDAV is disabled' in str(exc)
else:
    raise AssertionError('plaintext WebDAV accepted without explicit override')
plain=h.validate_destination({**web,'url':'http://backup.example/dav','allow_insecure_transport':True},{})
assert plain['allow_insecure_transport'] is True
sftp=h.validate_destination({'id':'s1','type':'sftp','host':'backup.example','username':'backup','remote_path':'backups'}, {})
assert sftp['host_key_policy']=='strict'
print('server backup transport security: PASS')

ctx=h.ftp_tls_context()
assert ctx.verify_mode == ssl.CERT_REQUIRED
assert ctx.check_hostname is True
print('server backup FTPS certificate verification: PASS')

#!/usr/bin/env python3
"""Focused contract tests; subprocesses and host paths are never live."""
from __future__ import annotations
import importlib.machinery, importlib.util, json, os, re, stat, sys, tempfile
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent.parent
loader=importlib.machinery.SourceFileLoader('provision',str(ROOT/'scripts/production-stack/host/provision-vnext'))
spec=importlib.util.spec_from_loader(loader.name,loader); mod=importlib.util.module_from_spec(spec); sys.modules[loader.name]=mod; loader.exec_module(mod)
def request():
 return {'schema':mod.SCHEMA,'schema_version':1,'target':'x6','domain':'x6.example.com','tenant_id':'01890f47-3a5b-7c1d-8e2f-123456789abc','indexer_id':'01890f47-3a5b-7c1d-8e2f-123456789abd','private_ipv4':'10.0.1.6','release_version':'1.2.3','bundle_sha256':'a'*64,'compose_sha256':'b'*64,'server_image':'dirextalk/vnet-server@sha256:'+'1'*64,'migrator_image':'dirextalk/vnet-server@sha256:'+'2'*64,'postgres_image':'postgres@sha256:'+'3'*64,'caddy_image':'caddy@sha256:'+'4'*64,'probe_image':'curlimages/curl@sha256:'+'5'*64}
def reject(v):
 try: mod.parse(mod.canonical(v))
 except mod.ContractError: return
 raise AssertionError('accepted invalid request')
v=request(); assert mod.parse(mod.canonical(v))==v
bad=dict(v); bad['target']='x9'; reject(bad)
bad=dict(v); bad['private_ipv4']='8.8.8.8'; reject(bad)
bad=dict(v); bad['server_image']='dirextalk/vnet-server:latest'; reject(bad)
try: mod.parse(mod.canonical(v).replace(b'"target":"x6"',b'"target":"x6","target":"x6"'))
except mod.ContractError: pass
else: raise AssertionError('accepted duplicate keys')
source=(ROOT/'docker/production/docker-compose.yml').read_text(); rendered=mod.transform_compose(source)
assert rendered.count('network_mode: service:agent-control')==2
caddy=mod.caddyfile(v['domain']); assert 'reverse_proxy @mcp http://127.0.0.1:9081' in caddy and '@node path_regexp versioned_api ^/v[1-9][0-9]*/.*$' in caddy and '@health path /healthz' in caddy and 'agent-control:9081' not in caddy
assert caddy.index('@owner_connectors') < caddy.index('@node path_regexp')
assert caddy.count('http://127.0.0.1:9081') == 20
owner_matchers={name:(method,re.compile(pattern)) for name,method,pattern in re.findall(r'@(owner_[a-z_]+) \{\n        method (GET|POST|PUT|DELETE)\n        path_regexp \1 (\S+)\n    \}',caddy)}
assert len(owner_matchers)==19
assert {name:method for name,(method,_) in owner_matchers.items()} == {
 'owner_connectors':'GET', 'owner_connector_drain':'POST', 'owner_connector_restart':'POST', 'owner_connector_rotate':'POST',
 'owner_binding_enable':'POST', 'owner_binding_disable':'POST', 'owner_conversation_grant_put':'PUT', 'owner_conversation_grant_delete':'DELETE',
 'owner_agent_route_run':'POST', 'owner_route_bootstrap_create':'POST', 'owner_route_bootstrap_get':'GET', 'owner_route_bootstrap_delivery':'PUT',
 'owner_identity_approval_create':'POST', 'owner_identity_approval_get':'GET', 'owner_provisioning_target':'GET', 'owner_agent_route_target':'GET',
 'owner_provisioning_delivery_create':'POST', 'owner_provisioning_delivery_get':'GET', 'owner_revocation':'POST',
}
for name,method,path,allowed in (
 ('owner_connectors','GET','/v1/connectors',True), ('owner_connectors','POST','/v1/connectors',False),
 ('owner_connector_drain','POST','/v1/connectors/a/drain',True), ('owner_connector_drain','POST','/v1/connectors/a/drain/x',False),
 ('owner_conversation_grant_put','PUT','/v1/conversations/a/agent-grants/b',True), ('owner_conversation_grant_delete','DELETE','/v1/conversations/a/agent-grants/b',True),
 ('owner_agent_route_run','POST','/v1/conversations/a/agent-routes/b/runs',True), ('owner_route_bootstrap_delivery','PUT','/v1/agent-route-bootstraps/a/deliveries/b',True),
 ('owner_identity_approval_get','GET','/v1/agent-installations/a/identity-approvals/b',True), ('owner_provisioning_delivery_get','GET','/v1/agent-installations/a/provisioning-deliveries/b',True),
 ('owner_revocation','POST','/v1/agent-installations/a/revocations',True), ('owner_revocation','GET','/v1/agent-installations/a/revocations',False),
):
 actual_method,matcher=owner_matchers[name]; assert (actual_method==method and bool(matcher.fullmatch(path))) == allowed, (name,method,path)
assert re.search(r'@mcp \{\n        method POST\n        path_regexp mcp (\S+)\n',caddy).group(1) == '^/mcp$'
versioned_matcher=re.search(r'@node path_regexp versioned_api (\S+)',caddy)
assert versioned_matcher
versioned_api=re.compile(versioned_matcher.group(1))
assert versioned_api.fullmatch('/v2/key-packages/claim') and versioned_api.fullmatch('/v12/future-route')
assert not versioned_api.fullmatch('/v0/key-packages/claim') and not versioned_api.fullmatch('/v01/key-packages/claim') and not versioned_api.fullmatch('/key-packages/claim')
public_feed_matcher=re.search(r'@public_feed path_regexp public_feed (\S+)',caddy)
assert public_feed_matcher and 'reverse_proxy @public_feed https://dtx-node:8443' in caddy
public_feed_api=re.compile(public_feed_matcher.group(1))
assert public_feed_api.fullmatch('/.well-known/dirextalk/public/v1/dtxc123/feed') and public_feed_api.fullmatch('/.well-known/dirextalk/public/v1/dtxa456/posts/hash/comments')
for path in ('/.well-known/dirextalk/public/v1', '/.well-known/dirextalk/public/v1/', '/.well-known/dirextalk/public/v1//feed', '/.well-known/dirextalk/public/v0/dtxc123/feed', '/.well-known/dirextalk/public/v00/dtxc123/feed', '/.well-known/public/v1/dtxc123/feed', '/public/v1/dtxc123/feed'):
 assert not public_feed_api.fullmatch(path), path
static_caddy=(ROOT/'docker/production/Caddyfile').read_text()
assert '@mcp {\n        method POST\n        path_regexp mcp ^/mcp$\n    }' in static_caddy
assert '127.0.0.1:9081' not in static_caddy and '@owner_' not in static_caddy
static_public_feed_matcher=re.search(r'@public_feed path_regexp public_feed (\S+)',static_caddy)
assert static_public_feed_matcher and 'reverse_proxy @public_feed https://dtx-node:8443' in static_caddy
static_public_feed_api=re.compile(static_public_feed_matcher.group(1))
assert static_public_feed_api.fullmatch('/.well-known/dirextalk/public/v1/dtxc123/feed')
for path in ('/.well-known/dirextalk/public/v1', '/.well-known/dirextalk/public/v1/', '/.well-known/dirextalk/public/v1//feed', '/.well-known/dirextalk/public/v0/dtxc123/feed', '/.well-known/dirextalk/public/v00/dtxc123/feed', '/.well-known/public/v1/dtxc123/feed', '/public/v1/dtxc123/feed'):
 assert not static_public_feed_api.fullmatch(path), path
agent=json.loads(mod.agent_config(v)); assert agent['owner_api']['listen']=='127.0.0.1:9081' and agent['control']['listen']=='0.0.0.0:9444' and agent['connector_issuer']['response_intermediate_bundle_pem'].startswith('/run/dtx-agent-control-tls/')
try: mod.transform_compose(source.replace('"80:80"','"81:80"',1))
except mod.ContractError: pass
else: raise AssertionError('accepted altered compose template')
receipt=mod.ready(v,mod.sha(mod.canonical(v))); parsed=json.loads(receipt); assert parsed['receipt_sha256']==mod.sha(mod.canonical({k:x for k,x in parsed.items() if k!='receipt_sha256'}))
assert b'postgresql://' not in receipt and b'password' not in receipt
with tempfile.TemporaryDirectory() as temporary:
 path=Path(temporary)/'key'; identity=os.getuid(); mod.write(path,b'x'*32,0o400,identity,identity); metadata=path.stat(); assert path.read_bytes()==b'x'*32 and stat.S_IMODE(metadata.st_mode)==0o400 and metadata.st_uid==identity and metadata.st_gid==identity
 original=os.write; calls=[]
 def short(fd,data): calls.append(len(data)); return original(fd,data[:1])
 os.write=short
 try: mod.write(Path(temporary)/'short',b'abc',0o600,identity,identity)
 finally: os.write=original
 assert (Path(temporary)/'short').read_bytes()==b'abc' and not list(Path(temporary).glob('.short.*'))
 compose=b'compose'; v['compose_sha256']=mod.sha(compose); example=b'DTX_POSTGRES_IMAGE='+v['postgres_image'].encode()+b'\nDTX_CADDY_IMAGE='+v['caddy_image'].encode()+b'\nDTX_PROBE_IMAGE='+v['probe_image'].encode()+b'\n'; installer=b'installer'
 payloads={'docker/production/docker-compose.yml':compose,'docker/production/examples/x6.env.example':example,'scripts/production-stack/install.sh':installer}
 records=[{'path':path,'sha256':mod.sha(data),'mode':'0555' if path.endswith('.sh') else '0444'} for path,data in sorted(payloads.items())]
 manifest={'schema':'dirextalk.vnext-stack-bundle','schema_version':1,'version':v['release_version'],'source_commit':'a'*40,'target':'linux-amd64','server_image':v['server_image'],'migrator_image':v['migrator_image'],'installer_sha256':mod.sha(installer),'files':records}; manifest_raw=mod.canonical(manifest)
 body={'schema':'dirextalk.vnext-installed-release','schema_version':1,'target':'linux-amd64','domain':v['domain'],'version':v['release_version'],'source_commit':'a'*40,'bundle_sha256':v['bundle_sha256'],'manifest_sha256':mod.sha(manifest_raw),'server_image':v['server_image'],'migrator_image':v['migrator_image'],'previous_receipt_sha256':None,'state':'installed','installed_at_ms':1}; receipt=dict(body); receipt['receipt_sha256']=mod.sha(mod.canonical(body)); mod.release_documents(v,manifest_raw,mod.canonical(receipt),payloads)
 bad=dict(receipt); bad['domain']='other.example.com'; badbody={k:x for k,x in bad.items() if k!='receipt_sha256'}; bad['receipt_sha256']=mod.sha(mod.canonical(badbody))
 try: mod.release_documents(v,manifest_raw,mod.canonical(bad),payloads)
 except mod.ContractError: pass
 else: raise AssertionError('accepted receipt for another domain')
 badrequest=dict(v); badrequest['probe_image']='curlimages/curl@sha256:'+'9'*64
 try: mod.release_documents(badrequest,manifest_raw,mod.canonical(receipt),payloads)
 except mod.ContractError: pass
 else: raise AssertionError('accepted mismatched dependency contract')
 original_run=mod.run; original_subprocess_run=mod.subprocess.run; calls=[]; subprocess_calls=[]
 class Result:
  returncode=0; stdout='401'
 mod.run=lambda *args,**kwargs: calls.append(args)
 mod.subprocess.run=lambda *args,**kwargs: (subprocess_calls.append(args[0]) or Result())
 try: mod.public_verify(v,ROOT)
 finally: mod.run=original_run; mod.subprocess.run=original_subprocess_run
 assert calls and calls[0][0]=='curl' and calls[0][-1].endswith('/healthz')
 assert subprocess_calls and 'Accept: application/json, text/event-stream' in subprocess_calls[0]
 class BadResult:
  returncode=0; stdout='500'
 mod.run=lambda *args,**kwargs: None; mod.subprocess.run=lambda *args,**kwargs: BadResult()
 try:
  try: mod.public_verify(v,ROOT)
  except mod.ContractError: pass
  else: raise AssertionError('accepted non-401 MCP response')
 finally: mod.run=original_run; mod.subprocess.run=original_subprocess_run
print('vNext host provision focused contract checks passed')

#!/usr/bin/env python3
"""Focused contract tests; subprocesses and host paths are never live."""
from __future__ import annotations
import importlib.machinery, importlib.util, json, sys
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
caddy=mod.caddyfile(v['domain']); assert 'reverse_proxy @mcp http://127.0.0.1:9081' in caddy and '@node path /v1/*' in caddy and '@health path /healthz' in caddy and 'agent-control:9081' not in caddy
agent=json.loads(mod.agent_config(v)); assert agent['owner_api']['listen']=='127.0.0.1:9081' and agent['control']['listen']=='0.0.0.0:9444' and agent['connector_issuer']['response_intermediate_bundle_pem'].startswith('/run/dtx-agent-control-tls/')
try: mod.transform_compose(source.replace('"80:80"','"81:80"',1))
except mod.ContractError: pass
else: raise AssertionError('accepted altered compose template')
receipt=mod.ready(v,mod.sha(mod.canonical(v))); parsed=json.loads(receipt); assert parsed['receipt_sha256']==mod.sha(mod.canonical({k:x for k,x in parsed.items() if k!='receipt_sha256'}))
assert b'postgresql://' not in receipt and b'password' not in receipt
print('vNext host provision focused contract checks passed')

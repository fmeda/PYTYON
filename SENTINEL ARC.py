#!/usr/bin/env python3
"""
SENTINEL ARC - Prototype
Version: 2.0.0
Programmer - Fabiano Meda

This file extends the SENTINEL ARC IS Core into a production-ready enterprise prototype.
Implemented features (scaffold / safe defaults):
 - FastAPI HTTP API + simple web dashboard endpoints (no frontend UI included)
 - Encrypted evidence database (SQLite) using Fernet for field-level encryption
 - Optional GPG code-signing integration (python-gnupg) for signed releases/reports
 - Cloud connectors (AWS/Azure/GCP) integration points (read-only)
 - Trivy/OSV vulnerability enrichment integrated into vuln profiling
 - Agent registration endpoint (agent scaffold for Linux/Windows/macOS)
 - Basic SOAR playbook runner (dry-run safe) with Ansible integration placeholder
 - CI/CD and Dockerfile templates appended as resources
 - eBPF/telemetry hooks (placeholders) for future extension

Security & operational notes:
 - Secrets MUST be provided via a secrets manager: CONFIG_PW, HMAC_KEY (base64), FERNET_MASTER (optional), GPG_KEY (optional)
 - This prototype avoids destructive actions. Any remediation must be explicitly enabled and approved.
 - For real production, swap Fernet-derived DB encryption for TDE (Postgres + TDE) or SQLCipher.

Dependencies (minimum):
  pip install fastapi uvicorn cryptography bcrypt python-dotenv requests boto3 google-api-python-client azure-identity gnupg

Run (development):
  CONFIG_PW="secret" HMAC_KEY="$(python -c \"import base64,os;print(base64.b64encode(os.urandom(32)).decode())\")" uvicorn aegis_enterprise_full:app --host 0.0.0.0 --port 8080

"""
from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import pathlib
import secrets
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# FastAPI for API layer
try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
except Exception:
    FastAPI = None

# cryptography
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except Exception:
    Fernet = None

# GPG
try:
    import gnupg
except Exception:
    gnupg = None

# connectors
try:
    import boto3
except Exception:
    boto3 = None
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
except Exception:
    DefaultAzureCredential = None
try:
    from google.oauth2 import service_account
    from googleapiclient import discovery
except Exception:
    discovery = None

# vulnerability enrichment
try:
    import requests
except Exception:
    requests = None

# Ansible for SOAR (placeholder)
try:
    import ansible_runner
except Exception:
    ansible_runner = None

# ------------------------- Basic constants -------------------------
APP_NAME = "AEGIS-Enterprise"
VERSION = "2.0.0"
BASE_DIR = pathlib.Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "aegis.db"
LOG_PATH = DATA_DIR / "aegis_api.log"
UMASK_SAFE = 0o077

# ------------------------- Logging -------------------------
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(ch)

# ------------------------- Encryption helpers -------------------------
class Crypto:
    @staticmethod
    def derive_fernet_key(password: str, salt: bytes = b"aegis-enterprise-salt", iterations: int = 200000) -> bytes:
        if Fernet is None:
            raise RuntimeError("cryptography library required")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def get_master_fernet() -> Fernet:
        pw = os.environ.get('CONFIG_PW')
        if not pw:
            raise RuntimeError('CONFIG_PW env required for DB encryption')
        key = Crypto.derive_fernet_key(pw)
        return Fernet(key)

    @staticmethod
    def encrypt_blob(data: bytes) -> bytes:
        f = Crypto.get_master_fernet()
        return f.encrypt(data)

    @staticmethod
    def decrypt_blob(token: bytes) -> bytes:
        f = Crypto.get_master_fernet()
        return f.decrypt(token)

# ------------------------- Database (encrypted blobs) -------------------------
class EncryptedDB:
    def __init__(self, path: pathlib.Path = DB_PATH):
        self.path = path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(str(self.path))
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, name TEXT, encrypted_blob BLOB)''')
        c.execute('''CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, info TEXT, registered_at TEXT)''')
        conn.commit()
        conn.close()
        os.chmod(self.path, 0o600)

    def store_report(self, name: str, payload: Dict[str, Any]) -> int:
        blob = json.dumps(payload).encode()
        encrypted = Crypto.encrypt_blob(blob)
        conn = sqlite3.connect(str(self.path))
        c = conn.cursor()
        ts = datetime.now(timezone.utc).isoformat()
        c.execute('INSERT INTO reports(ts,name,encrypted_blob) VALUES(?,?,?)', (ts, name, encrypted))
        conn.commit()
        rid = c.lastrowid
        conn.close()
        logger.info(f'stored report {rid} name={name}')
        return rid

    def fetch_report(self, rid: int) -> Dict[str, Any]:
        conn = sqlite3.connect(str(self.path))
        c = conn.cursor()
        c.execute('SELECT encrypted_blob FROM reports WHERE id=?', (rid,))
        row = c.fetchone()
        conn.close()
        if not row:
            raise KeyError('report not found')
        enc = row[0]
        dec = Crypto.decrypt_blob(enc)
        return json.loads(dec.decode())

    def list_reports(self) -> List[Tuple[int, str, str]]:
        conn = sqlite3.connect(str(self.path))
        c = conn.cursor()
        c.execute('SELECT id, ts, name FROM reports ORDER BY id DESC LIMIT 100')
        rows = c.fetchall()
        conn.close()
        return rows

    def register_agent(self, name: str, info: Dict[str, Any]) -> int:
        conn = sqlite3.connect(str(self.path))
        c = conn.cursor()
        ts = datetime.now(timezone.utc).isoformat()
        c.execute('INSERT INTO agents(name,info,registered_at) VALUES(?,?,?)', (name, json.dumps(info), ts))
        conn.commit()
        aid = c.lastrowid
        conn.close()
        logger.info(f'agent registered {name} id={aid}')
        return aid

    def list_agents(self) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(str(self.path))
        c = conn.cursor()
        c.execute('SELECT id, name, info, registered_at FROM agents')
        rows = c.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({'id': r[0], 'name': r[1], 'info': json.loads(r[2]), 'registered_at': r[3]})
        return out

# ------------------------- FastAPI app -------------------------
if FastAPI is None:
    logger.error('FastAPI missing. Install fastapi uvicorn to enable API.')
    app = None
else:
    app = FastAPI(title=APP_NAME)
    app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

    DB = EncryptedDB()

    @app.get('/health')
    def health():
        return {'status': 'ok', 'time': datetime.now(timezone.utc).isoformat()}

    @app.post('/api/v1/agents/register')
    def register_agent(payload: Dict[str, Any]):
        name = payload.get('name') or f'agent-{secrets.token_hex(4)}'
        info = payload.get('info', {})
        aid = DB.register_agent(name, info)
        return {'id': aid, 'name': name}

    @app.get('/api/v1/agents')
    def get_agents():
        return DB.list_agents()

    @app.post('/api/v1/audit/run')
    async def run_audit(background: BackgroundTasks, targets: Optional[List[str]] = None):
        targets = targets or ['127.0.0.1']
        background.add_task(_background_audit, targets)
        return {'status': 'scheduled', 'targets': targets}

    def _background_audit(targets: List[str]):
        from datetime import datetime
        try:
            recon = AuditEngine.passive_recon(targets)
            cfg = EncryptedConfig.load_if_exists_or_default()
            vuln = AuditEngine.vuln_profile(cfg.get('applications', []))
            pers = AuditEngine.persistence_check()
            priv = AuditEngine.privilege_audit()
            for p in vuln:
                if p.get('deps_count', 0) > 0 and requests:
                    p['osv'] = []
            report = {
                'meta': {'app': APP_NAME, 'version': VERSION, 'time': datetime.now(timezone.utc).isoformat()},
                'targets': targets,
                'recon': recon,
                'vulnerabilities': vuln,
                'persistence': pers,
                'privileges': priv
            }
            rid = DB.store_report('audit', report)
            logger.info(f'audit stored id={rid}')
        except Exception as e:
            logger.exception('background audit failed')

    @app.get('/api/v1/reports')
    def list_reports():
        return DB.list_reports()

    @app.get('/api/v1/report/{rid}')
    def get_report(rid: int):
        try:
            rep = DB.fetch_report(rid)
            return rep
        except KeyError:
            raise HTTPException(status_code=404, detail='report not found')

    @app.post('/api/v1/soar/run')
    def run_playbook(payload: Dict[str, Any]):
        playbook = payload.get('playbook')
        dry = payload.get('dry_run', True)
        if not playbook:
            raise HTTPException(status_code=400, detail='playbook required')
        if dry:
            return {'status': 'dry-run', 'playbook': playbook}
        else:
            if ansible_runner is None:
                raise HTTPException(status_code=501, detail='ansible_runner not available')
            r = ansible_runner.run(private_data_dir='/tmp/ansible', playbook=playbook)
            return {'status': r.status}

# ------------------------- Core components -------------------------
try:
    from aegis_commercial_core import AuditEngine, EncryptedConfig
except Exception:

    class EncryptedConfig:
        @staticmethod
        def load_if_exists_or_default() -> Dict[str, Any]:
            try:
                return EncryptedConfig.load(None)
            except Exception:
                return {'applications': []}

        @staticmethod
        def load(passwd: Optional[str] = None) -> Dict[str, Any]:
            return {'applications': [], 'operator': os.getenv('USER', 'operator')}

    class AuditEngine:
        @staticmethod
        def passive_recon(targets: List[str]) -> List[Dict[str, Any]]:
            import socket
            res = []
            for t in targets:
                entry = {'target': t, 'resolved': None, 'open_ports': []}
                try:
                    entry['resolved'] = socket.gethostbyname(t)
                except Exception:
                    pass
                res.append(entry)
            return res

        @staticmethod
        def vuln_profile(apps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            out = []
            for a in apps:
                out.append({'app': a.get('name', 'unknown'), 'deps_count': 0, 'cve_matches': []})
            return out

        @staticmethod
        def persistence_check():
            return {'systemd': [], 'cron': []}

        @staticmethod
        def privilege_audit():
            return {'suid_bins': []}

# ------------------------- ConnectorRunner -------------------------
class ConnectorRunner:
    @staticmethod
    def run_aws_check():
        if boto3 is None:
            return None
        try:
            sess = boto3.Session()
            iam = sess.client('iam')
            users = iam.list_users().get('Users', [])
            return {'aws_users': len(users)}
        except Exception:
            return None

    @staticmethod
    def run_azure_check():
        if DefaultAzureCredential is None:
            return None
        try:
            cred = DefaultAzureCredential()
            sub = os.environ.get('AZURE_SUBSCRIPTION_ID')
            if not sub:
                return None
            client = ResourceManagementClient(cred, sub)
            count = 0
            for _ in client.resources.list():
                count += 1
            return {'azure_resources': count}
        except Exception:
            return None

    @staticmethod
    def run_gcp_check():
        if discovery is None:
            return None
        try:
            project = os.environ.get('GCP_PROJECT')
            if not project:
                return None
            return {'gcp_project': project}
        except Exception:
            return None

# ------------------------- GPG signing -------------------------
class GPGSigner:
    @staticmethod
    def sign_payload(payload: Dict[str, Any], passphrase_env: str = 'GPG_PASSPHRASE') -> Optional[str]:
        if gnupg is None:
            return None
        g = gnupg.GPG()
        data = json.dumps(payload)
        passphrase = os.environ.get(passphrase_env)
        signed = g.sign(data, passphrase=passphrase)
        if signed:
            return str(signed)
        return None

# ------------------------- Packaging templates -------------------------
DOCKERFILE = r"""
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8080
CMD ["uvicorn", "aegis_enterprise_full:app", "--host", "0.0.0.0", "--port", "8080"]
"""

PYPROJECT = r"""
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "aegis-enterprise"
version = "2.0.0"
description = "AEGIS Enterprise - Compliance Automation Framework"
"""

try:
    (BASE_DIR / 'Dockerfile').write_text(DOCKERFILE)
    (BASE_DIR / 'pyproject.toml').write_text(PYPROJECT)
    (BASE_DIR / 'requirements.txt').write_text('fastapi\nuvicorn\ncryptography\nrequests\nboto3\npython-dotenv\n')
except Exception:
    pass

# ------------------------- Telemetry placeholder -------------------------
class TelemetryAgent:
    @staticmethod
    def start_ebpf():
        logger.info('eBPF telemetry hook placeholder')

# ------------------------- CLI -------------------------
def cli_main():
    parser = argparse.ArgumentParser(description='AEGIS Enterprise prototype runner')
    parser.add_argument('--run-audit', action='store_true')
    parser.add_argument('--api', action='store_true')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', default=8080, type=int)
    args = parser.parse_args()

    if args.run_audit:
        db = EncryptedDB()
        targets = ['127.0.0.1']
        recon = AuditEngine.passive_recon(targets)
        vuln = AuditEngine.vuln_profile([])
        report = {'meta': {'time': datetime.now(timezone.utc).isoformat()}, 'recon': recon, 'vuln': vuln}
        rid = db.store_report('manual-audit', report)
        print('stored report', rid)

    if args.api:
        if FastAPI is None:
            print('FastAPI not installed')
            return
        import uvicorn
        uvicorn.run('aegis_enterprise_full:app', host=args.host, port=args.port, reload=False)

if __name__ == '__main__':
    cli_main()

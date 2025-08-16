#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
triple_guard.py (2025-08)
=========================

Criptografia em tripla camada com interface intuitiva, proteção de credenciais,
detecção de alteração do script e hardenings atualizados:

- AEAD tripla: AES-256-GCM → ChaCha20-Poly1305 → AES-256-GCM.
- Envelope encryption (DEKs em .key, protegido por KEK via scrypt).
- Armadilha (--trap): após N falhas consecutivas, destrói o .key (cripto-eliminação).
- Pré-check de dependências (comutável com --no-auto-install / --requirements).
- Proteção de credenciais & verificação de integridade (.tg_prot).
- Backoff persistente anti-brute-force (.tg_lock).
- Extração TAR segura (bloqueia traversal/symlinks).
- Permissões estritas 0600 para artefatos sensíveis; recusa perms fracas.
- Modo OPSEC (--opsec): minimiza metadados.
- Hardening de processo: bloqueio de core dumps e tentativa de mlockall.

AVISOS:
- Teste sempre com dados não críticos.
- Em SSDs/NVMe, “shred” não é garantido → prefira cripto-eliminação (apagar chaves).
"""

from __future__ import annotations
import sys, os, subprocess, argparse, getpass, secrets, json, time, struct, tempfile, tarfile, shutil, pathlib, platform
from typing import Tuple

# ========================= CORES E PRINTS =========================
class Color:
    OK = "\033[92m"; INFO = "\033[94m"; WARN = "\033[93m"; ERR = "\033[91m"; END = "\033[0m"

def cprint(msg: str, level: str = "INFO"):
    use_color = sys.stdout.isatty()
    tag = level if level in ("OK","INFO","WARN","ERR") else ""
    if use_color:
        color = {"OK":Color.OK,"INFO":Color.INFO,"WARN":Color.WARN,"ERR":Color.ERR}.get(level, "")
        reset = Color.END if color else ""
        print(f"{color}[{tag}]{reset} {msg}" if tag else msg)
    else:
        print(f"[{tag}] {msg}" if tag else msg)

# ========================= ARGS GLOBAIS PRÉ-PARSE =========================
# precisamos ler flags globais antes do pre-check de deps
NO_AUTO_INSTALL = "--no-auto-install" in sys.argv
REQ_FILE = None
if "--requirements" in sys.argv:
    try:
        REQ_FILE = sys.argv[sys.argv.index("--requirements") + 1]
    except Exception:
        pass

# ========================= PRE-CHECK DE DEPENDÊNCIAS ======================
REQUIRED_PKGS = ["cryptography", "zstandard", "tqdm"]

def _pip_install(pkgs):
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + pkgs
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def _pip_install_requirements(req_path: str):
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "-r", req_path]
    # recomendável: --require-hashes dentro do arquivo
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def ensure_dependencies():
    missing = []
    for pkg in REQUIRED_PKGS:
        try: __import__(pkg)
        except Exception: missing.append(pkg)

    if not missing:
        cprint("Verificação de dependências: OK.", "OK"); return True

    if NO_AUTO_INSTALL:
        cprint("Auto-instalação desativada (--no-auto-install). Instale manualmente:", "WARN")
        cprint("python -m pip install " + " ".join(missing), "INFO")
        return False

    if REQ_FILE:
        cprint(f"Instalando dependências via requirements: {REQ_FILE}", "INFO")
        proc = _pip_install_requirements(REQ_FILE)
    else:
        cprint(f"Dependências faltando: {', '.join(missing)}. Tentando instalar via pip...", "WARN")
        proc = _pip_install(missing)

    if proc.returncode != 0:
        cprint("Instalação automática falhou.", "ERR")
        cprint((proc.stderr or proc.stdout).strip(), "ERR")
        return False

    # re-testar import
    for pkg in missing:
        __import__(pkg)
    cprint("Dependências instaladas com sucesso.", "OK")
    return True

if not ensure_dependencies():
    cprint("Não foi possível garantir dependências. Abortando.", "ERR"); sys.exit(4)

# ========================= IMPORTS EXTERNOS ===============================
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac as chmac
import zstandard as zstd

# ========================= PARÂMETROS CRIPTO =============================
MAGIC = b"TGUARD1"; VERSION = 2  # versão incrementada p/ mudanças
SCRYPT_N = 2**18; SCRYPT_R = 8; SCRYPT_P = 1; SALT_LEN = 16
NONCE_LEN = 12; DEK_LEN = 32; HKDF_LEN = 32

# ========================= ARQUIVOS INTERNOS =============================
SCRIPT_PATH = pathlib.Path(__file__).resolve()
DATA_DIR = SCRIPT_PATH.parent
INTEGRITY_FILE = DATA_DIR / ".tg_integrity"   # reservado (não usado nesta versão)
CRED_FILE = DATA_DIR / ".tg_prot"             # proteção de credenciais/integridade
LOCK_FILE = DATA_DIR / ".tg_lock"             # backoff persistente

# ========================= UTILITÁRIOS =============================
def harden_process():
    # bloqueia core dump; tenta mlockall (best-effort)
    try:
        import resource; resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    except Exception: pass
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        MCL_CURRENT, MCL_FUTURE = 1, 2
        libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    except Exception: pass

def derive_kek(passphrase: bytes, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase)

def hkdf_expand(key: bytes, info: bytes, length: int = HKDF_LEN) -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hk.derive(key)

def aead_encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b""):
    nonce = secrets.token_bytes(NONCE_LEN); a = AESGCM(key)
    return nonce, a.encrypt(nonce, plaintext, aad)

def aead_decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b""):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

def aead_encrypt_chacha(key: bytes, plaintext: bytes, aad: bytes = b""):
    nonce = secrets.token_bytes(NONCE_LEN); c = ChaCha20Poly1305(key)
    return nonce, c.encrypt(nonce, plaintext, aad)

def aead_decrypt_chacha(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b""):
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = chmac.HMAC(key, hashes.SHA256()); h.update(data); return h.finalize()

def write_atomic(path: pathlib.Path, data: bytes, mode: int = 0o600):
    tmp = path.with_suffix(path.suffix + f".tmp-{secrets.token_hex(4)}")
    with open(tmp, "wb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    try: os.chmod(path, mode)
    except Exception: pass

def refuse_weak_perms(path: pathlib.Path, expected: int = 0o600):
    if os.name == "posix" and path.exists():
        if (path.stat().st_mode & 0o077) != 0:
            raise SystemExit(f"Permissões fracas detectadas em {path}. Execute: chmod 600 '{path}'")

def shred_path(p: pathlib.Path, passes: int = 3):
    if not p.exists(): return
    if p.is_dir():
        for root, dirs, files in os.walk(p, topdown=False):
            for name in files: shred_path(pathlib.Path(root)/name, passes)
            for name in dirs:
                try: os.rmdir(pathlib.Path(root)/name)
                except Exception: pass
        try: os.rmdir(p)
        except Exception: pass
        return
    size = p.stat().st_size
    try:
        with open(p, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0); f.write(os.urandom(size)); f.flush(); os.fsync(f.fileno())
        os.remove(p)
    except Exception:
        try: os.remove(p)
        except Exception: pass

def pack_header_dict(d: dict) -> bytes:
    return json.dumps(d, separators=(",", ":"), sort_keys=True).encode("utf-8")

def unpack_header_dict(bts: bytes) -> dict:
    return json.loads(bts.decode("utf-8"))

def tar_zstd(source: pathlib.Path) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        tar_path = pathlib.Path(td) / "data.tar"
        with tarfile.open(tar_path, "w") as tar:
            arcname = source.name
            tar.add(source, arcname=arcname)
        c = zstd.ZstdCompressor(level=10)
        with open(tar_path, "rb") as f:
            return c.compress(f.read())

# --------- Extração TAR segura (defense-in-depth) ---------
def _is_within_directory(base: pathlib.Path, target: pathlib.Path) -> bool:
    try:
        base = base.resolve(); target = target.resolve()
        return str(target).startswith(str(base) + os.sep)
    except Exception:
        return False

def safe_extractall(tar: tarfile.TarFile, path: pathlib.Path):
    for member in tar.getmembers():
        if member.islnk() or member.issym():
            raise RuntimeError(f"TAR contém link proibido: {member.name}")
        if member.name.startswith("/") or ".." in pathlib.Path(member.name).parts:
            raise RuntimeError(f"TAR com caminho suspeito: {member.name}")
        member_path = path / member.name
        if not _is_within_directory(path, member_path):
            raise RuntimeError(f"Escape de diretório detectado: {member.name}")
    tar.extractall(path=path)

def untar_zstd(blob: bytes, outdir: pathlib.Path):
    d = zstd.ZstdDecompressor()
    raw = d.decompress(blob)
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td) / "data.tar"
        with open(t, "wb") as f: f.write(raw)
        with tarfile.open(t, "r") as tar:
            safe_extractall(tar, outdir)

def add_random_padding(b: bytes, min_pad: int = 1024, max_pad: int = 65536) -> bytes:
    pad_len = secrets.choice(range(min_pad, max_pad + 1))
    pad = secrets.token_bytes(pad_len)
    return struct.pack(">I", pad_len) + b + pad

def remove_random_padding(b: bytes) -> bytes:
    pad_len = struct.unpack(">I", b[:4])[0]
    core = b[4:-pad_len] if pad_len else b[4:]
    return core

# ========================= TRIPLE AEAD =============================
def triple_encrypt(plaintext: bytes, dek1: bytes, dek2: bytes, dek3: bytes, aad: bytes):
    n1, c1 = aead_encrypt_aes_gcm(dek1, plaintext, aad)
    n2, c2 = aead_encrypt_chacha(dek2, n1 + c1, aad)
    n3, c3 = aead_encrypt_aes_gcm(dek3, n2 + c2, aad)
    return (n1, n2, n3), c3

def triple_decrypt(ciphertext: bytes, nonces, dek1: bytes, dek2: bytes, dek3: bytes, aad: bytes):
    n1, n2, n3 = nonces
    p2 = aead_decrypt_aes_gcm(dek3, n3, ciphertext, aad)
    n2r, c2 = p2[:NONCE_LEN], p2[NONCE_LEN:]
    if n2r != n2: raise ValueError("Integridade inválida (layer 3).")
    p1 = aead_decrypt_chacha(dek2, n2, c2, aad)
    n1r, c1 = p1[:NONCE_LEN], p1[NONCE_LEN:]
    if n1r != n1: raise ValueError("Integridade inválida (layer 2).")
    p0 = aead_decrypt_aes_gcm(dek1, n1, c1, aad)
    return p0

# ========================= KEYFILE (ENVELOPE) =============================
def hmac_compare(a: bytes, b: bytes) -> bool:
    try:
        import hmac as _h; return _h.compare_digest(a, b)
    except Exception:
        return a == b

def build_keyfile(passphrase: bytes, dek1: bytes, dek2: bytes, dek3: bytes, kdf_params: dict) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    kek = derive_kek(passphrase, salt)
    mac_k = hkdf_expand(kek, b"mac")
    payload = {
        "v": VERSION,
        "salt": salt.hex(),
        "kdf": {"algo":"scrypt","params":kdf_params},
        "dek": (dek1 + dek2 + dek3).hex()
    }
    blob = pack_header_dict(payload)
    tag = hmac_sha256(mac_k, blob)
    header = {"magic": MAGIC.hex(), "v": VERSION, "salt": salt.hex(), "wrap": "scrypt", "mac": tag.hex(), "blob": blob.hex()}
    return pack_header_dict(header)

def parse_keyfile(keyfile_bytes: bytes, passphrase: bytes):
    kfh = unpack_header_dict(keyfile_bytes)
    if bytes.fromhex(kfh.get("magic","")) != MAGIC:
        raise ValueError("Formato de keyfile inválido.")
    salt = bytes.fromhex(kfh["salt"])
    kek = derive_kek(passphrase, salt)
    mac_k = hkdf_expand(kek, b"mac")
    blob = bytes.fromhex(kfh["blob"])
    expected = bytes.fromhex(kfh["mac"])
    tag = hmac_sha256(mac_k, blob)
    if not hmac_compare(tag, expected):
        raise ValueError("Passphrase incorreta ou keyfile corrompido.")
    inner = unpack_header_dict(blob)
    if inner["v"] != VERSION:
        raise ValueError("Versão de keyfile incompatível.")
    deks = bytes.fromhex(inner["dek"])
    if len(deks) != 3*DEK_LEN:
        raise ValueError("Tamanho de DEKs inválido.")
    return deks[:DEK_LEN], deks[DEK_LEN:2*DEK_LEN], deks[2*DEK_LEN:3*DEK_LEN]

# ========================= PROTEÇÃO CREDENCIAIS & INTEGRIDADE ============
def get_machine_id() -> bytes:
    try:
        if sys.platform.startswith("linux"):
            p = pathlib.Path("/etc/machine-id")
            if p.exists(): return p.read_bytes().strip()
        if sys.platform.startswith("win"):
            return (platform.node() + platform.platform()).encode("utf-8")
    except Exception: pass
    return (platform.node() + platform.platform()).encode("utf-8")

def protect_credentials_init(master_pass: bytes):
    machine_id = get_machine_id()
    salt = secrets.token_bytes(SALT_LEN)
    kek = derive_kek(master_pass + machine_id, salt)
    mac_k = hkdf_expand(kek, b"tg_prot_mac")
    script_bytes = SCRIPT_PATH.read_bytes()
    script_hmac = hmac_sha256(mac_k, script_bytes)
    store = {"salt": salt.hex(), "hmac": script_hmac.hex(), "ts": int(time.time())}
    write_atomic(CRED_FILE, pack_header_dict(store), 0o600)
    cprint("Proteção de credenciais inicializada/atualizada (.tg_prot).", "OK")

def protect_credentials_verify(master_pass: bytes) -> bool:
    if not CRED_FILE.exists():
        cprint("Arquivo .tg_prot ausente — inicialize com: protection --init", "WARN")
        return False
    try:
        content = unpack_header_dict(CRED_FILE.read_bytes())
        salt = bytes.fromhex(content["salt"])
        machine_id = get_machine_id()
        kek = derive_kek(master_pass + machine_id, salt)
        mac_k = hkdf_expand(kek, b"tg_prot_mac")
        script_hmac = hmac_sha256(mac_k, SCRIPT_PATH.read_bytes())
        if not hmac_compare(script_hmac, bytes.fromhex(content["hmac"])):
            cprint("Integridade do script: INVÁLIDA.", "ERR"); return False
        cprint("Integridade do script: OK.", "OK"); return True
    except Exception as e:
        cprint(f"Erro ao verificar .tg_prot: {e}", "ERR"); return False

# ========================= BACKOFF PERSISTENTE ===========================
def _load_lock():
    if LOCK_FILE.exists():
        try: return json.loads(LOCK_FILE.read_text())
        except Exception: return {"fails":0,"until":0}
    return {"fails":0,"until":0}

def _save_lock(d):
    write_atomic(LOCK_FILE, json.dumps(d).encode(), 0o600)

def _check_backoff():
    now = int(time.time())
    lk = _load_lock()
    if now < lk.get("until", 0):
        wait = lk["until"] - now
        raise SystemExit(f"Backoff ativo. Aguarde {wait}s antes de tentar novamente.")
    return lk

def _register_fail(lk, cap_sec=30*60):
    now = int(time.time())
    lk["fails"] = lk.get("fails",0) + 1
    wait = min(cap_sec, (2**(lk["fails"]-1))*10)  # 10s, 20s, 40s, ...
    lk["until"] = now + wait
    _save_lock(lk)

# ========================= FLUXOS CLI (encrypt/decrypt/shred/protection) ==
def cmd_encrypt(args):
    src = pathlib.Path(args.input).resolve()
    out = pathlib.Path(args.output).resolve()
    keyout = pathlib.Path(args.keyfile).resolve()

    if not src.exists():
        cprint(f"Entrada não encontrada: {src}", "ERR"); raise SystemExit(2)
    if out.exists():
        cprint(f"Saída já existe: {out}", "ERR"); raise SystemExit(1)
    if keyout.exists():
        cprint(f"Keyfile já existe: {keyout}", "ERR"); raise SystemExit(1)

    passphrase = (args.passphrase or getpass.getpass("Passphrase (KEK): ")).encode("utf-8")
    confirm = (args.passphrase or getpass.getpass("Confirme a passphrase: ")).encode("utf-8")
    if passphrase != confirm:
        cprint("As passphrases não coincidem.", "ERR"); raise SystemExit(1)

    cprint("Empacotando e comprimindo entrada...", "INFO")
    if src.is_dir():
        blob = tar_zstd(src)
    else:
        with open(src, "rb") as f: raw = f.read()
        c = zstd.ZstdCompressor(level=10); blob = c.compress(raw)

    blob = add_random_padding(blob)
    dek1, dek2, dek3 = (secrets.token_bytes(DEK_LEN) for _ in range(3))

    # AAD com modo OPSEC
    meta = {"magic": MAGIC.hex(), "v": VERSION, "is_dir": src.is_dir()}
    if not args.opsec:
        meta.update({"ts": int(time.time()), "src_name": src.name})
    aad = pack_header_dict(meta)

    nonces, c3 = triple_encrypt(blob, dek1, dek2, dek3, aad)
    enc_header = {"magic": MAGIC.hex(), "v": VERSION, "n1": nonces[0].hex(), "n2": nonces[1].hex(), "n3": nonces[2].hex(), "aad": aad.hex()}
    enc_bytes = pack_header_dict(enc_header) + b"\n" + c3
    write_atomic(out, enc_bytes, 0o600)
    refuse_weak_perms(out)

    kdf_params = {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
    key_bytes = build_keyfile(passphrase, dek1, dek2, dek3, kdf_params)
    write_atomic(keyout, key_bytes, 0o600)
    refuse_weak_perms(keyout)

    cprint(f"Criptografia concluída: {out}", "OK")
    cprint(f"Keyfile criado (GUARDE em local separado): {keyout}", "OK")

def cmd_decrypt(args):
    enc = pathlib.Path(args.input).resolve()
    keyfile = pathlib.Path(args.keyfile).resolve()
    out = pathlib.Path(args.output).resolve()

    if not enc.exists():
        cprint(f".enc não encontrado: {enc}", "ERR"); raise SystemExit(2)
    if not keyfile.exists():
        cprint(f"Keyfile não encontrado: {keyfile}", "ERR"); raise SystemExit(2)
    if out.exists():
        cprint(f"Saída já existe: {out}", "ERR"); raise SystemExit(1)
    refuse_weak_perms(keyfile)

    # backoff persistente (antes de pedir senha)
    lk = _check_backoff()

    with open(enc, "rb") as f:
        head = f.readline().rstrip(b"\n"); c3 = f.read()
    try:
        enc_header = unpack_header_dict(head)
    except Exception:
        cprint(".enc corrompido ou cabeçalho inválido.", "ERR"); raise SystemExit(1)
    if bytes.fromhex(enc_header.get("magic","")) != MAGIC:
        cprint("Formato .enc inválido.", "ERR"); raise SystemExit(1)

    aad = bytes.fromhex(enc_header["aad"])
    nonces = (bytes.fromhex(enc_header["n1"]), bytes.fromhex(enc_header["n2"]), bytes.fromhex(enc_header["n3"]))
    max_fail = args.max_fail; failures = 0

    while True:
        try:
            pstr = (args.passphrase or getpass.getpass("Passphrase (KEK): ")).encode("utf-8")
            dek1, dek2, dek3 = parse_keyfile(keyfile.read_bytes(), pstr)
            plaintext = triple_decrypt(c3, nonces, dek1, dek2, dek3, aad)
            # sucesso: limpa lock
            _save_lock({"fails":0,"until":0})
            break
        except Exception as e:
            failures += 1
            _register_fail(lk)
            cprint(f"Tentativa {failures}/{max_fail} falhou: {e}", "ERR")
            if args.trap and failures >= max_fail:
                cprint(f"[TRAP] {failures} falhas — destruindo keyfile: {keyfile}", "WARN")
                try: shred_path(keyfile)
                finally:
                    cprint("Keyfile destruído. Ciphertext tornou-se inútil.", "WARN")
                    raise SystemExit(23)
            if failures >= max_fail:
                cprint(f"Máximo de tentativas atingido ({max_fail}).", "ERR"); raise SystemExit(1)

    core = remove_random_padding(plaintext)
    meta = json.loads(bytes.fromhex(enc_header["aad"]).decode("utf-8"))
    is_dir = meta.get("is_dir", False)

    if is_dir:
        out.mkdir(parents=True, exist_ok=False)
        untar_zstd(core, out)
    else:
        d = zstd.ZstdDecompressor(); raw = d.decompress(core)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f: f.write(raw)
        refuse_weak_perms(out)

    cprint(f"Decriptação concluída em: {out}", "OK")

def cmd_shred(args):
    p = pathlib.Path(args.path).resolve()
    if not p.exists():
        cprint(f"Caminho não encontrado: {p}", "ERR"); raise SystemExit(2)
    shred_path(p, passes=args.passes)
    cprint(f"Shred concluído: {p}", "OK")

def cmd_protection(args):
    if args.init:
        master_pass = (args.passphrase or getpass.getpass("Passphrase mestre (proteção): ")).encode("utf-8")
        if not master_pass: cprint("Passphrase vazia.", "ERR"); raise SystemExit(1)
        if CRED_FILE.exists() and not args.force:
            cprint(".tg_prot já existe. Use --force para recriar.", "WARN"); raise SystemExit(1)
        protect_credentials_init(master_pass); return
    if args.verify:
        master_pass = (args.passphrase or getpass.getpass("Passphrase mestre (verificação): ")).encode("utf-8")
        ok = protect_credentials_verify(master_pass)
        if not ok: cprint("Verificação falhou.", "ERR"); raise SystemExit(5)
        return
    cprint("Use --init para criar proteção ou --verify para checar integridade.", "INFO")

# ========================= ARGPARSE & SAFE RUNNER =========================
def build_argparser():
    parser = argparse.ArgumentParser(
        prog="triple_guard.py",
        description="Triple Guard - Criptografia tripla com armadilha e hardenings 2025.",
        epilog=(
            "Exemplos:\n"
            "  Encrypt (opsec): triple_guard.py encrypt -i dados -o dados.enc -k dados.key --opsec\n"
            "  Decrypt com armadilha: triple_guard.py decrypt -i dados.enc -k dados.key -o restaure --trap --max-fail 3\n"
            "  Shred: triple_guard.py shred -p dados.key\n"
            "  Proteção: triple_guard.py protection --init\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    # flags globais informativas
    parser.add_argument("--no-auto-install", action="store_true", help="Não instalar dependências automaticamente (global).")
    parser.add_argument("--requirements", metavar="ARQ", help="Instalar deps a partir de requirements.txt (com hashes).")

    sub = parser.add_subparsers(dest="cmd", required=True, help="Comando a executar")

    pe = sub.add_parser("encrypt", help="Criptografar arquivo ou pasta")
    pe.add_argument("-i","--input", required=True, help="Arquivo/pasta de entrada")
    pe.add_argument("-o","--output", required=True, help="Arquivo .enc de saída")
    pe.add_argument("-k","--keyfile", required=True, help="Arquivo .key (será criado)")
    pe.add_argument("--passphrase", help="Passphrase (não recomendado passar em CLI)")
    pe.add_argument("--opsec", action="store_true", help="Minimiza metadados (sem nome/timestamp)")
    pe.set_defaults(func=cmd_encrypt)

    pd = sub.add_parser("decrypt", help="Descriptografar arquivo/pasta")
    pd.add_argument("-i","--input", required=True, help="Arquivo .enc")
    pd.add_argument("-k","--keyfile", required=True, help="Arquivo .key correspondente")
    pd.add_argument("-o","--output", required=True, help="Caminho de saída")
    pd.add_argument("--passphrase", help="Passphrase (não recomendado passar em CLI)")
    pd.add_argument("--trap", action="store_true", help="Ativa armadilha: destrói .key após falhas")
    pd.add_argument("--max-fail", type=int, default=3, help="Tentativas permitidas antes da ação (--trap ou saída)")
    pd.set_defaults(func=cmd_decrypt)

    ps = sub.add_parser("shred", help="Sobrescrever e apagar arquivo/pasta")
    ps.add_argument("-p","--path", required=True, help="Caminho a destruir")
    ps.add_argument("--passes", type=int, default=3, help="Número de sobrescritas (não garante em SSD)")
    ps.set_defaults(func=cmd_shred)

    prot = sub.add_parser("protection", help="Gerenciar proteção/integridade do script")
    prot.add_argument("--init", action="store_true", help="Inicializa/atualiza proteção (.tg_prot)")
    prot.add_argument("--verify", action="store_true", help="Verifica integridade do script com .tg_prot")
    prot.add_argument("--force", action="store_true", help="Força recriação de .tg_prot")
    prot.add_argument("--passphrase", help="Passphrase mestre")
    prot.set_defaults(func=cmd_protection)

    return parser

def safe_run(func, args):
    try:
        func(args)
    except KeyboardInterrupt:
        cprint("Operação interrompida pelo usuário.", "WARN"); raise SystemExit(130)
    except FileNotFoundError as e:
        cprint(f"Arquivo não encontrado: {e.filename}", "ERR"); raise SystemExit(2)
    except PermissionError as e:
        cprint(f"Permissão negada: {e.filename}", "ERR"); raise SystemExit(3)
    except SystemExit:
        raise
    except Exception as e:
        cprint(f"Erro inesperado: {e}", "ERR"); raise SystemExit(1)

# ========================= MAIN =========================
def main():
    harden_process()
    parser = build_argparser()
    args = parser.parse_args()

    # ecoa flags globais (informativo – já aplicadas no pré-parse)
    if args.no_auto_install: cprint("Aviso: --no-auto-install ativo.", "INFO")
    if args.requirements: cprint(f"Requisitos usados: {args.requirements}", "INFO")

    # Se existir .tg_prot e comando não for 'protection', exija verificação
    if CRED_FILE.exists() and args.cmd != "protection":
        cprint("Proteção detectada (.tg_prot). Verificando integridade...", "INFO")
        master_pass = getpass.getpass("Passphrase mestre (verificação): ").encode("utf-8")
        if not protect_credentials_verify(master_pass):
            cprint("Falha na verificação de integridade. Abortando.", "ERR"); raise SystemExit(6)

    safe_run(args.func, args)

if __name__ == "__main__":
    main()

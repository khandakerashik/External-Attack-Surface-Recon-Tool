"""Active TLS posture check (stdlib ssl): certificate validity, expiry, self-signed,
hostname match, legacy protocol support. One handshake per protocol per endpoint."""
import concurrent.futures as cf
import datetime
import os
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlparse

from .util import log, read_jsonl, write_json

LEGACY = {"TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1_1"}


def _decode_der(der):
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        path = fh.name
    try:
        try:
            return ssl._ssl._test_decode_cert(path)  # CPython helper; stable for years
        except Exception:
            out = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-startdate",
                                  "-ext", "subjectAltName", "-in", path], capture_output=True, text=True, timeout=10)
            return {"_openssl_text": out.stdout}
    finally:
        os.unlink(path)


def _name(rdns):
    flat = {}
    for rdn in rdns or ():
        for k, v in rdn:
            flat[k] = v
    return flat


def _probe_version(host, port, proto, timeout):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ver = getattr(ssl.TLSVersion, proto)
        ctx.minimum_version = ver
        ctx.maximum_version = ver
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, AttributeError, ssl.SSLError):
        return None  # local OpenSSL cannot test this protocol
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        if "no protocols available" in str(exc).lower():
            return None
        return False
    except OSError:
        return False


def check(host, port=443, timeout=8):
    res = {"host": host, "port": port, "checked": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    # 1) Default handshake without verification: fetch cert + negotiated params
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                res["negotiated_protocol"] = tls.version()
                c = tls.cipher()
                res["cipher"] = c[0] if c else ""
                res["cipher_bits"] = c[2] if c else None
    except (OSError, ssl.SSLError) as exc:
        res["error"] = f"{exc.__class__.__name__}: {exc}"[:200]
        return res
    if der:
        cert = _decode_der(der)
        subj, iss = _name(cert.get("subject")), _name(cert.get("issuer"))
        res["subject_cn"] = subj.get("commonName", "")
        res["issuer"] = iss.get("organizationName") or iss.get("commonName", "")
        res["issuer_cn"] = iss.get("commonName", "")
        res["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:100]
        res["not_before"] = cert.get("notBefore", "")
        res["not_after"] = cert.get("notAfter", "")
        res["self_signed"] = bool(subj) and subj == iss
        if res["not_after"]:
            try:
                exp = ssl.cert_time_to_seconds(res["not_after"])
                res["days_to_expiry"] = int((exp - time.time()) // 86400)
            except ValueError:
                pass
    # 2) Verified handshake: trust chain + hostname
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                res["trusted"] = True
                res["hostname_match"] = True
    except ssl.SSLCertVerificationError as exc:
        res["trusted"] = False
        res["verify_error"] = (exc.verify_message or str(exc))[:200]
        res["hostname_match"] = "hostname mismatch" not in str(exc).lower() and "doesn't match" not in str(exc).lower()
    except (OSError, ssl.SSLError) as exc:
        res["verify_error"] = f"{exc.__class__.__name__}: {exc}"[:200]
    # 3) Legacy protocol support
    res["protocols"] = {}
    for label, proto in LEGACY.items():
        res["protocols"][label] = _probe_version(host, port, proto, timeout)
        time.sleep(0.2)
    res["protocols"]["TLSv1.3"] = _probe_version(host, port, "TLSv1_3", timeout)
    return res


def run(run_dir, workers=4):
    endpoints = set()
    for row in read_jsonl(f"{run_dir}/http/httpx.jsonl"):
        url = row.get("url") or ""
        u = urlparse(url)
        if u.scheme == "https" and u.hostname:
            endpoints.add((u.hostname, u.port or 443))
    endpoints = sorted(endpoints)
    log(f"TLS checks on {len(endpoints)} HTTPS endpoint(s)")
    results = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(lambda hp: check(*hp), endpoints):
            results.append(r)
    write_json(f"{run_dir}/tls/tls.json", results)
    return 0

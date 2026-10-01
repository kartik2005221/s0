"""Command-line entry points: s0-keygen / -sign / -verify / -cert-pdf.

These are the out-of-band tools the issuing authority uses. The wipe CLI
(src/s0) imports the library directly; it does not shell out to these.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import crypto, pdfgen
from .certificate import verify_certificate


def _cmd_keygen(args) -> int:

    from .certificate import now_utc  # noqa: F401  (import keeps parity with docs)

    priv = crypto.generate_private_key()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = crypto.write_private_pem(priv, out_dir / f"{args.name}_private.pem")
    pub_path = crypto.write_public_pem(priv.public_key(), out_dir / f"{args.name}_public.pem")
    print(f"private key : {priv_path}  (mode 600 — NEVER commit or ship this)")
    print(f"public key  : {pub_path}")
    print(f"fingerprint : {crypto.public_key_fingerprint(priv.public_key())}")
    print()
    print("Pin the PUBLIC key in verifiers (portal keys.json, CLI --key).")
    print("The private key belongs to the issuing authority only — see src/s0/data/keys/README.md.")
    return 0


def _load_cert(path: Path) -> dict:
    try:
        cert = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid JSON: {exc}") from exc
    if not isinstance(cert, dict):
        raise SystemExit(f"error: {path} does not contain a JSON object")
    return cert


def _cmd_sign(args) -> int:
    cert = _load_cert(Path(args.cert))
    key = crypto.load_private_pem(Path(args.key))
    from .certificate import CertificateError, sign_certificate

    try:
        signed = sign_certificate(cert, key)
    except CertificateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else Path(args.cert).with_suffix(".signed.json")
    out.write_text(json.dumps(signed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"signed -> {out}")
    return 0


def _cmd_verify(args) -> int:
    cert = _load_cert(Path(args.cert))
    keys = [crypto.load_public_pem(p) for p in args.key]
    ok, reason = verify_certificate(cert, keys)
    print(("PASS: " if ok else "FAIL: ") + reason)
    return 0 if ok else 1


def _cmd_pdf(args) -> int:
    cert = _load_cert(Path(args.cert))
    path = pdfgen.generate_pdf(
        cert, Path(args.out),
        qr_url_template=args.qr_url_template,
    )
    if args.qr_png:
        pdfgen.write_qr_file(cert, Path(args.qr_png))
    print(f"pdf -> {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="s0-tool", description="s0 certificate tooling")
    sub = p.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="generate an Ed25519 issuer keypair (out-of-band step)")
    kg.add_argument("--out-dir", default="src/s0/data/keys")
    kg.add_argument("--name", default="issuer",
                    help="file stem, e.g. 'demo_issuer' -> demo_issuer_private.pem / _public.pem")
    kg.set_defaults(func=_cmd_keygen)

    sg = sub.add_parser("sign", help="sign a certificate JSON")
    sg.add_argument("--cert", required=True)
    sg.add_argument("--key", required=True)
    sg.add_argument("--out")
    sg.set_defaults(func=_cmd_sign)

    vf = sub.add_parser("verify", help="verify a signed certificate against pinned public keys")
    vf.add_argument("--cert", required=True)
    vf.add_argument("--key", action="append", required=True,
                    help="trusted public key PEM (repeatable)")
    vf.set_defaults(func=_cmd_verify)

    pf = sub.add_parser("pdf", help="render a signed certificate to PDF (+ optional QR PNG)")
    pf.add_argument("--cert", required=True)
    pf.add_argument("--out", default="certificate.pdf")
    pf.add_argument("--qr-png")
    pf.add_argument("--qr-url-template", default=pdfgen.QR_URL_TEMPLATE_DEFAULT)
    pf.set_defaults(func=_cmd_pdf)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


def keygen_main() -> int:
    return main(["keygen"] + sys.argv[1:])


def sign_main() -> int:
    return main(["sign"] + sys.argv[1:])


def verify_main() -> int:
    return main(["verify"] + sys.argv[1:])


def pdf_main() -> int:
    return main(["pdf"] + sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())

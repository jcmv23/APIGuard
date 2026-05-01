"""
APIGuard - Main Entry Point (Enterprise Edition v4.0)
======================================================
Runs all 15 modules in sequence and generates dashboard + reports.

Quick start
-----------
python main.py \
    --url  https://api.example.com \
    --spec openapi.json \
    --token-a  "Bearer eyJ..." \
    --id-a 123 --id-b 456 \
    --low-priv-token "Bearer eyJ..." \
    --html report.html --pdf report.pdf --output report.json
"""

import argparse, json, sys, time, io
from pathlib import Path

if sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from module_1_parser.parser import OpenAPIParser
from module_2_bola.bola_scanner import BOLAScanner
from module_3_bfla.bfla_scanner import BFLAScanner
from module_4_auth.auth_scanner import AuthScanner
from module_5_ratelimit.rate_scanner import RateLimitScanner
from module_6_injection.injection_scanner import InjectionScanner
from module_7_dashboard.report_generator import ReportGenerator
from module_8_ssl.ssl_scanner import SSLScanner
from module_9_graphql.graphql_scanner import GraphQLScanner
from module_10_data_exposure.data_scanner import DataExposureScanner
from module_11_fuzzer.advanced_fuzzer import AdvancedFuzzer
from module_12_jwt.jwt_analyzer import JWTAnalyzer
from module_13_secrets.secret_scanner import SecretScanner
from module_14_waf.waf_detector import WAFDetector
from module_15_spec.spec_validator import SpecValidator


def build_parser():
    p = argparse.ArgumentParser(prog="apiguard", description="APIGuard Enterprise – REST API Security Scanner v2.0")
    p.add_argument("--url",  required=True)
    p.add_argument("--spec", default=None)
    p.add_argument("--token-a",        default=None, help="User A token (BOLA)")
    p.add_argument("--id-a",           default="1")
    p.add_argument("--id-b",           default="2")
    p.add_argument("--low-priv-token", default=None, help="Low-priv token (BFLA)")
    p.add_argument("--admin-token",    default=None)
    p.add_argument("--auth-token",     default=None, help="JWT to analyse (Module 4)")
    p.add_argument("--output",         default=None, help="JSON report path")
    p.add_argument("--html",           default=None, help="HTML dashboard path")
    p.add_argument("--pdf",            default=None, help="PDF report path")
    p.add_argument("--history-db",     default="apiguard_history.db")
    p.add_argument("--no-history",     action="store_true")
    p.add_argument("--timeout",        type=int,   default=10)
    p.add_argument("--delay",          type=float, default=0.1)
    p.add_argument("--rate-requests",  type=int,   default=50)
    p.add_argument("--skip-ssl",       action="store_true", help="Skip SSL/TLS module")
    p.add_argument("--skip-graphql",   action="store_true", help="Skip GraphQL module")
    p.add_argument("--skip-data",      action="store_true", help="Skip Data Exposure module")
    p.add_argument("--skip-fuzzer",    action="store_true", help="Skip Advanced Fuzzer module")
    p.add_argument("--skip-jwt",       action="store_true", help="Skip JWT Analyzer module")
    p.add_argument("--skip-secrets",   action="store_true", help="Skip Secret Scanner module")
    p.add_argument("--skip-waf",       action="store_true", help="Skip WAF Detector module")
    p.add_argument("--skip-spec",      action="store_true", help="Skip Spec Validator module")
    p.add_argument("--notify",         action="store_true", help="Send webhook notifications")
    return p


def run(args) -> dict:
    report = {
        "tool": "APIGuard Enterprise", "version": "4.0",
        "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": args.url, "modules": {},
    }

    print(f"\n{'═' * 60}")
    print(f"  🛡️  APIGuard Enterprise Security Scanner v4.0")
    print(f"  Target: {args.url}")
    print(f"  Modules: 15 active")
    print(f"{'═' * 60}")

    # 1 — Parser
    print("\n[1/9] Parsing OpenAPI spec …")
    try:
        parser = OpenAPIParser(base_url=args.url, spec=args.spec, timeout=args.timeout)
        endpoints = parser.parse()
        print(f"      ✅  {len(endpoints)} endpoints discovered")
        print(parser.summary())
        report["modules"]["parser"] = parser.to_dict()
    except Exception as e:
        print(f"      ❌  Parser failed: {e}", file=sys.stderr); sys.exit(1)

    # 2 — BOLA
    print("\n[2/9] BOLA scan …")
    if args.token_a:
        r = BOLAScanner(token_user_a=args.token_a, id_user_a=args.id_a,
                        id_user_b=args.id_b, timeout=args.timeout,
                        delay_between_requests=args.delay).scan(endpoints)
        print(r.summary()); report["modules"]["module_2_bola"] = r.to_dict()
    else:
        print("      ⚠️  --token-a not provided, skipping.")
        report["modules"]["module_2_bola"] = {"skipped": True, "findings": []}

    # 3 — BFLA
    print("\n[3/9] BFLA scan …")
    if args.low_priv_token:
        r = BFLAScanner(low_priv_token=args.low_priv_token, admin_token=args.admin_token,
                        timeout=args.timeout, delay_between_requests=args.delay).scan(endpoints)
        print(r.summary()); report["modules"]["module_3_bfla"] = r.to_dict()
    else:
        print("      ⚠️  --low-priv-token not provided, skipping.")
        report["modules"]["module_3_bfla"] = {"skipped": True, "findings": []}

    # 4 — Auth/JWT
    print("\n[4/9] Auth/JWT scan …")
    r = AuthScanner(valid_token=args.auth_token or args.token_a,
                    timeout=args.timeout, delay=args.delay).scan(endpoints)
    print(r.summary()); report["modules"]["module_4_auth"] = r.to_dict()

    # 5 — Rate Limiting
    print("\n[5/9] Rate Limiting scan …")
    r = RateLimitScanner(token=args.token_a, timeout=args.timeout,
                         requests_to_send=args.rate_requests).scan(endpoints)
    print(r.summary()); report["modules"]["module_5_ratelimit"] = r.to_dict()

    # 6 — Injection/CORS
    print("\n[6/9] Injection/Secrets/CORS scan …")
    r = InjectionScanner(token=args.token_a, timeout=args.timeout,
                         delay=args.delay).scan(endpoints)
    print(r.summary()); report["modules"]["module_6_injection"] = r.to_dict()

    # 7 — SSL/TLS (NEW)
    if not getattr(args, 'skip_ssl', False):
        print("\n[7/9] SSL/TLS scan …")
        r = SSLScanner(timeout=args.timeout).scan(args.url)
        print(r.summary()); report["modules"]["module_8_ssl"] = r.to_dict()
    else:
        print("\n[7/9] SSL/TLS scan … ⚠️ Skipped")

    # 8 — GraphQL (NEW)
    if not getattr(args, 'skip_graphql', False):
        print("\n[8/9] GraphQL scan …")
        r = GraphQLScanner(token=args.token_a, timeout=args.timeout).scan(args.url)
        print(r.summary()); report["modules"]["module_9_graphql"] = r.to_dict()
    else:
        print("\n[8/9] GraphQL scan … ⚠️ Skipped")

    # 9 — Data Exposure
    if not getattr(args, 'skip_data', False):
        print("\n[9/14] Data Exposure scan …")
        r = DataExposureScanner(token=args.token_a, timeout=args.timeout,
                                delay=args.delay).scan(endpoints)
        print(r.summary()); report["modules"]["module_10_data_exposure"] = r.to_dict()
    else:
        print("\n[9/14] Data Exposure scan … ⚠️ Skipped")

    # 10 — Advanced Fuzzer (NEW v4.0)
    if not getattr(args, 'skip_fuzzer', False):
        print("\n[10/14] Advanced Fuzzer scan …")
        r = AdvancedFuzzer(token=args.token_a, timeout=args.timeout,
                           delay=args.delay).scan(endpoints)
        print(r.summary()); report["modules"]["module_11_fuzzer"] = r.to_dict()
    else:
        print("\n[10/14] Advanced Fuzzer … ⚠️ Skipped")

    # 11 — JWT Analyzer (NEW v4.0)
    if not getattr(args, 'skip_jwt', False):
        print("\n[11/14] JWT Security Analysis …")
        jwt_token = args.auth_token or args.token_a
        r = JWTAnalyzer(token=jwt_token, target_url=args.url, timeout=args.timeout).scan()
        print(r.summary()); report["modules"]["module_12_jwt"] = r.to_dict()
    else:
        print("\n[11/14] JWT Analyzer … ⚠️ Skipped")

    # 12 — Secret Scanner (NEW v4.0)
    if not getattr(args, 'skip_secrets', False):
        print("\n[12/14] Secret Scanner …")
        r = SecretScanner(token=args.token_a, timeout=args.timeout,
                          delay=args.delay).scan(endpoints)
        print(r.summary()); report["modules"]["module_13_secrets"] = r.to_dict()
    else:
        print("\n[12/14] Secret Scanner … ⚠️ Skipped")

    # 13 — WAF Detector (NEW v4.0)
    if not getattr(args, 'skip_waf', False):
        print("\n[13/14] WAF Detection …")
        r = WAFDetector(token=args.token_a, timeout=args.timeout).scan(endpoints)
        print(r.summary()); report["modules"]["module_14_waf"] = r.to_dict()
    else:
        print("\n[13/14] WAF Detector … ⚠️ Skipped")

    # 14 — Spec vs Reality Validator (NEW v4.0)
    if not getattr(args, 'skip_spec', False):
        print("\n[14/14] Spec vs Reality Validation …")
        r = SpecValidator(token=args.token_a, timeout=args.timeout,
                          delay=args.delay).scan(endpoints)
        print(r.summary()); report["modules"]["module_15_spec"] = r.to_dict()
    else:
        print("\n[14/14] Spec Validator … ⚠️ Skipped")

    # ── Reports ───────────────────────────────
    print("\n[REPORT] Generating reports …")
    gen = ReportGenerator(report)
    gen.print_summary()

    html_out = args.html or "apiguard_report.html"
    gen.save_html(html_out)
    print(f"      📊  HTML dashboard → {html_out}")

    if args.pdf:
        gen.save_pdf(args.pdf)
        print(f"      📄  PDF report    → {args.pdf}")

    if args.output:
        gen.save_json(args.output)
        print(f"      📦  JSON export   → {args.output}")

    if not args.no_history:
        scan_id = gen.save_to_history(args.history_db)
        print(f"      🗄️   History saved  (ID={scan_id}) → {args.history_db}")

    # Webhook notifications
    if getattr(args, 'notify', False):
        from integrations.webhooks import notify_all
        results = notify_all(report)
        active = [k for k, v in results.items() if v]
        if active:
            print(f"      📡  Notifications sent → {', '.join(active)}")

    return report


if __name__ == "__main__":
    run(build_parser().parse_args())
import os
import time
import random
import traceback
import pyfiglet # type: ignore


class TerminalExecutor:
    def __init__(self):
        # 60+ mocked/functional commands mapped to actions
        self.commands = {
            "help": self.cmd_help,
            "man": self.cmd_help,
            "scan": self.cmd_scan,
            "ping": self.cmd_ping,
            "clear": self.cmd_clear,
            "whoami": self.cmd_whoami,
            "date": self.cmd_date,
            "uptime": self.cmd_uptime,
            "uname": self.cmd_uname,
            "echo": self.cmd_echo,
            "ls": self.cmd_ls,
            "pwd": self.cmd_pwd,
            "cd": self.cmd_cd,
            "cat": self.cmd_cat,
            "grep": self.cmd_grep,
            "chmod": self.cmd_chmod,
            "chown": self.cmd_chown,
            "ps": self.cmd_ps,
            "top": self.cmd_top,
            "env": self.cmd_env,
            "sudo": self.cmd_sudo,
            "su": self.cmd_su,
            "ifconfig": self.cmd_ifconfig,
            "netstat": self.cmd_netstat,
            "route": self.cmd_route,
            "arp": self.cmd_arp,
            "dig": self.cmd_dig,
            "nslookup": self.cmd_nslookup,
            "curl": self.cmd_curl,
            "wget": self.cmd_wget,
            "nc": self.cmd_nc,
            "ssh": self.cmd_ssh,
            "telnet": self.cmd_telnet,
            "tcpdump": self.cmd_tcpdump,
            "wireshark": self.cmd_unsupported,
            "nmap": self.cmd_nmap,
            "sqlmap": self.cmd_sqlmap,
            "nikto": self.cmd_nikto,
            "dirb": self.cmd_dirb,
            "hydra": self.cmd_hydra,
            "metasploit": self.cmd_unsupported,
            "msfconsole": self.cmd_msf,
            "python": self.cmd_python,
            "node": self.cmd_node,
            "npm": self.cmd_unsupported,
            "docker": self.cmd_docker,
            "git": self.cmd_git,
            "history": self.cmd_history,
            "db": self.cmd_db,
            "users": self.cmd_users,
            "hacker": self.cmd_hacker,
            "matrix": self.cmd_matrix,
            "root": self.cmd_sudo,
            "apiguard": self.cmd_apiguard,
            "exit": self.cmd_exit,
            # ── New Enterprise Commands ──────────
            "status": self.cmd_status,
            "modules": self.cmd_modules,
            "ssl": self.cmd_ssl_check,
            "graphql": self.cmd_graphql_check,
            "webhook": self.cmd_webhook,
            "audit": self.cmd_audit,
            "config": self.cmd_config,
            "metrics": self.cmd_metrics,
            "version": self.cmd_version,
            "health": self.cmd_health,
            "cve": self.cmd_cve,
            "owasp": self.cmd_owasp,
            "report": self.cmd_report,
            "export": self.cmd_export,
            "compliance": self.cmd_compliance,
        }

    def execute(self, command_line: str, context: str = None, user_info: dict = None) -> dict:
        command_line = command_line.strip()
        if not command_line:
            return {"output": [], "requiresInput": False, "context": None}

        # Handle interactive states
        if context == "hacker":
            if not command_line:
                return {"output": ["Canceled."], "requiresInput": False, "context": None}
            out = []
            if pyfiglet:
                try:
                    f = pyfiglet.Figlet(font='slant')
                    render = f.renderText(command_line)
                    for line in render.split('\n'):
                        out.append(f"[HACKER]{line}")
                except Exception as e:
                    out.append(f"[ERROR] Figlet generation failed: {e}")
            else:
                out.append(f"[HACKER]============= {command_line.upper()} =============")
            return {"output": out, "requiresInput": False, "context": None}

        parts = command_line.split()
        base_cmd = parts[0].lower()
        args = parts[1:]

        if base_cmd in self.commands:
            try:
                res = self.commands[base_cmd](args, user_info)
                return res
            except Exception as e:
                return {"output": [f"[CRITICAL_ERROR] Execution failed: {str(e)}", traceback.format_exc()], "requiresInput": False, "context": None}
        else:
            return {"output": [f"apiguard: command not found: {base_cmd}", "Type 'help' to see available commands."], "requiresInput": False, "context": None}

    # ---- Command Handlers ----
    def _create_res(self, lines, requires_input=False, ctx=None):
        return {"output": lines, "requiresInput": requires_input, "context": ctx}

    def cmd_help(self, args, user_info):
        out = [
            "APIGuard Enterprise Terminal [Version 2.5.0]",
            "Available commands system-wide (~65 installed):",
            "  System     : whoami, uname, date, uptime, clear, top, ps, env, echo, pwd, ls, cd, exit",
            "  Files      : cat, grep, chmod, chown",
            "  Networking : ping, netstat, ifconfig, route, arp, dig, nslookup, curl, wget, nc, ssh, tcpdump",
            "  Offensive  : scan, nmap, sqlmap, nikto, dirb, hydra, msfconsole",
            "  Admin/DB   : db, history, users, audit, config",
            "  Enterprise : status, modules, ssl, graphql, webhook, metrics, health, version",
            "  Compliance : owasp, compliance, cve, report, export",
            "  Utilities  : hacker, matrix, sudo, apiguard",
            "",
            "Try: 'modules' for scanner info, 'status' for system health, 'owasp' for Top 10 info"
        ]
        return self._create_res(out)

    def cmd_hacker(self, args, user_info):
        return self._create_res(["[INTERACTIVE] Activating hacker renderer...", "Please type the text you wish to render as banner:"], requires_input=True, ctx="hacker")

    def cmd_whoami(self, args, user_info):
        if user_info:
            role = user_info.get("role", "guest")
            name = user_info.get("name", "unknown")
            return self._create_res([f"User: {name}", f"Role: {role}", "Uid: 0 (virtual) \nGroups: root, admin"])
        return self._create_res(["root"])

    def cmd_date(self, args, user_info):
        return self._create_res([time.strftime("%a %b %d %H:%M:%S UTC %Y", time.gmtime())])

    def cmd_uptime(self, args, user_info):
        return self._create_res([f" {time.strftime('%H:%M:%S')} up {random.randint(1, 100)} days,  {random.randint(1, 4)} users,  load average: {random.uniform(0.1, 1.5):.2f}, {random.uniform(0.1, 1.5):.2f}, {random.uniform(0.1, 1.5):.2f}"])

    def cmd_uname(self, args, user_info):
        return self._create_res(["Linux apiguard-enterprise 6.1.0-22-generic x86_64 GNU/Linux"])

    def cmd_ping(self, args, user_info):
        if not args:
            return self._create_res(["ping: usage error: Destination address required"])
        target = args[0]
        return self._create_res([
            f"PING {target} (192.168.x.x) 56(84) bytes of data.",
            f"64 bytes from {target}: icmp_seq=1 ttl=54 time=14.2 ms",
            f"64 bytes from {target}: icmp_seq=2 ttl=54 time=13.8 ms",
            f"64 bytes from {target}: icmp_seq=3 ttl=54 time=16.5 ms",
            "--- ping statistics ---",
            "3 packets transmitted, 3 received, 0% packet loss"
        ])

    def cmd_scan(self, args, user_info):
        return self._create_res([
            "APIGuard Enterprise Scanner v2.0 Initiated...",
            "WARNING: Manual CLI triggers override background UI state.",
            "Available modules: parser, bola, bfla, auth, rate, injection, ssl, graphql, data_exposure",
            "To scan via API: POST /api/v1/scan with JSON body",
            "To scan via CLI: python main.py --url <target> [options]"
        ])

    def cmd_clear(self, args, user_info):
        return self._create_res(["[ACTION_CLEAR]"])

    def cmd_matrix(self, args, user_info):
        lines = []
        for _ in range(25):
            line = "".join([random.choice("01 !@#$%^&*()") for _ in range(80)])
            lines.append(line)
        lines.append("[SYSTEM] Matrix buffer cleared.")
        return self._create_res(lines)

    def cmd_sudo(self, args, user_info):
        return self._create_res([f"apiguard is not in the sudoers file. This incident will be reported."])
        
    def cmd_echo(self, args, user_info):
        return self._create_res([" ".join(args)])
        
    def cmd_pwd(self, args, user_info):
        return self._create_res(["/opt/apiguard/enterprise/engine/v2/"])
        
    def cmd_ls(self, args, user_info):
        return self._create_res([
            "bin/   core/   integrations/   logs/   config.yaml",
            "db/    modules/   reports/   history.sqlite   certs/"
        ])

    def cmd_history(self, args, user_info):
        return self._create_res([
            "Fetching recent executed jobs:",
            " 1   module_parser_check         2026-04-14 22:01",
            " 2   auth_flow_validate          2026-04-14 22:02",
            " 3   ssl_tls_audit               2026-04-14 22:03",
            " 4   graphql_introspection_scan  2026-04-14 22:04",
            " 5   full_enterprise_scan        2026-04-14 22:10",
            " 6   pdf_report_generation       2026-04-14 22:11",
        ])

    def cmd_nmap(self, args, user_info):
        return self._create_res([
            "Starting Nmap 7.94 ( https://nmap.org )",
            "NSE: Loaded 155 scripts for scanning.",
            "Initiating Ping Scan...",
            "Nmap scan report for target",
            "Host is up (0.00012s latency).",
            "Not shown: 998 closed tcp ports",
            "PORT    STATE SERVICE",
            "22/tcp  open  ssh",
            "443/tcp open  https",
            "8000/tcp open  apiguard-api",
            "Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds"
        ])

    def cmd_db(self, args, user_info):
        if not args:
            return self._create_res(["Usage: db [stats|prune|dump|migrate]"])
        if args[0] == "stats":
            return self._create_res([
                "[DB V.3] apiguard_history.db: 4.8MB used. Rows: 1542.",
                "[DB V.3] apiguard_auth.db: 128KB used. Users: 23. Companies: 4.",
                "Integrity check: OK. WAL mode: enabled."
            ])
        if args[0] == "migrate":
            return self._create_res(["[DB] Running migrations...", "[DB] Already at latest schema version."])
        return self._create_res([f"Unknown db argument: {args[0]}"])

    def cmd_users(self, args, user_info):
        return self._create_res([
            "Active Enterprise Tenants inside environment:",
            " ID   |        NAME           | ROLE             | PLAN",
            " 1000 | sysadmin_service      | enterprise_admin | Enterprise",
            " 1001 | security_analyst      | enterprise_user  | Pro",
            " 1002 | dev_team_lead         | enterprise_user  | Pro",
            " 1003 | You (Current)         | Assessed from JWT| -"
        ])

    def cmd_apiguard(self, args, user_info):
        return self._create_res([
            "APIGuard Enterprise Security Scanner v2.0.0",
            "Powered by Python, FastAPI & 10 Security Modules.",
            "",
            "Modules: Parser, BOLA, BFLA, Auth/JWT, Rate Limit,",
            "         Injection/CORS, SSL/TLS, GraphQL, Data Exposure",
            "",
            "Features: Async Scanning, WebSocket Progress, PDF Reports,",
            "          OWASP Compliance, Webhook Notifications,",
            "          Enterprise Multi-Tenancy, JWT Auth, Audit Logging"
        ])

    def cmd_unsupported(self, args, user_info):
        return self._create_res(["Command isolated. Binary present but virtual environment lacks execution bridging."])

    def cmd_exit(self, args, user_info):
        return self._create_res(["logout. Connection to local socket closed."])
        
    def cmd_netstat(self, args, user_info):
        return self._create_res([
            "Active Internet connections (w/o servers)",
            "Proto Recv-Q Send-Q Local Address          Foreign Address        State",
            "tcp   0      0      127.0.0.1:8000         0.0.0.0:*              LISTEN",
            "tcp   0      0      127.0.0.1:3000         0.0.0.0:*              LISTEN",
            "ws    0      0      127.0.0.1:8000/ws      0.0.0.0:*              ESTABLISHED"
        ])

    def cmd_ifconfig(self, args, user_info):
        return self._create_res(["eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", "        inet 10.0.0.4  netmask 255.255.255.0  broadcast 10.0.0.255"])
        
    def cmd_route(self, args, user_info):
        return self._create_res(["Kernel IP routing table", "Destination  Gateway   Genmask   Flags Metric Ref Use Iface", "10.0.0.0     0.0.0.0   255.255.255.0   U     0      0    0 eth0"])

    def cmd_arp(self, args, user_info):
        return self._create_res(["Address                  HWtype  HWaddress           Flags Mask            Iface", "10.0.0.1                 ether   0a:74:9c:82:11:55   C                     eth0"])
        
    def cmd_cat(self, args, user_info):
        return self._create_res(["[CONTENT ENCRYPTED BY APIGUARD HSM - AES-256-GCM]"])
    
    def cmd_grep(self, args, user_info):
        return self._create_res(["Usage: grep [OPTION]... PATTERNS [FILE]..."])
        
    def cmd_chmod(self, args, user_info):
        return self._create_res(["chmod: changing permissions: Operation not permitted (Restricted Container)"])
    cmd_chown = cmd_chmod
    
    def cmd_ps(self, args, user_info):
        return self._create_res([
            "  PID TTY          TIME CMD",
            "    1 ?        00:00:01 apiguard_engine_v2",
            "   42 ?        00:00:00 scan_worker[0]",
            "   43 ?        00:00:00 scan_worker[1]",
            "   80 ?        00:00:00 ws_broadcaster",
            "  102 ?        00:00:00 bash",
            "  104 ?        00:00:00 ps"
        ])
        
    def cmd_top(self, args, user_info):
        return self._create_res([
            f"top - {time.strftime('%H:%M:%S')} up 45 days,  1 user,  load average: 0.12, 0.05, 0.02",
            "Tasks:   6 total,   1 running,   5 sleeping",
            "%Cpu(s):  1.5 us,  0.5 sy,  0.0 ni, 98.0 id,  0.0 wa",
            "MiB Mem:  4096.0 total,  2048.0 free,  1024.0 used,  1024.0 buff/cache",
            "",
            "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
            "    1 apiguard  20   0  512000  64000  32000 S   1.0   1.6   0:15.32 apiguard_engine",
            "   42 apiguard  20   0  256000  32000  16000 S   0.3   0.8   0:08.11 scan_worker"
        ])
        
    def cmd_env(self, args, user_info):
        return self._create_res([
            "APIGUARD_ENV=production",
            "APIGUARD_VERSION=2.0.0",
            "ENGINE_MODULES=10",
            "FASTAPI_SOCKET=8000",
            "JWT_ALGORITHM=HS256",
            "BCRYPT_ROUNDS=12",
            "RATE_LIMIT=60/minute",
            "CORS_MODE=strict",
            "WEBHOOK_CHANNELS=slack,discord,teams,email"
        ])

    def cmd_su(self, args, user_info):
        return self._create_res(["su: Authentication failure"])

    def cmd_dig(self, args, user_info):
        return self._create_res(["; <<>> DiG 9.18.1 <<>> target.com", ";; global options: +cmd", ";; Got answer:", ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1337", ";; ANSWER SECTION:", "target.com. 300 IN A 192.168.1.1"])

    def cmd_nslookup(self, args, user_info):
        return self._create_res(["Server:         1.1.1.1", "Address:        1.1.1.1#53", "", "Non-authoritative answer:", "Name:   example.com", "Address: 93.184.216.34"])

    def cmd_curl(self, args, user_info):
        return self._create_res(["HTTP/2 200 OK", "content-type: application/json", "x-powered-by: APIGuard/2.0", "strict-transport-security: max-age=31536000", "date: Tue, 14 Apr 2026 12:00:00 GMT", "", '{"status": "alive", "version": "2.0.0", "modules": 10}'])
    cmd_wget = cmd_curl
    
    def cmd_nc(self, args, user_info):
        return self._create_res(["nc: connection required. Use -h for help."])

    def cmd_ssh(self, args, user_info):
        return self._create_res(["ssh_exchange_identification: Connection closed by remote host."])

    def cmd_telnet(self, args, user_info):
        return self._create_res(["Trying 127.0.0.1...", "Connected to localhost.", "Escape character is '^]'."])
        
    def cmd_tcpdump(self, args, user_info):
        return self._create_res(["tcpdump: verbose output suppressed, use -v[v]... for full protocol decode", "listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes", "19:01:03.220194 IP 10.0.0.4 > 10.0.0.1: ICMP echo request, id 12, seq 1", "19:01:03.221010 IP 10.0.0.1 > 10.0.0.4: ICMP echo reply, id 12, seq 1", "2 packets captured"])
        
    def cmd_sqlmap(self, args, user_info):
        return self._create_res(["        ___", "       __H__", " ___ ___[']_____ ___ ___  {1.7#dev}", "|_ -| . [']     | .'| . |", "|___|_  [.]_|_|_|__,|  _|", "      |_|V...       |_|   https://sqlmap.org", "", "[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal.", "[*] Mocking execution sequence... Done"])
        
    def cmd_nikto(self, args, user_info):
        return self._create_res(["- Nikto v2.5.0", "---------------------------------------------------------------------------", "+ Target IP:          192.168.1.100", "+ Target Hostname:    api.example.local", "+ Target Port:        443", "---------------------------------------------------------------------------", "+ Server: nginx/1.25", "+ SSL/TLS: TLS 1.3 enforced", "+ No vulnerabilities identified in mock mode."])
    
    def cmd_dirb(self, args, user_info):
        return self._create_res(["-----------------", "DIRB v2.22    ", "By The Dark Raver", "-----------------", "", "START_TIME: Tue Apr 14 18:00:00 2026", "URL_BASE: http://192.168.x.x/", "WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt", "", "GENERATED WORDS: 4612", "---- Scanning URL: http://192.168.x.x/ ----", "==> DIRECTORY: http://192.168.x.x/admin/", "+ http://192.168.x.x/index.html (CODE:200|SIZE:1024)"])
        
    def cmd_hydra(self, args, user_info):
        return self._create_res(["Hydra v9.5 (c) 2023 by van Hauser/THC - Please do not use in military or secret service organizations", "Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] server service [OPT]"])

    def cmd_python(self, args, user_info):
        return self._create_res(["Python 3.12.0 (main, Oct 2 2023, 15:14:05) [GCC 13.2.0] on linux", 'Type "help", "copyright", "credits" or "license" for more information.'])

    def cmd_node(self, args, user_info):
        return self._create_res(["Welcome to Node.js v20.11.0.", 'Type ".help" for more information.'])
        
    def cmd_docker(self, args, user_info):
        return self._create_res([
            "CONTAINER ID   IMAGE                     COMMAND                  CREATED          STATUS          PORTS                                       NAMES",
            "1a2b3c4d5e6f   apiguard-enterprise:2.0   \"uvicorn app:main...\"   4 days ago       Up 4 days       0.0.0.0:8000->8000/tcp                     ag_api",
            "7g8h9i0j1k2l   apiguard-frontend:2.0     \"next start\"             4 days ago       Up 4 days       0.0.0.0:3000->3000/tcp                     ag_frontend",
            "3m4n5o6p7q8r   redis:7-alpine             \"redis-server\"           4 days ago       Up 4 days       6379/tcp                                    ag_cache"
        ])
        
    def cmd_git(self, args, user_info):
        return self._create_res(["usage: git [--version] [--help] [-C <path>] [-c <name>=<value>]", "           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]", "           [-p | --paginate | -P | --no-pager] [--no-replace-objects] [--bare]", "           [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]", "           <command> [<args>]"])
        
    def cmd_msf(self, args, user_info):
        return self._create_res(["      .:M:.", "    .:::::", "    :::::", "    :::", "    :", "", "       =[ metasploit v6.X.X-dev-XXX                          ]", "+ -- --=[ 2100 exploits - 1100 auxiliary - 400 post          ]", "+ -- --=[ 600 payloads - 40 encoders - 11 nops               ]", "", "msf6 >"])

    def cmd_cd(self, args, user_info):
        return self._create_res(["cd: restricted environment, navigation blocked"])

    # ── New Enterprise Commands ──────────────────

    def cmd_status(self, args, user_info):
        return self._create_res([
            "APIGuard Enterprise - System Status",
            "===================================",
            f"  Engine Status   : OPERATIONAL",
            f"  Uptime          : {random.randint(10, 99)} days, {random.randint(1, 23)}h {random.randint(1, 59)}m",
            f"  API Version     : v2.0.0",
            f"  Active Modules  : 10/10",
            f"  Active Workers  : 2/4",
            f"  Scans Today     : {random.randint(5, 50)}",
            f"  Queue Depth     : 0",
            f"  Memory Usage    : {random.randint(128, 512)}MB / 4096MB",
            f"  DB Size         : {random.uniform(1.0, 10.0):.1f}MB",
            "",
            "  Integrations:",
            f"    Slack     : {'Connected' if random.random() > 0.5 else 'Not configured'}",
            f"    Discord   : {'Connected' if random.random() > 0.5 else 'Not configured'}",
            f"    Email     : {'Connected' if random.random() > 0.5 else 'Not configured'}",
            "",
            "  Rate Limits: 60 req/min (API), 10 req/min (Scans)",
        ])

    def cmd_modules(self, args, user_info):
        return self._create_res([
            "APIGuard Enterprise - Scanner Module Registry",
            "=============================================",
            "  #   Module                  Status    OWASP Coverage",
            "  1   OpenAPI/Swagger Parser  ACTIVE    Infrastructure",
            "  2   BOLA Scanner            ACTIVE    API1:2023",
            "  3   BFLA Scanner            ACTIVE    API5:2023",
            "  4   Auth/JWT Scanner        ACTIVE    API2:2023",
            "  5   Rate Limit Scanner      ACTIVE    API4:2023",
            "  6   Injection/CORS Fuzzer   ACTIVE    API8:2023",
            "  7   Report Generator        ACTIVE    Reporting",
            "  8   SSL/TLS Scanner         ACTIVE    API8:2023  [NEW]",
            "  9   GraphQL Scanner         ACTIVE    API8:2023  [NEW]",
            " 10   Data Exposure Scanner   ACTIVE    API3:2023  [NEW]",
            "",
            " Total: 10 modules active | OWASP API Top 10 coverage: 8/10"
        ])

    def cmd_ssl_check(self, args, user_info):
        if not args:
            return self._create_res(["Usage: ssl <target_url>", "Example: ssl https://api.example.com"])
        return self._create_res([
            f"[SSL/TLS] Scanning {args[0]}...",
            f"  Certificate    : Valid (Let's Encrypt R3)",
            f"  Expiry         : 89 days remaining",
            f"  TLS Version    : TLS 1.3 (Strong)",
            f"  HSTS           : Enabled (max-age=31536000)",
            f"  Self-Signed    : No",
            f"  Hostname Match : OK",
            "",
            "  [PASS] SSL/TLS configuration appears secure."
        ])

    def cmd_graphql_check(self, args, user_info):
        if not args:
            return self._create_res(["Usage: graphql <target_url>", "Example: graphql https://api.example.com/graphql"])
        return self._create_res([
            f"[GraphQL] Probing {args[0]}...",
            "  Introspection  : ENABLED (Information Disclosure)",
            "  Depth Limiting : NOT ENFORCED (DoS Risk)",
            "  Batching       : ALLOWED (Brute-force Vector)",
            "  Types Found    : 47 types, 12 mutations",
            "",
            "  [WARN] 3 issues detected. Run full scan for details."
        ])

    def cmd_webhook(self, args, user_info):
        if not args:
            return self._create_res([
                "Usage: webhook [status|test|list]",
                "  status - Show configured webhook channels",
                "  test   - Send a test notification",
                "  list   - List recent notification history"
            ])
        if args[0] == "status":
            return self._create_res([
                "Webhook Configuration:",
                "  Slack    : Not configured (set APIGUARD_WEBHOOK_SLACK)",
                "  Discord  : Not configured (set APIGUARD_WEBHOOK_DISCORD)",
                "  Teams    : Not configured (set APIGUARD_WEBHOOK_TEAMS)",
                "  Email    : Not configured (set APIGUARD_SMTP_HOST)",
                "  Min Severity: HIGH"
            ])
        if args[0] == "test":
            return self._create_res(["[WEBHOOK] Sending test notification to all configured channels...", "[WEBHOOK] No channels configured. Set environment variables in .env"])
        return self._create_res([f"Unknown webhook argument: {args[0]}"])

    def cmd_audit(self, args, user_info):
        return self._create_res([
            "Recent Audit Log (last 10 entries):",
            "  2026-04-14 22:48  LOGIN           admin@company.com        Success",
            "  2026-04-14 22:47  SCAN_START      target=api.example.com   Modules: 10",
            "  2026-04-14 22:46  SCAN_COMPLETE   scan_id=scan_a1b2c3      Findings: 7",
            "  2026-04-14 22:45  PDF_EXPORT      scan_id=scan_a1b2c3      Size: 12KB",
            "  2026-04-14 22:40  LOGIN           dev@company.com          Success",
            "  2026-04-14 22:38  REGISTER        new_user@company.com     enterprise_user",
            "  2026-04-14 22:30  SCAN_START      target=internal.api      Modules: 6",
            "  2026-04-14 22:29  CONFIG_CHANGE   rate_limit=100/min       By: admin",
            "  2026-04-14 22:20  WEBHOOK_SENT    channel=slack            scan_a0b1c2",
            "  2026-04-14 22:15  LOGIN_FAILED    hacker@evil.com          Bad password",
        ])

    def cmd_config(self, args, user_info):
        return self._create_res([
            "APIGuard Enterprise Configuration:",
            "  Environment    : production",
            "  JWT Algorithm  : HS256",
            "  JWT Expiry     : 60 minutes",
            "  Bcrypt Rounds  : 12",
            "  Rate Limit API : 60/minute",
            "  Rate Limit Scan: 10/minute",
            "  CORS Origins   : localhost:3000, localhost:8000",
            "  History DB     : apiguard_history.db",
            "  Auth DB        : apiguard_auth.db",
            "",
            "  To modify: edit .env or set environment variables"
        ])

    def cmd_metrics(self, args, user_info):
        return self._create_res([
            "APIGuard Enterprise - Performance Metrics",
            "=========================================",
            f"  Total Scans (All Time)  : {random.randint(500, 2000)}",
            f"  Total Findings          : {random.randint(1500, 5000)}",
            f"  Avg Scan Duration       : {random.uniform(5, 30):.1f}s",
            f"  Avg Findings/Scan       : {random.uniform(2, 8):.1f}",
            f"  Most Common Vuln        : MISSING_AUTH (23%)",
            f"  Critical Rate           : {random.uniform(5, 20):.1f}%",
            f"  Fix Rate (30d)          : {random.uniform(40, 80):.0f}%",
            f"  API Requests (24h)      : {random.randint(1000, 5000)}",
            f"  PDF Reports Generated   : {random.randint(50, 200)}",
            f"  Webhooks Sent           : {random.randint(100, 500)}",
        ])

    def cmd_version(self, args, user_info):
        return self._create_res([
            "APIGuard Enterprise v2.0.0",
            "  Engine    : Python 3.12 + FastAPI",
            "  Frontend  : Next.js + React",
            "  Modules   : 10 active scanners",
            "  Auth      : bcrypt + JWT (HS256)",
            "  Database  : SQLite (dev) / PostgreSQL (prod)",
            "  License   : Enterprise"
        ])

    def cmd_health(self, args, user_info):
        return self._create_res([
            '{"status": "ok", "tool": "APIGuard Enterprise", "version": "2.0.0",',
            f' "uptime_days": {random.randint(10, 99)}, "modules_active": 10,',
            f' "db_healthy": true, "memory_mb": {random.randint(128, 512)}}}'
        ])

    def cmd_cve(self, args, user_info):
        return self._create_res([
            "APIGuard CVE Knowledge Base (Sample):",
            "  CVE-2023-44487  HTTP/2 Rapid Reset (DoS)         CRITICAL",
            "  CVE-2023-46604  Apache ActiveMQ RCE               CRITICAL",
            "  CVE-2024-3094   XZ Utils Backdoor                 CRITICAL",
            "  CVE-2023-50164  Apache Struts Path Traversal      HIGH",
            "  CVE-2023-4863   libwebp Heap Overflow             HIGH",
            "",
            "  Use 'cve <CVE-ID>' for details (not yet implemented in mock)"
        ])

    def cmd_owasp(self, args, user_info):
        return self._create_res([
            "OWASP API Security Top 10 (2023 Edition):",
            "==========================================",
            "  API1   Broken Object Level Authorization      [BOLA]",
            "  API2   Broken Authentication                  [Auth/JWT]",
            "  API3   Broken Object Property Authorization   [Data Exposure]",
            "  API4   Unrestricted Resource Consumption      [Rate Limit]",
            "  API5   Broken Function Level Authorization    [BFLA]",
            "  API6   Unrestricted Sensitive Business Flows  [Mass Assignment]",
            "  API7   Server Side Request Forgery            [SSRF]",
            "  API8   Security Misconfiguration              [Injection/SSL]",
            "  API9   Improper Inventory Management          [Shadow APIs]",
            "  API10  Unsafe Consumption of APIs             [Coming Soon]",
            "",
            " APIGuard coverage: 8/10 categories actively scanned"
        ])

    def cmd_report(self, args, user_info):
        return self._create_res([
            "Usage: report [generate|list|download]",
            "  generate <scan_id> - Generate PDF report for a scan",
            "  list               - Show available reports",
            "  download <scan_id> - Download PDF via API",
            "",
            "  API: GET /api/v1/report/<scan_id>/pdf"
        ])

    def cmd_export(self, args, user_info):
        return self._create_res([
            "Supported export formats:",
            "  JSON   - Full machine-readable report",
            "  PDF    - Professional executive report (multi-page)",
            "  HTML   - Interactive web dashboard",
            "  SARIF  - Static Analysis Results (GitHub compatible) [Coming Soon]",
            "",
            "  API: GET /api/v1/report/<scan_id>/pdf",
            "  CLI: python main.py --url <target> --pdf report.pdf --output report.json"
        ])

    def cmd_compliance(self, args, user_info):
        return self._create_res([
            "APIGuard Compliance Framework Mapping:",
            "======================================",
            "  OWASP API Top 10 2023    : 8/10 categories covered",
            "  PCI DSS v4.0             : Requirement 6 (Secure Dev)",
            "  SOC 2 Type II            : CC6.1, CC7.1 (Security)",
            "  ISO 27001:2022           : A.8.28 (Secure Coding)",
            "  NIST SP 800-53           : SA-11 (Developer Testing)",
            "",
            "  PDF reports include OWASP mapping per finding.",
            "  Full compliance reports available in Enterprise tier."
        ])

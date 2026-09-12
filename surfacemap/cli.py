"""Command-line entry point for the surfacemap attack-surface mapping tool."""
import argparse
import datetime
import os
import sys

from surfacemap import utils
from surfacemap.modules import dir_enum, dns_recon, http_probe, ports, subdomains, whois_lookup
from surfacemap.report import builder

DEFAULT_SUBDOMAIN_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "subdomains.txt")
DEFAULT_DIR_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "common-dirs.txt")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="surfacemap",
        description="Ferramenta de coleta de informacoes e mapeamento de superficie para pentest.",
    )
    parser.add_argument("target", help="Dominio alvo (ex: exemplo.com.br)")
    parser.add_argument("-o", "--output", help="Diretorio de saida do relatorio", default=None)
    parser.add_argument("-t", "--threads", type=int, default=30, help="Numero de threads (padrao: 30)")
    parser.add_argument(
        "--ports", default=None,
        help="Portas a escanear, ex: '1-1024' ou '22,80,443'. Padrao: lista top-ports interna."
    )
    parser.add_argument(
        "--max-hosts", type=int, default=15,
        help="Numero maximo de subdominios (alem do alvo principal) a escanear em profundidade (padrao: 15)"
    )
    parser.add_argument("--subdomain-wordlist", default=DEFAULT_SUBDOMAIN_WORDLIST)
    parser.add_argument("--dir-wordlist", default=DEFAULT_DIR_WORDLIST)
    parser.add_argument(
        "--dir-enum-all", action="store_true",
        help="Executar descoberta de diretorios em todos os hosts (padrao: apenas o alvo principal)"
    )
    parser.add_argument("--skip-dns", action="store_true")
    parser.add_argument("--skip-whois", action="store_true")
    parser.add_argument("--skip-subdomains", action="store_true")
    parser.add_argument("--no-passive-subdomains", action="store_true")
    parser.add_argument("--no-active-subdomains", action="store_true")
    parser.add_argument("--skip-ports", action="store_true")
    parser.add_argument("--skip-http", action="store_true")
    parser.add_argument("--skip-dirs", action="store_true")
    parser.add_argument("--skip-zone-transfer", action="store_true")
    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="Confirma que voce possui autorizacao para testar o alvo (pula o prompt interativo)"
    )
    return parser


def confirm_authorization(args) -> bool:
    print(utils.LEGAL_WARNING)
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print(
            "Execucao nao interativa detectada. Use --yes para confirmar que voce "
            "possui autorizacao para testar este alvo.",
            file=sys.stderr,
        )
        return False
    answer = input(f"Voce possui autorizacao para testar '{args.target}'? [digite 'sim' para continuar]: ")
    return answer.strip().lower() in ("sim", "s", "yes", "y")


def run(args) -> dict:
    target = args.target.strip().lower()
    if not utils.is_valid_domain(target):
        print(f"Erro: '{target}' nao parece ser um dominio valido.", file=sys.stderr)
        sys.exit(2)

    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data = {"target": target, "started_at": started_at, "hosts": {}}

    if not args.skip_dns:
        print(f"[*] Coletando registros DNS de {target}...")
        data["dns"] = dns_recon.get_dns_records(target)
        if not args.skip_zone_transfer:
            print("[*] Testando zone transfer (AXFR)...")
            data["zone_transfer"] = dns_recon.attempt_zone_transfer(target)

    if not args.skip_whois:
        print(f"[*] Consultando WHOIS de {target}...")
        data["whois"] = whois_lookup.get_whois(target)

    resolved_hosts = {}
    main_ip = utils.resolve_ip(target)
    if main_ip:
        resolved_hosts[target] = main_ip
    else:
        print(f"[!] Nao foi possivel resolver o dominio principal '{target}'.", file=sys.stderr)

    if not args.skip_subdomains:
        print(f"[*] Enumerando subdominios de {target}...")
        sub_wordlist = None if args.no_active_subdomains else args.subdomain_wordlist
        sub_result = subdomains.enumerate_subdomains(
            target,
            wordlist_path=sub_wordlist,
            threads=args.threads,
            passive=not args.no_passive_subdomains,
            active=not args.no_active_subdomains,
        )
        data["subdomains"] = sub_result

        for host, ip in sub_result.get("active", {}).items():
            resolved_hosts.setdefault(host, ip)

        for host in sub_result.get("passive", []):
            if host not in resolved_hosts and len(resolved_hosts) <= args.max_hosts:
                ip = utils.resolve_ip(host)
                if ip:
                    resolved_hosts[host] = ip

    hosts_to_scan = list(resolved_hosts.items())[: args.max_hosts + 1]
    print(f"[*] {len(hosts_to_scan)} host(s) serao analisados em profundidade: "
          f"{', '.join(h for h, _ in hosts_to_scan)}")

    port_list = ports.parse_port_range(args.ports) if args.ports else None

    for host, ip in hosts_to_scan:
        host_data = {"ip": ip}
        print(f"\n=== {host} ({ip}) ===")

        if not args.skip_ports:
            print(f"[*] Escaneando portas em {ip}...")
            host_data["ports"] = ports.scan_ports(ip, ports=port_list, threads=args.threads)
            print(f"    -> {len(host_data['ports'])} porta(s) aberta(s)")

        if not args.skip_http:
            print(f"[*] Fazendo fingerprint HTTP/HTTPS de {host}...")
            host_data["http"] = http_probe.probe_host(host)

        if not args.skip_dirs and (host == target or args.dir_enum_all):
            has_http = any(
                v.get("status") is not None
                for v in host_data.get("http", {}).values()
            ) if not args.skip_http else True
            if has_http:
                base_url = f"https://{host}"
                if host_data.get("http", {}).get("https", {}).get("status") is None:
                    base_url = f"http://{host}"
                print(f"[*] Buscando caminhos comuns em {base_url}...")
                host_data["dir_enum"] = dir_enum.enumerate_paths(
                    base_url, args.dir_wordlist, threads=args.threads
                )
                print(f"    -> {len(host_data['dir_enum'])} caminho(s) interessante(s)")

        data["hosts"][host] = host_data

    data["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return data


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    print(utils.banner())

    if not confirm_authorization(args):
        print("Abortado: autorizacao nao confirmada.", file=sys.stderr)
        sys.exit(1)

    data = run(args)

    output_dir = args.output or os.path.join(
        "reports", f"{data['target']}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
    paths = builder.save_all_reports(data, output_dir)

    print("\n[+] Relatorios gerados:")
    for fmt, path in paths.items():
        print(f"    - {fmt}: {path}")


if __name__ == "__main__":
    main()

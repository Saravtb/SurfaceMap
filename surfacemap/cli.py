"""Command-line entry point for the surfacemap attack-surface mapping tool."""
import argparse
import datetime
import os
import re
import sys

from surfacemap import utils
from surfacemap.modules import dir_enum, dns_recon, http_probe, nmap_scan, ports, subdomains, whois_lookup
from surfacemap.report import builder

DEFAULT_SUBDOMAIN_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "subdomains.txt")
DEFAULT_DIR_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "common-dirs.txt")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="surfacemap",
        description="Ferramenta de coleta de informacoes e mapeamento de superficie para pentest.",
    )
    parser.add_argument(
        "target",
        help="Dominio (exemplo.com.br), IP unico (192.168.1.10), bloco CIDR (192.168.1.0/24) "
             "ou range de IPs (192.168.1.10-192.168.1.20 ou 192.168.1.10-20)"
    )
    parser.add_argument("-o", "--output", help="Diretorio de saida do relatorio", default=None)
    parser.add_argument("-t", "--threads", type=int, default=30, help="Numero de threads (padrao: 30)")
    parser.add_argument(
        "--ports", default=None,
        help="Portas a escanear, ex: '1-1024' ou '22,80,443'. Padrao: lista top-ports interna."
    )
    parser.add_argument(
        "--max-hosts", type=int, default=15,
        help="Numero maximo de hosts a escanear em profundidade: subdominios extras (alem do "
             "alvo principal) para um dominio, ou enderecos IP para um CIDR/range (padrao: 15)"
    )
    parser.add_argument(
        "--no-ptr", action="store_true",
        help="Nao tentar resolver PTR (DNS reverso) para alvos IP/CIDR/range"
    )
    parser.add_argument(
        "--use-nmap", action="store_true",
        help="Usa o nmap (se disponivel no PATH) para escanear portas com deteccao de servico/versao, "
             "em vez do scanner TCP connect interno. Cai de volta para o scanner interno se o nmap "
             "nao estiver instalado ou falhar."
    )
    parser.add_argument(
        "--nmap-args", default=nmap_scan.DEFAULT_EXTRA_ARGS,
        help=f"Argumentos extras passados ao nmap (padrao: '{nmap_scan.DEFAULT_EXTRA_ARGS}')."
    )
    parser.add_argument(
        "--nmap-timeout", type=int, default=300,
        help="Timeout em segundos para a execucao do nmap por host (padrao: 300)"
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


def _run_domain_recon(args, target: str, data: dict) -> dict:
    """DNS/WHOIS/subdomain-enum phase for a domain target. Returns the
    resolved_hosts dict ({hostname: ip}) to scan in depth."""
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

    return dict(list(resolved_hosts.items())[: args.max_hosts + 1])


def _run_network_recon(args, target_raw: str, target_kind: str, data: dict) -> dict:
    """Expansion + WHOIS phase for an ip/cidr/range target. Returns the
    resolved_hosts dict ({ip: ip}) to scan in depth."""
    print(f"[*] Expandindo alvo de rede '{target_raw}' ({target_kind})...")
    try:
        ip_iter = utils.expand_ip_targets(target_raw)
        collected = []
        for ip in ip_iter:
            collected.append(ip)
            if len(collected) >= args.max_hosts:
                break
        truncated = False
        try:
            next(ip_iter)
            truncated = True
        except StopIteration:
            pass
    except ValueError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        sys.exit(2)

    data["network"] = {"spec": target_raw, "scanned_count": len(collected), "truncated": truncated}

    print(f"[*] {len(collected)} endereco(s) IP serao analisados em profundidade.")
    if truncated:
        print(
            f"[!] O alvo contem mais enderecos do que --max-hosts ({args.max_hosts}). "
            "Aumente --max-hosts para escanear mais IPs.",
            file=sys.stderr,
        )

    if not args.skip_whois and collected:
        print(f"[*] Consultando WHOIS de {collected[0]} (representativo do bloco)...")
        data["whois"] = whois_lookup.get_whois(collected[0])

    return {ip: ip for ip in collected}


def run(args) -> dict:
    target_raw = args.target.strip()
    try:
        target_kind = utils.classify_target(target_raw)
    except ValueError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        sys.exit(2)

    target = target_raw.lower() if target_kind == "domain" else target_raw
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data = {"target": target, "target_type": target_kind, "started_at": started_at, "hosts": {}}

    if target_kind == "domain":
        resolved_hosts = _run_domain_recon(args, target, data)
    else:
        resolved_hosts = _run_network_recon(args, target_raw, target_kind, data)

    hosts_to_scan = list(resolved_hosts.items())
    print(f"[*] {len(hosts_to_scan)} host(s) serao analisados em profundidade: "
          f"{', '.join(h for h, _ in hosts_to_scan)}")

    port_list = ports.parse_port_range(args.ports) if args.ports else None
    nmap_port_spec = args.ports or ",".join(str(p) for p in ports.TOP_PORTS)

    use_nmap = args.use_nmap
    if use_nmap and not nmap_scan.is_available():
        print("[!] --use-nmap solicitado, mas o binario 'nmap' nao foi encontrado no PATH. "
              "Usando o scanner interno.", file=sys.stderr)
        use_nmap = False

    for host, ip in hosts_to_scan:
        host_data = {"ip": ip}

        if target_kind != "domain" and not args.no_ptr:
            ptr = utils.resolve_ptr(ip)
            if ptr:
                host_data["ptr"] = ptr

        label = f"{host} ({host_data['ptr']})" if host_data.get("ptr") else host
        print(f"\n=== {label} ===")

        if not args.skip_ports:
            if use_nmap:
                print(f"[*] Escaneando portas em {ip} com nmap ({args.nmap_args})...")
                try:
                    host_data["ports"] = nmap_scan.scan_ports(
                        ip, port_spec=nmap_port_spec, extra_args=args.nmap_args, timeout=args.nmap_timeout
                    )
                    host_data["port_scanner"] = "nmap"
                except RuntimeError as exc:
                    print(f"[!] nmap falhou em {ip} ({exc}); usando scanner interno.", file=sys.stderr)
                    host_data["ports"] = ports.scan_ports(ip, ports=port_list, threads=args.threads)
                    host_data["port_scanner"] = "builtin (fallback apos falha do nmap)"
            else:
                print(f"[*] Escaneando portas em {ip}...")
                host_data["ports"] = ports.scan_ports(ip, ports=port_list, threads=args.threads)
                host_data["port_scanner"] = "builtin"
            print(f"    -> {len(host_data['ports'])} porta(s) aberta(s)")

        if not args.skip_http:
            print(f"[*] Fazendo fingerprint HTTP/HTTPS de {host}...")
            host_data["http"] = http_probe.probe_host(host)

        if not args.skip_dirs and (target_kind != "domain" or host == target or args.dir_enum_all):
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

    safe_target = re.sub(r"[^A-Za-z0-9.\-]", "_", data["target"])
    output_dir = args.output or os.path.join(
        "reports", f"{safe_target}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
    paths = builder.save_all_reports(data, output_dir)

    print("\n[+] Relatorios gerados:")
    for fmt, path in paths.items():
        print(f"    - {fmt}: {path}")


if __name__ == "__main__":
    main()

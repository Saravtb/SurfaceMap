"""Builds JSON, Markdown and HTML reports from aggregated recon results."""
import html
import json
import os

from surfacemap.utils import save_json


def save_json_report(data: dict, output_dir: str) -> str:
    path = os.path.join(output_dir, "report.json")
    save_json(data, path)
    return path


def _md_table(headers, rows) -> str:
    if not rows:
        return "_Nenhum resultado._\n"
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines) + "\n"


def to_markdown(data: dict) -> str:
    lines = [f"# Relatorio de Mapeamento de Superficie - {data['target']}", ""]
    lines.append(f"- Inicio: {data.get('started_at')}")
    lines.append(f"- Fim: {data.get('finished_at')}")
    lines.append("")

    dns_records = data.get("dns", {})
    if dns_records:
        lines.append("## Registros DNS")
        rows = []
        for rtype, values in dns_records.items():
            rows.append([rtype, ", ".join(values) if values else "-"])
        lines.append(_md_table(["Tipo", "Valores"], rows))

    axfr = data.get("zone_transfer")
    if axfr:
        lines.append("## Teste de Zone Transfer (AXFR)")
        if "error" in axfr:
            lines.append(f"- {axfr['error']}\n")
        else:
            rows = [[ns, "SIM (vulneravel)" if r.get("vulnerable") else "nao"] for ns, r in axfr.items()]
            lines.append(_md_table(["Nameserver", "Transferencia permitida"], rows))

    whois_text = data.get("whois")
    if whois_text:
        lines.append("## WHOIS (resumo)")
        snippet = "\n".join(whois_text.splitlines()[:20])
        lines.append("```")
        lines.append(snippet)
        lines.append("```")
        lines.append("")

    subs = data.get("subdomains", {})
    if subs:
        lines.append("## Subdominios")
        passive = subs.get("passive", [])
        active = subs.get("active", {})
        lines.append(f"- Encontrados via CT logs (passivo): {len(passive)}")
        lines.append(f"- Confirmados via brute force (ativo, resolvidos): {len(active)}")
        if active:
            rows = [[host, ip] for host, ip in sorted(active.items())]
            lines.append(_md_table(["Host", "IP"], rows))

    hosts = data.get("hosts", {})
    for host, hdata in hosts.items():
        lines.append(f"## Host: {host} ({hdata.get('ip', 'sem IP')})")

        ports = hdata.get("ports", {})
        if ports:
            rows = [[p, s] for p, s in ports.items()]
            lines.append("### Portas abertas")
            lines.append(_md_table(["Porta", "Servico"], rows))

        http_data = hdata.get("http", {})
        for scheme, info in http_data.items():
            if info.get("status") is None and info.get("error"):
                continue
            lines.append(f"### {scheme.upper()}")
            lines.append(f"- Status: {info.get('status')}")
            lines.append(f"- Servidor: {info.get('server')}")
            lines.append(f"- Titulo: {info.get('title')}")
            if info.get("technologies"):
                lines.append(f"- Tecnologias detectadas: {', '.join(info['technologies'])}")
            lines.append("")

        dirs = hdata.get("dir_enum", [])
        if dirs:
            lines.append("### Caminhos interessantes encontrados")
            rows = [[d["path"], d["status"], d["url"]] for d in dirs]
            lines.append(_md_table(["Caminho", "Status", "URL"], rows))

    return "\n".join(lines)


_HTML_TEMPLATE = """<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>Relatorio de Superficie - {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem;
         background: #0f1117; color: #e6e6e6; }}
  h1, h2, h3 {{ color: #7dd3fc; }}
  h1 {{ border-bottom: 2px solid #334155; padding-bottom: .5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
  th, td {{ border: 1px solid #334155; padding: .4rem .6rem; text-align: left; font-size: .9rem; }}
  th {{ background: #1e293b; }}
  tr:nth-child(even) {{ background: #161b26; }}
  .meta {{ color: #94a3b8; margin-bottom: 1.5rem; }}
  .badge {{ display: inline-block; padding: .1rem .5rem; border-radius: .3rem; font-size: .75rem;
            background: #1e293b; margin-right: .3rem; }}
  .danger {{ color: #f87171; font-weight: bold; }}
  section {{ margin-bottom: 2.5rem; }}
  pre {{ background: #1e293b; padding: 1rem; overflow-x: auto; border-radius: .4rem; }}
</style>
</head>
<body>
<h1>Mapeamento de Superficie: {target}</h1>
<p class="meta">Inicio: {started_at} &nbsp;|&nbsp; Fim: {finished_at}</p>
{body}
</body>
</html>
"""


def _html_table(headers, rows) -> str:
    if not rows:
        return "<p><em>Nenhum resultado.</em></p>"
    out = ["<table><thead><tr>"]
    out += [f"<th>{html.escape(str(h))}</th>" for h in headers]
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def to_html(data: dict) -> str:
    sections = []

    dns_records = data.get("dns", {})
    if dns_records:
        rows = [[rtype, ", ".join(values) if values else "-"] for rtype, values in dns_records.items()]
        sections.append(f"<section><h2>Registros DNS</h2>{_html_table(['Tipo', 'Valores'], rows)}</section>")

    axfr = data.get("zone_transfer")
    if axfr:
        if "error" in axfr:
            body = f"<p>{html.escape(axfr['error'])}</p>"
        else:
            rows = ["<table><thead><tr><th>Nameserver</th><th>Transferencia permitida</th></tr></thead><tbody>"]
            for ns, r in axfr.items():
                flag = '<span class="danger">SIM (vulneravel)</span>' if r.get("vulnerable") else "nao"
                rows.append(f"<tr><td>{html.escape(ns)}</td><td>{flag}</td></tr>")
            rows.append("</tbody></table>")
            body = "".join(rows)
        sections.append(f"<section><h2>Teste de Zone Transfer (AXFR)</h2>{body}</section>")

    whois_text = data.get("whois")
    if whois_text:
        snippet = "\n".join(whois_text.splitlines()[:25])
        sections.append(
            f"<section><h2>WHOIS (resumo)</h2><pre>{html.escape(snippet)}</pre></section>"
        )

    subs = data.get("subdomains", {})
    if subs:
        passive = subs.get("passive", [])
        active = subs.get("active", {})
        rows = [[host, ip] for host, ip in sorted(active.items())]
        body = (
            f"<p>Encontrados via CT logs (passivo): <span class='badge'>{len(passive)}</span> "
            f"&nbsp; Confirmados via brute force (ativo): <span class='badge'>{len(active)}</span></p>"
            + _html_table(["Host", "IP"], rows)
        )
        sections.append(f"<section><h2>Subdominios</h2>{body}</section>")

    hosts = data.get("hosts", {})
    for host, hdata in hosts.items():
        parts = [f"<h2>Host: {html.escape(host)} ({html.escape(str(hdata.get('ip', 'sem IP')))})</h2>"]

        ports = hdata.get("ports", {})
        if ports:
            rows = [[p, s] for p, s in ports.items()]
            parts.append("<h3>Portas abertas</h3>" + _html_table(["Porta", "Servico"], rows))

        http_data = hdata.get("http", {})
        for scheme, info in http_data.items():
            if info.get("status") is None and info.get("error"):
                continue
            techs = ", ".join(info.get("technologies", [])) or "-"
            parts.append(
                f"<h3>{scheme.upper()}</h3><p>Status: {info.get('status')}<br>"
                f"Servidor: {html.escape(str(info.get('server')))}<br>"
                f"Titulo: {html.escape(str(info.get('title')))}<br>"
                f"Tecnologias: {html.escape(techs)}</p>"
            )

        dirs = hdata.get("dir_enum", [])
        if dirs:
            rows = [[d["path"], d["status"], d["url"]] for d in dirs]
            parts.append(
                "<h3>Caminhos interessantes</h3>" + _html_table(["Caminho", "Status", "URL"], rows)
            )

        sections.append("<section>" + "".join(parts) + "</section>")

    return _HTML_TEMPLATE.format(
        target=html.escape(data.get("target", "")),
        started_at=html.escape(str(data.get("started_at", ""))),
        finished_at=html.escape(str(data.get("finished_at", ""))),
        body="\n".join(sections),
    )


def save_all_reports(data: dict, output_dir: str) -> dict:
    os.makedirs(output_dir, exist_ok=True)
    paths = {}

    paths["json"] = save_json_report(data, output_dir)

    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(to_markdown(data))
    paths["markdown"] = md_path

    html_path = os.path.join(output_dir, "report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(to_html(data))
    paths["html"] = html_path

    return paths

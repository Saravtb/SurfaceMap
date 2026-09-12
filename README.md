# SurfaceMap

Ferramenta de coleta de informacoes (reconnaissance) para construir um
mapeamento de superficie de ataque de um dominio, como etapa inicial de um
pentest autorizado.

## ⚠️ Aviso legal

Esta ferramenta executa varredura ativa de rede (portas, subdominios,
diretorios web). **Use apenas contra alvos para os quais voce possui
autorizacao explicita e por escrito** (contrato de pentest, programa de
bug bounty com escopo definido, ou ativos proprios). Uso nao autorizado
pode configurar crime e violar termos de servico. Ao rodar a ferramenta,
voce sera solicitado a confirmar que possui essa autorizacao.

## O que ela coleta

| Modulo | Descricao |
|---|---|
| DNS | Registros A, AAAA, MX, NS, TXT, SOA, CNAME + teste de zone transfer (AXFR) |
| WHOIS | Dados de registro do dominio |
| Subdominios | Enumeracao passiva via Certificate Transparency (crt.sh) + brute force ativo por wordlist |
| Portas | Varredura TCP connect nas portas mais comuns (ou range customizado) |
| HTTP/HTTPS | Status, headers, titulo da pagina e fingerprint leve de tecnologias (WordPress, Nginx, Laravel, etc.) |
| Diretorios | Descoberta de caminhos/arquivos sensiveis comuns (`.git`, `.env`, painel admin, backups, etc.) |

O resultado agregado e exportado em **JSON**, **Markdown** e **HTML**
(relatorio navegavel, tema escuro, com tabelas por host).

## Instalacao

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`dnspython` e opcional mas recomendado: sem ele, a coleta de DNS fica
limitada a registros A e o teste de AXFR e pulado.

## Uso

```bash
python main.py exemplo.com.br
```

Voce sera solicitado a confirmar autorizacao interativamente. Para rodar
sem prompt (ex.: em CI, com autorizacao ja documentada):

```bash
python main.py exemplo.com.br --yes
```

### Opcoes principais

```
positional:
  target                     Dominio alvo (ex: exemplo.com.br)

  -o, --output DIR           Diretorio de saida (padrao: reports/<alvo>-<timestamp>)
  -t, --threads N            Threads para brute force/scan (padrao: 30)
  --ports RANGE              Ex: "1-1024" ou "22,80,443" (padrao: top ports internas)
  --max-hosts N              Maximo de subdominios analisados em profundidade (padrao: 15)
  --subdomain-wordlist PATH  Wordlist customizada para brute force de subdominios
  --dir-wordlist PATH        Wordlist customizada para descoberta de diretorios
  --dir-enum-all             Roda descoberta de diretorios em todos os hosts, nao so no alvo principal

  --skip-dns                 Pula coleta de registros DNS
  --skip-zone-transfer       Pula teste de AXFR
  --skip-whois               Pula consulta WHOIS
  --skip-subdomains          Pula enumeracao de subdominios
  --no-passive-subdomains    Desativa apenas a fonte passiva (crt.sh)
  --no-active-subdomains     Desativa apenas o brute force ativo
  --skip-ports               Pula varredura de portas
  --skip-http                Pula fingerprint HTTP/HTTPS
  --skip-dirs                Pula descoberta de diretorios

  -y, --yes                  Confirma autorizacao sem prompt interativo
```

### Exemplos

Reconhecimento completo, portas customizadas, saida em pasta especifica:

```bash
python main.py exemplo.com.br --ports 1-1024 -o relatorios/exemplo --yes
```

Somente reconhecimento passivo (sem tocar diretamente no alvo com scans
ativos de porta/diretorio, apenas DNS/WHOIS/subdominios passivos):

```bash
python main.py exemplo.com.br --skip-ports --skip-dirs --no-active-subdomains --yes
```

## Estrutura do projeto

```
surfacemap/
  cli.py                 Orquestracao / argparse
  utils.py                Helpers (validacao de dominio, banner, aviso legal)
  modules/
    dns_recon.py          Registros DNS + AXFR
    subdomains.py          crt.sh (passivo) + brute force (ativo)
    ports.py                Varredura de portas TCP
    http_probe.py           Fingerprint HTTP/HTTPS
    dir_enum.py              Descoberta de diretorios/arquivos
    whois_lookup.py          WHOIS
  report/
    builder.py               Geracao de JSON/Markdown/HTML
  wordlists/
    subdomains.txt
    common-dirs.txt
main.py                Ponto de entrada (python main.py <alvo>)
```

## Limitacoes conhecidas

- A varredura de portas usa TCP connect scan simples (sem SYN scan), o que
  e mais lento que ferramentas como `nmap` mas nao requer privilegios de
  root.
- A enumeracao de subdominios ativa depende da wordlist fornecida; para
  cobertura maior, use uma wordlist maior (ex. SecLists) via
  `--subdomain-wordlist`.
- O fingerprint de tecnologias e heuristico (regex sobre headers/HTML) e
  pode gerar falsos positivos/negativos.
- Esta ferramenta nao substitui uma analise manual aprofundada nem testes
  de exploracao; ela serve para acelerar a fase de reconhecimento.

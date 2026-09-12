# SurfaceMap

Ferramenta de coleta de informacoes (reconnaissance) para construir um
mapeamento de superficie de ataque, como etapa inicial de um pentest
autorizado. Aceita como alvo um **dominio**, um **IP unico**, um **bloco
CIDR** ou um **range de IPs**.

## ⚠️ Aviso legal

Esta ferramenta executa varredura ativa de rede (portas, subdominios,
diretorios web). **Use apenas contra alvos para os quais voce possui
autorizacao explicita e por escrito** (contrato de pentest, programa de
bug bounty com escopo definido, ou ativos proprios). Uso nao autorizado
pode configurar crime e violar termos de servico. Ao rodar a ferramenta,
voce sera solicitado a confirmar que possui essa autorizacao.

## Tipos de alvo suportados

| Alvo | Exemplo | O que roda |
|---|---|---|
| Dominio | `exemplo.com.br` | DNS, WHOIS, enumeracao de subdominios, e o restante abaixo para cada host resolvido |
| IP unico | `192.168.1.10` | WHOIS do IP, e o restante abaixo |
| Bloco CIDR | `192.168.1.0/24` | Expande para os IPs do bloco (host bits; `/31` e `/32` incluem ambos os enderecos), WHOIS do primeiro IP como amostra, e o restante abaixo para cada IP |
| Range de IPs | `192.168.1.10-192.168.1.20` ou `192.168.1.10-20` (abreviado, ultimo octeto) | Mesmo tratamento de um bloco CIDR |

Para alvos IP/CIDR/range a ferramenta tambem tenta resolver o **PTR**
(DNS reverso) de cada endereco (desative com `--no-ptr`), e a descoberta
de diretorios roda em todos os IPs com HTTP ativo por padrao (nao so no
"alvo principal", conceito que so existe para dominios).

⚠️ Um bloco grande (ex. `/16`) pode ter dezenas de milhares de enderecos;
a ferramenta so escaneia em profundidade ate `--max-hosts` deles (padrao
15) e avisa quando a lista foi truncada. Aumente `--max-hosts` conforme o
escopo autorizado do teste.

## O que ela coleta

| Modulo | Descricao |
|---|---|
| DNS | Registros A, AAAA, MX, NS, TXT, SOA, CNAME + teste de zone transfer (AXFR) — apenas para alvos de dominio |
| WHOIS | Dados de registro do dominio, ou do IP/bloco quando o alvo e uma rede |
| Subdominios | Enumeracao passiva via Certificate Transparency (crt.sh) + brute force ativo por wordlist — apenas para alvos de dominio |
| Portas | Varredura TCP connect nas portas mais comuns (ou range customizado); opcionalmente via `nmap` com deteccao de servico/versao (`--use-nmap`) |
| HTTP/HTTPS | Status, headers, titulo da pagina e fingerprint leve de tecnologias (WordPress, Nginx, Laravel, etc.) |
| Diretorios | Descoberta de caminhos/arquivos sensiveis comuns (`.git`, `.env`, painel admin, backups, etc.) |
| Screenshots | Captura de tela de cada host web ativo, via Chromium headless (`--screenshots`, opcional) |

O resultado agregado e exportado em **JSON**, **Markdown** e **HTML**
(relatorio navegavel, tema escuro, com tabelas por host e screenshots
incorporados quando capturados).

## Instalacao

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`dnspython` e opcional mas recomendado: sem ele, a coleta de DNS fica
limitada a registros A e o teste de AXFR e pulado.

Para usar `--screenshots` tambem e preciso instalar o Playwright e um
navegador Chromium (nao vem no `requirements.txt` por padrao, ja que baixa
~150MB):

```bash
pip install playwright
playwright install chromium
```

Sem isso, `--screenshots` apenas imprime um aviso e a ferramenta continua
normalmente (as demais etapas nao dependem do Playwright).

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
  target                     Dominio, IP unico, bloco CIDR ou range de IPs (ex: exemplo.com.br,
                              192.168.1.10, 192.168.1.0/24, 192.168.1.10-192.168.1.20)

  -o, --output DIR           Diretorio de saida (padrao: reports/<alvo>-<timestamp>)
  -t, --threads N            Threads para brute force/scan (padrao: 30)
  --ports RANGE              Ex: "1-1024" ou "22,80,443" (padrao: top ports internas)
  --max-hosts N              Maximo de hosts analisados em profundidade: subdominios extras
                              (dominio) ou enderecos IP (CIDR/range) (padrao: 15)
  --no-ptr                   Nao resolver PTR (DNS reverso) para alvos IP/CIDR/range
  --use-nmap                 Usa o nmap (se instalado) para escanear portas com deteccao de
                              servico/versao, em vez do scanner TCP connect interno. Se o
                              nmap nao estiver no PATH ou a execucao falhar, cai automaticamente
                              para o scanner interno.
  --nmap-args ARGS            Argumentos extras passados ao nmap (padrao: "-sV")
  --nmap-timeout N            Timeout em segundos por host para o nmap (padrao: 300)
  --subdomain-wordlist PATH  Wordlist customizada para brute force de subdominios
  --dir-wordlist PATH        Wordlist customizada para descoberta de diretorios
  --dir-enum-all             Roda descoberta de diretorios em todos os hosts, nao so no alvo principal
  --screenshots              Captura screenshot de cada host web ativo (requer Playwright + Chromium)
  --screenshot-timeout MS    Timeout em ms para carregar a pagina antes do screenshot (padrao: 15000)

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

Varredura de portas usando nmap com deteccao de servico e scripts padrao
(requer `nmap` instalado no sistema; sem privilegio de root o nmap usa
automaticamente TCP connect scan em vez de SYN scan):

```bash
python main.py exemplo.com.br --use-nmap --nmap-args "-sV -sC" --yes
```

Reconhecimento com captura de screenshot de cada host web encontrado
(requer Playwright + Chromium instalados, ver secao de Instalacao):

```bash
python main.py exemplo.com.br --screenshots --yes
```

Somente reconhecimento passivo (sem tocar diretamente no alvo com scans
ativos de porta/diretorio, apenas DNS/WHOIS/subdominios passivos):

```bash
python main.py exemplo.com.br --skip-ports --skip-dirs --no-active-subdomains --yes
```

Varredura de um bloco CIDR (rede interna de um cliente, por exemplo),
elevando o limite de hosts para cobrir toda a `/24`:

```bash
python main.py 192.168.1.0/24 --max-hosts 254 --yes
```

Varredura de um range especifico de IPs, com sintaxe abreviada de
ultimo octeto:

```bash
python main.py 10.0.0.100-150 --yes
```

## Estrutura do projeto

```
surfacemap/
  cli.py                 Orquestracao / argparse
  utils.py                Helpers (validacao de dominio, banner, aviso legal)
  modules/
    dns_recon.py          Registros DNS + AXFR
    subdomains.py          crt.sh (passivo) + brute force (ativo)
    ports.py                Varredura de portas TCP (scanner interno)
    nmap_scan.py             Backend opcional de varredura via nmap (-sV, XML parsing)
    http_probe.py           Fingerprint HTTP/HTTPS
    dir_enum.py              Descoberta de diretorios/arquivos
    whois_lookup.py          WHOIS
    screenshot.py            Captura de tela opcional via Playwright/Chromium
  report/
    builder.py               Geracao de JSON/Markdown/HTML
  wordlists/
    subdomains.txt
    common-dirs.txt
main.py                Ponto de entrada (python main.py <alvo>)
```

## Limitacoes conhecidas

- Por padrao a varredura de portas usa TCP connect scan simples (sem SYN
  scan), o que e mais lento que o `nmap` mas nao requer privilegios de
  root. Use `--use-nmap` para deteccao de servico/versao via `nmap` quando
  ele estiver instalado (a ferramenta cai de volta para o scanner interno
  automaticamente se o binario nao existir ou a execucao falhar).
- `--screenshots` exige `pip install playwright` + `playwright install
  chromium` (ou um Chromium ja instalado e compativel com a versao do
  pacote `playwright`); sem isso, a flag e ignorada com um aviso e o
  restante do reconhecimento roda normalmente.
- A enumeracao de subdominios ativa depende da wordlist fornecida; para
  cobertura maior, use uma wordlist maior (ex. SecLists) via
  `--subdomain-wordlist`.
- O fingerprint de tecnologias e heuristico (regex sobre headers/HTML) e
  pode gerar falsos positivos/negativos.
- Esta ferramenta nao substitui uma analise manual aprofundada nem testes
  de exploracao; ela serve para acelerar a fase de reconhecimento.

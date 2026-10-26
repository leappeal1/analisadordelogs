#!/usr/bin/env python3
"""
Analisador de logs para triagem inicial de ameaças.

Formatos aceitos:
  1) CSV com cabeçalho
  2) JSON Lines (um objeto JSON por linha)

Campos reconhecidos (aliases são aceitos):
  timestamp/data/hora, user/usuario/username, ip/src_ip/source_ip,
  event/event_type/tipo/action/message/status

Exemplo de CSV:
timestamp,user,ip,event
2026-10-26T10:00:00Z,ana,192.0.2.10,login_failed
2026-10-26T10:00:20Z,ana,192.0.2.10,login_failed
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone, timedelta
from pathlib import Path


ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "date", "data", "hora", "@timestamp"),
    "user": ("user", "usuario", "username", "account", "login", "subject"),
    "ip": ("ip", "src_ip", "source_ip", "client_ip", "remote_addr", "address"),
    "event": ("event", "event_type", "type", "tipo", "action", "message", "status"),
}

FAILURE_RE = re.compile(
    r"(login[_ -]?fail|auth(?:entication)?[_ -]?fail|failed password|"
    r"invalid user|access denied|falha(?:s)? de autentica|autenticacao falhou|"
    r"authentication failure|logon failure)",
    re.IGNORECASE,
)


def normalize_key(value):
    return re.sub(r"[^a-z0-9_@]", "", str(value).strip().lower())


def pick_field(record, logical_name):
    normalized = {normalize_key(k): v for k, v in record.items() if k is not None}
    for alias in ALIASES[logical_name]:
        key = normalize_key(alias)
        if key in normalized and normalized[key] not in (None, ""):
            return str(normalized[key]).strip()
    return ""


def parse_timestamp(value):
    """Converte ISO-8601 e formatos comuns; timestamps sem fuso são tratados como UTC."""
    if not value:
        raise ValueError("timestamp ausente")
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                    "%d/%m/%Y %H:%M:%S", "%b %d %H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt)
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                break
            except ValueError:
                continue
        if dt is None:
            raise ValueError(f"timestamp inválido: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def detect_format(path):
    suffix = path.suffix.lower()
    if suffix in (".jsonl", ".ndjson"):
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    # Detecta pelo primeiro caractere não vazio.
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                return "jsonl" if stripped.startswith("{") else "csv"
    return "csv"


def read_records(path):
    """Yield (line_number, record, error). Erros de linha não interrompem a leitura."""
    fmt = detect_format(path)
    if fmt == "csv":
        with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                yield (1, None, "CSV sem cabeçalho ou arquivo vazio")
                return
            for line_no, record in enumerate(reader, start=2):
                if not any(str(v or "").strip() for v in record.values()):
                    continue
                yield (line_no, record, None)
    else:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("cada linha JSON deve ser um objeto")
                    yield (line_no, record, None)
                except (json.JSONDecodeError, ValueError) as exc:
                    yield (line_no, None, f"JSON inválido: {exc}")


def is_auth_failure(event):
    return bool(FAILURE_RE.search(event or ""))


def analyze(path, output, threshold=5, window_minutes=10, start=None, end=None):
    if threshold < 1:
        raise ValueError("o limite de alerta deve ser pelo menos 1")
    if window_minutes < 1:
        raise ValueError("a janela temporal deve ser de pelo menos 1 minuto")

    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"arquivo não encontrado: {source}")

    start_dt = parse_timestamp(start) if start else None
    end_dt = parse_timestamp(end) if end else None
    if start_dt and end_dt and start_dt > end_dt:
        raise ValueError("a data inicial não pode ser posterior à data final")

    counts_user = Counter()
    counts_ip = Counter()
    counts_type = Counter()
    invalid_rows = []
    events = []
    skipped_outside_period = 0

    for line_no, record, error in read_records(source):
        if error:
            invalid_rows.append((line_no, error))
            continue
        try:
            timestamp_text = pick_field(record, "timestamp")
            timestamp = parse_timestamp(timestamp_text)
            user = pick_field(record, "user") or "(desconhecido)"
            ip = pick_field(record, "ip") or "(desconhecido)"
            event = pick_field(record, "event") or "(sem_tipo)"
            if start_dt and timestamp < start_dt:
                skipped_outside_period += 1
                continue
            if end_dt and timestamp > end_dt:
                skipped_outside_period += 1
                continue
            events.append({
                "timestamp": timestamp, "user": user, "ip": ip,
                "event": event, "line": line_no,
                "auth_failure": is_auth_failure(event),
            })
            counts_user[user] += 1
            counts_ip[ip] += 1
            counts_type[event] += 1
        except (ValueError, TypeError) as exc:
            invalid_rows.append((line_no, str(exc)))

    events.sort(key=lambda e: e["timestamp"])
    window = timedelta(minutes=window_minutes)
    # Detecção por usuário e por IP, usando janela móvel de tempo.
    alerts_by_key = {}
    for dimension in ("user", "ip"):
        groups = defaultdict(deque)
        for event in events:
            if not event["auth_failure"]:
                continue
            key = event[dimension]
            queue = groups[key]
            queue.append(event)
            cutoff = event["timestamp"] - window
            while queue and queue[0]["timestamp"] < cutoff:
                queue.popleft()
            if len(queue) >= threshold:
                alert_key = (dimension, key)
                existing = alerts_by_key.get(alert_key)
                if existing is None or len(queue) > existing["count"]:
                    alerts_by_key[alert_key] = {
                        "dimension": dimension,
                        "key": key,
                        "count": len(queue),
                        "window_start": queue[0]["timestamp"],
                        "last_seen": event["timestamp"],
                        "severity": "ALTO" if len(queue) >= threshold * 2 else "MÉDIO",
                        "details": f"{len(queue)} falhas de autenticação em até {window_minutes} min",
                    }
    alerts = list(alerts_by_key.values())

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        fields = [
            "record_type", "period_start_utc", "period_end_utc",
            "dimension", "user", "ip", "event_type", "count",
            "severity", "details", "source_line",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        def write_row(**kwargs):
            row = {field: "" for field in fields}
            row.update(kwargs)
            writer.writerow(row)

        period_start = min((e["timestamp"] for e in events), default=None)
        period_end = max((e["timestamp"] for e in events), default=None)
        period_start_text = period_start.isoformat() if period_start else ""
        period_end_text = period_end.isoformat() if period_end else ""

        for user, count in counts_user.most_common():
            write_row(record_type="contagem_usuario", period_start_utc=period_start_text,
                      period_end_utc=period_end_text, dimension="user", user=user, count=count)
        for ip, count in counts_ip.most_common():
            write_row(record_type="contagem_ip", period_start_utc=period_start_text,
                      period_end_utc=period_end_text, dimension="ip", ip=ip, count=count)
        for event_type, count in counts_type.most_common():
            write_row(record_type="contagem_tipo", period_start_utc=period_start_text,
                      period_end_utc=period_end_text, dimension="event_type",
                      event_type=event_type, count=count)
        for alert in alerts:
            write_row(record_type="alerta", period_start_utc=alert["window_start"].isoformat(),
                      period_end_utc=alert["last_seen"].isoformat(),
                      dimension=alert["dimension"],
                      user=alert["key"] if alert["dimension"] == "user" else "",
                      ip=alert["key"] if alert["dimension"] == "ip" else "",
                      count=alert["count"], severity=alert["severity"], details=alert["details"])
        for line_no, reason in invalid_rows:
            write_row(record_type="linha_invalida", details=reason, source_line=line_no)

    print("\n=== Resultado da análise ===")
    print(f"Arquivo: {source}")
    print(f"Eventos analisados: {len(events)}")
    print(f"Linhas inválidas: {len(invalid_rows)}")
    print(f"Eventos fora do período informado: {skipped_outside_period}")
    print(f"Falhas de autenticação: {sum(e['auth_failure'] for e in events)}")
    print(f"Alertas gerados: {len(alerts)}")
    print(f"Relatório CSV: {output_path.resolve()}")

    if alerts:
        print("\nAlertas:")
        for alert in alerts:
            print(f"- [{alert['severity']}] {alert['dimension']}={alert['key']}: "
                  f"{alert['details']} (janela termina em {alert['last_seen'].isoformat()})")
    else:
        print("\nNenhum alerta de falha de autenticação com os critérios configurados.")

    if invalid_rows:
        print("\nAlgumas linhas foram ignoradas por estarem inválidas. Consulte o CSV.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Conta eventos e detecta falhas de autenticação em logs CSV ou JSONL."
    )
    parser.add_argument("arquivo", help="caminho do arquivo de logs (.csv, .jsonl ou .ndjson)")
    parser.add_argument("-o", "--output", default="relatorio_logs.csv",
                        help="caminho do relatório CSV (padrão: relatorio_logs.csv)")
    parser.add_argument("--limite", type=int, default=5,
                        help="número de falhas para disparar alerta (padrão: 5)")
    parser.add_argument("--janela", type=int, default=10,
                        help="janela móvel em minutos (padrão: 10)")
    parser.add_argument("--inicio", help="início do período ISO-8601, ex.: 2026-10-26T09:00:00Z")
    parser.add_argument("--fim", help="fim do período ISO-8601, ex.: 2026-10-26T18:00:00Z")
    args = parser.parse_args()

    try:
        return analyze(args.arquivo, args.output, args.limite, args.janela, args.inicio, args.fim)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

# Analisador de logs e avaliação inicial de ameaças

Ferramenta didática em Python, sem dependências externas. Lê logs CSV ou JSON Lines (JSONL), conta eventos, identifica rajadas de falhas de autenticação em janela móvel e exporta relatório CSV.

## Requisitos
- Python 3.9 ou superior
- Nenhuma biblioteca externa

## Executar

```bash
python analisador_logs.py logs_exemplo.csv
```

Exemplo com limite de 3 falhas em 5 minutos:

```bash
python analisador_logs.py logs_exemplo.csv --limite 3 --janela 5 -o relatorio.csv
```

Filtrar por período (ISO-8601; datas sem fuso são interpretadas como UTC):

```bash
python analisador_logs.py logs_exemplo.csv \
  --inicio 2026-10-26T09:00:00Z \
  --fim 2026-10-26T10:00:00Z \
  --limite 5 --janela 10 -o relatorio.csv
```

## Formato de entrada CSV

O arquivo precisa ter cabeçalho. Campos recomendados:

```csv
timestamp,user,ip,event
2026-10-26T09:01:00Z,ana,192.0.2.10,login_failed
```

Também aceita aliases comuns como `data`, `hora`, `username`, `src_ip`, `event_type`, `action`, `message` e `status`. O formato JSONL aceita um objeto JSON por linha com os mesmos campos.

## O que o relatório contém
- `contagem_usuario`: quantidade de eventos por usuário.
- `contagem_ip`: quantidade de eventos por IP.
- `contagem_tipo`: quantidade por tipo de evento.
- `alerta`: rajada de falhas de autenticação por usuário ou IP dentro da janela móvel.
- `linha_invalida`: linhas que não puderam ser interpretadas, com o número da linha e o motivo.

## Limitações importantes
- O detector é heurístico e depende de como o sistema registra falhas. Ajuste `FAILURE_RE` no código para os padrões reais dos seus logs.
- O alerta indica comportamento suspeito, não prova invasão. NAT, usuários legítimos que erram a senha e scanners autorizados podem gerar falsos positivos.
- A ferramenta não substitui SIEM/EDR nem correlaciona automaticamente eventos entre múltiplas fontes.
- Datas sem fuso são tratadas como UTC. Confirme o fuso do sistema de origem.
- Use apenas em logs que você tem autorização para analisar.

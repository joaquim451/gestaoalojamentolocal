# Requisitos Legais Obrigatórios (Portugal)

Este documento traduz requisitos regulatórios para critérios técnicos verificáveis.

## 1) Faturação Certificada AT
- O sistema deve emitir faturas, recibos e notas de crédito por software certificado AT ou integração API com software certificado.
- Deve existir trilho de auditoria por documento fiscal (estado, hash interno, timestamps, utilizador responsável).
- Deve suportar comunicação automática para AT segundo regras vigentes.

Critérios de aceitação:
- Emissão de documento fiscal com referência única e estado de comunicação.
- Retentativas automáticas em falhas de comunicação.
- Registo imutável de alterações e anulações.

## 2) Comunicação SEF/AIMA (SIBA)
- Reporte de hóspedes estrangeiros dentro do prazo legal (até 3 dias úteis após check-in e check-out, conforme enquadramento aplicável).
- Deve existir fila de envios, confirmação de entrega e gestão de falhas.

Critérios de aceitação:
- Submissão automática por evento de check-in/check-out.
- Histórico de submissões com estado e comprovativo.

## 3) Livro de Reclamações Eletrónico
- Link visível e direto para a plataforma oficial deve estar presente em áreas públicas exigidas.

Critérios de aceitação:
- Link renderizado no website/motor de reservas e páginas obrigatórias.
- Teste automatizado validando presença do link.

## 4) Reporte Estatístico INE
- Exportação estruturada dos dados operacionais para resposta a inquéritos obrigatórios.

Critérios de aceitação:
- Exportador com filtros por período, unidade e tipologia.
- Validação de integridade e consistência dos campos.

## 5) Taxas Turísticas Municipais
- Cálculo automático por concelho, sazonalidade, idade e regras de isenção.

Critérios de aceitação:
- Motor de regras versionado por município.
- Reprocessamento histórico quando regras mudam.

## 6) RGPD e Segurança (inclui PCI)
- Minimização de dados, consentimento, base legal, retenção e direito ao apagamento/portabilidade.
- Dados sensíveis e financeiros protegidos por cifragem em trânsito e em repouso.
- Nenhum dado completo de cartão deve ser armazenado fora de fornecedor PCI.

Critérios de aceitação:
- Registo de consentimentos e políticas de retenção por tipo de dado.
- Logs de acesso e trilho de auditoria.
- Mecanismos para DSAR (acesso/apagamento/retificação/exportação).

## 7) Seguro Obrigatório
- Registo de apólice e monitorização da validade do seguro de responsabilidade civil extracontratual (capital mínimo indicado no requisito).

Critérios de aceitação:
- Campo obrigatório por unidade/propriedade.
- Alertas de expiração configuráveis.

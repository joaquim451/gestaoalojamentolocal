# Arquitetura Inicial

## Módulos Core
1. Gestão de Propriedades e Unidades
2. Reservas e Calendário
3. Channel Manager (sincronização bidirecional)
4. Faturação e Compliance Fiscal (AT)
5. Reporte AIMA/SEF (SIBA)
6. Operações (limpeza, manutenção, lavandaria)
7. CRM/Comunicação (email, SMS, IA para triagem)
8. Portal do Proprietário
9. Analytics e Funis de Conversão

## Serviços Técnicos
- API Gateway
- Serviço de Autenticação (RBAC por perfil: admin, gestor, proprietário, fornecedor)
- Serviço de Notificações
- Motor de Regras (taxas turísticas, políticas de cancelamento)
- Job Queue para integrações assíncronas
- Auditoria e Observabilidade

## Integrações Externas
- OTAs: Airbnb, Booking.com, etc.
- Faturação certificada: InvoiceXpress / YnnovFat (ou outro certificado)
- SIBA: comunicação AIMA/SEF
- SMS/Email providers
- Pagamentos (gateway com tokenização)

## Dados e Segurança
- Base relacional para dados transacionais.
- Cache para disponibilidade/preço em tempo real.
- Cifragem TLS + cifragem de dados em repouso.
- Segregação de dados por conta/entidade gestora.

## Frontend e Mobile
- Frontend web em PT-PT com UX simplificada.
- App móvel para iOS/Android (operações em tempo real).
- Dashboard de performance (bounce rate, tempo no site, funis).

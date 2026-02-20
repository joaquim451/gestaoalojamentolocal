# Gestao Alojamento Local (Portugal)

Projeto base para um PMS + Channel Manager "All-in-One" focado no mercado português, com prioridade total para conformidade legal.

## Objetivo
Construir uma plataforma para proprietários e gestores de Alojamento Local em Portugal que:
- centralize reservas multicanal (Airbnb, Booking.com e outros);
- automatize operações (check-in/out, comunicação, limpezas, manutenção);
- garanta conformidade com AT, AIMA/SEF, INE, RGPD e regras municipais.

## Estrutura
- `docs/REQUISITOS_LEGAIS_PT.md`: requisitos legais obrigatórios e critérios de aceitação.
- `docs/ARQUITETURA.md`: proposta técnica inicial (módulos, integrações e segurança).
- `docs/ROADMAP.md`: plano de entregas por fases (MVP -> produção).
- `prompt/MASTER_PROMPT_PT.md`: prompt base para orientar desenvolvimento com IA.
- `src/backend`, `src/frontend`, `src/mobile`: pastas para implementação.

## Próximos Passos
1. Definir stack final (ex: Node.js + React + React Native).
2. Implementar autenticação, gestão de propriedades e reservas.
3. Integrar faturação certificada AT e reporte AIMA/SEF.
4. Desenvolver motor de reservas diretas e channel sync.
5. Preparar auditoria RGPD e trilhos de compliance.

## MVP Técnico Atual
- Backend Node.js/Express inicial em `src/backend`.
- Persistência local em `data/db.json`.
- Autenticação JWT simples com utilizador admin bootstrap via variáveis `AUTH_BOOTSTRAP_*`.
- Proteção de login com lockout temporário após tentativas falhadas consecutivas.
- Sessões com refresh token rotativo e logout com revogação de sessão.
- Gestão de utilizadores com perfis `admin` e `manager` (endpoints admin-only para criar/listar).
- Auditoria persistente de ações críticas (login, gestão de utilizadores, operações de reservas).
- CRUD de alojamentos e controle de ligação Booking por alojamento.
- Endpoints de configuração/sincronização Booking protegidos para perfil `admin`.
- Módulo inicial de rate plans com cotação dinâmica por noite (fim de semana/sazonalidade).
- Endpoint de link para Livro de Reclamações.

Ver detalhes em `docs/API_MVP.md`.

## Testes
- `npm test` para correr testes automáticos do backend (Node test runner).
- `npm run check` para validação rápida de sintaxe.

## Checklist: Troca de PC
Fluxo recomendado para continuar trabalho noutro computador sem perder alterações.

1. No PC atual (antes de desligar):
   - `git add .`
   - `git commit -m "descrição curta da sessão"`
   - `git push`
2. No novo PC (ao começar):
   - `git pull`
   - `npm install` (se necessário)
3. Durante o trabalho no novo PC:
   - repetir ciclo `add -> commit -> push`.

Boas práticas:
- manter `.env` fora do Git e atualizar `.env.example` quando surgirem novas variáveis.
- não copiar `node_modules` entre PCs; instalar sempre com `npm install`.
- em caso de conflito no `git pull`, resolver conflito, testar e só depois fazer `git push`.

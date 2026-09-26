#!/usr/bin/env node
/**
 * Integram MCP Server — exposes Integram AI tools via MCP protocol.
 *
 * Env vars:
 *   INTEGRAM_URL        — base URL (default: http://localhost:8081)
 *   INTEGRAM_EMAIL      — login email
 *   INTEGRAM_PASSWORD   — login password
 *   INTEGRAM_WORKSPACE  — workspace slug (e.g. "my")
 *   INTEGRAM_SKIP_HITL  — set to "true" to auto-confirm all HITL prompts (for automation)
 */

// ─── SOCKS/HTTP proxy for MCP calls (reads HTTPS_PROXY env) ─────────────────
import { EnvHttpProxyAgent, setGlobalDispatcher } from 'undici';
if (process.env.HTTPS_PROXY || process.env.HTTP_PROXY) {
  setGlobalDispatcher(new EnvHttpProxyAgent());
}

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createRequire } from 'module';
import { rememberActivation as rememberActivationIn, applyActivation, forgetActivation } from './activation-memory.js';
import { startOrphanWatchdog } from './orphan-watchdog.js';
import { enqueuePending, takePending } from './pending-hitl.js';

// Own identity — read from package.json, never hardcoded: a hardcoded copy drifts
// (it sat at 0.5.0 through the 0.6.0 and 0.7.0 releases).
const PKG = createRequire(import.meta.url)('./package.json');

const BASE_URL = (process.env.INTEGRAM_URL || 'http://localhost:8081').replace(/\/$/, '');
const EMAIL = process.env.INTEGRAM_EMAIL;
const PASSWORD = process.env.INTEGRAM_PASSWORD;
let workspace = process.env.INTEGRAM_WORKSPACE || '';
const SKIP_HITL = process.env.INTEGRAM_SKIP_HITL === 'true';

// ─── Auth state ──────────────────────────────────────────────────────────────

let accessToken = null;
let refreshToken = null;
let tokenExp = 0; // epoch seconds
let _authPromise = null;

async function apiFetch(path, opts = {}, _retried = false) {
  const url = `${BASE_URL}${path}`;
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;
  const res = await fetch(url, { ...opts, headers });
  if (!res.ok) {
    // Retry once on 401 — token may have expired between ensureAuth and fetch
    if (res.status === 401 && !_retried) {
      tokenExp = 0; // force re-auth
      await ensureAuth();
      return apiFetch(path, opts, true);
    }
    const text = await res.text().catch(() => '');
    const err = new Error(`API ${opts.method || 'GET'} ${path} → ${res.status}: ${text}`);
    // TD-065: тело отказа доезжает вместе с ошибкой — конвертация в isError
    // читает code/message/details из err.body, а не из текста «API … → 400: {…}».
    try { err.body = JSON.parse(text); } catch { /* не JSON — остаётся только текст */ }
    err.status = res.status;
    throw err;
  }
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`API ${opts.method || 'GET'} ${path} → invalid JSON response (${text.length} chars)`);
  }
}

// TD-065: отказ бэкенда → результат тула с isError:true (признак протокола MCP).
// Чистый текст для модели: message + details, без JSON-обёртки всего ответа.
// Тела нет (не JSON, сеть) — остаётся текст самой ошибки.
function toolErrorResult(err) {
  const be = err?.body?.error;
  const text = be
    ? `Error: ${be.message || err.message}${be.details ? '\n\n' + JSON.stringify(be.details, null, 2) : ''}`
    : `Error: ${err?.message}`;
  return { content: [{ type: 'text', text }], isError: true };
}

async function login() {
  if (!EMAIL || !PASSWORD) throw new Error('INTEGRAM_EMAIL and INTEGRAM_PASSWORD are required');
  const data = await apiFetch('/api/v2/iam/login', {
    method: 'POST',
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!data.ok) throw new Error(`Login failed: ${JSON.stringify(data.error)}`);
  accessToken = data.accessToken || data.data?.accessToken || data.data?.token;
  refreshToken = data.refreshToken || data.data?.refreshToken;
  tokenExp = decodeExp(accessToken);
  log(`Logged in as ${EMAIL}, token expires ${new Date(tokenExp * 1000).toISOString()}`);
}

async function ensureAuth() {
  const now = Math.floor(Date.now() / 1000);
  if (tokenExp - now >= 60) return;

  // Coalesce concurrent auth attempts into a single request
  if (_authPromise) return _authPromise;
  _authPromise = (async () => {
    if (refreshToken) {
      try {
        const data = await apiFetch('/api/v2/iam/refresh', {
          method: 'POST',
          body: JSON.stringify({ refreshToken }),
        });
        if (data.ok) {
          accessToken = data.accessToken || data.data?.accessToken || data.data?.token;
          refreshToken = data.refreshToken || data.data?.refreshToken || refreshToken;
          tokenExp = decodeExp(accessToken);
          log('Token refreshed');
          return;
        }
      } catch { /* fall through to re-login */ }
    }
    await login();
  })().finally(() => { _authPromise = null; });
  return _authPromise;
}

function decodeExp(jwt) {
  try {
    if (!jwt || typeof jwt !== 'string') return 0;
    const parts = jwt.split('.');
    if (parts.length < 3) return 0;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload.exp || 0;
  } catch { return 0; }
}

function log(msg) {
  process.stderr.write(`[integram-mcp] ${msg}\n`);
}

// ─── Сигнал о новой версии в npm ─────────────────────────────────────────────
//
// Пакет обновляется вручную (npm publish), поэтому клиенту нужен способ узнать,
// что он запустил устаревшую сборку. Два канала, оба необязательные для работы:
//
//   1. stderr — единственный поток, куда спецификация stdio-транспорта прямо
//      разрешает писать что угодно ("The server MAY write UTF-8 strings to
//      stderr for any logging purposes"). В stdout нельзя ничего, кроме
//      JSON-RPC. Клиент stderr МОЖЕТ проигнорировать — поэтому канал не один.
//   2. Приписка к результату первого вызова инструмента — единственный канал,
//      который доходит до модели и через неё до человека. Ровно один раз за
//      запуск процесса.
//
// Чего здесь намеренно нет: пакета update-notifier (печатает в stdout и только
// при TTY — под stdio-транспортом не сработает и сломает протокол) и
// notifications/message (объявлен устаревшим в версии протокола 2026-07-28,
// а отправка до initialize ломает строгие клиенты).
//
// Проверка не блокирует запуск, не падает без сети и глушится переменными
// NO_UPDATE_NOTIFIER (общепринятое соглашение) и INTEGRAM_MCP_NO_UPDATE_CHECK.

const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const NPM_REGISTRY = (process.env.npm_config_registry || 'https://registry.npmjs.org').replace(/\/$/, '');
let updateNotice = null;          // текст приписки, когда есть версия новее

// Сравнение версий: >0 если a новее b. Предвыпуск (0.8.0-beta.1) считается
// старше своего релиза и не поднимает сигнал.
function cmpVersion(a, b) {
  const parse = v => {
    const m = /^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/.exec(String(v).trim());
    return m ? { nums: [+m[1], +m[2], +m[3]], pre: m[4] || '' } : null;
  };
  const pa = parse(a), pb = parse(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] > pb.nums[i] ? 1 : -1;
  }
  if (pa.pre === pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  return pa.pre > pb.pre ? 1 : -1;
}

async function checkForUpdate() {
  if (process.env.NO_UPDATE_NOTIFIER || process.env.INTEGRAM_MCP_NO_UPDATE_CHECK) return;
  try {
    const { readFileSync, writeFileSync } = await import('fs');
    const os = await import('os');
    const path = await import('path');
    const cacheFile = path.join(os.tmpdir(), `${PKG.name}-update-check.json`);

    let latest = null;
    try {
      const cached = JSON.parse(readFileSync(cacheFile, 'utf8'));
      if (Date.now() - cached.checkedAt < UPDATE_CHECK_INTERVAL_MS) latest = cached.latest;
    } catch { /* кэша нет или он битый — спросим реестр */ }

    if (!latest) {
      // Самая лёгкая точка реестра: только теги, без метаданных пакета.
      const res = await fetch(`${NPM_REGISTRY}/-/package/${PKG.name}/dist-tags`, {
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) return;
      latest = (await res.json())?.latest;
      if (!latest) return;
      try { writeFileSync(cacheFile, JSON.stringify({ checkedAt: Date.now(), latest })); } catch { /* кэш необязателен */ }
    }

    // Предвыпуск не предлагаем тому, кто сидит на стабильной версии: тег latest
    // на него в норме не указывает, а если указал — это оплошность выкладки.
    if (/-/.test(latest) && !/-/.test(PKG.version)) return;
    if (cmpVersion(latest, PKG.version) <= 0) return;

    log(`Доступна версия ${latest} (запущена ${PKG.version}): https://www.npmjs.com/package/${PKG.name}`);
    updateNotice = [
      `⚠️ integram-mcp: запущена версия ${PKG.version}, в npm выложена ${latest}.`,
      `Скажи пользователю обновиться: заменить версию в конфиге MCP на \`${PKG.name}@${latest}\` и перезапустить клиент.`,
      `Список изменений: https://www.npmjs.com/package/${PKG.name}`,
    ].join(' ');
  } catch { /* нет сети, реестр недоступен, прокси — работе сервера не мешает */ }
}

// Приписывает сигнал к КАЖДОМУ ответу инструмента, пока юзер не обновится:
// одноразовая приписка в длинной сессии теряется, а устаревшая сборка — это
// дыра против юзера (нет новых тулов и фиксов до ручного обновления).
export function withUpdateNotice(result) {
  if (!result || !Array.isArray(result.content)) return result;
  let extra = [];
  if (updateNotice) extra.push(updateNotice);
  if (unreadNotice) { extra.push(unreadNotice); unreadNotice = null; }
  if (!extra.length) return result;
  return { ...result, content: [...result.content, { type: 'text', text: extra.join('\n') }] };
}

// ─── Сводка непрочитанных при старте ────────────────────────────────────────
//
// Канал «сервер MCP → модель → пользователь» без подписок из спецификации
// 2026-07-28 (в Claude Code их ещё нет): приписка к ответу инструмента.
// Одноразовая — сводка в каждом ответе была бы спамом (сигнал обновления
// приписывается ДО ОБНОВЛЕНИЯ к каждому — там одноразовость вредна).

let unreadNotice = null;

export function setUnreadNotice(text) { unreadNotice = text; }

export function buildUnreadNoticeText(data) {
  if (!data || !Array.isArray(data.items)) return null;
  const busy = data.items.filter((i) => i.count > 0);
  if (!busy.length) return null;
  return [
    `🔔 Непрочитанные уведомления: ${busy.map((i) => `${i.workspace} — ${i.count}`).join(', ')}.`,
    'Скажи пользователю, где висит непрочитанное. Прочитать: switch_workspace на воркспейс и list_notifications.',
  ].join(' ');
}

async function checkUnreadNotifications() {
  try {
    await ensureAuth();
    let db = workspace;
    if (!db) {
      const list = await apiFetch('/api/v2/workspaces');
      const first = (list.data || list)[0];
      if (!first?.slug) return;
      db = first.slug;
    }
    const data = await apiFetch(`/api/v2/${db}/notifications/across-workspaces`);
    const payload = data.data || data;
    const text = buildUnreadNoticeText(payload);
    if (text) {
      setUnreadNotice(text);
      log(text);
    }
  } catch { /* нет сети, бэкенд недоступен — работе сервера не мешает */ }
}

// ─── Tool definitions cache ──────────────────────────────────────────────────

let allTools = [];                // full list from backend
const activeTools = new Map();    // name → tool def (currently exposed via MCP)
// Память активации по воркспейсу: switch_workspace ВОССТАНАВЛИВАЕТ неядерную
// активацию целевого воркспейса, а не сбрасывает до ядра. Инцидент 05.09.2026:
// clear() в switch_workspace субагента сбрасывал активацию ГЛОБАЛЬНО — у
// основного сеанса тоже; см. tests/activation-memory.test.js.
const activationMemory = new Map(); // slug → Set имён неядерных инструментов

function rememberActivation() {
  rememberActivationIn(activationMemory, workspace, [...activeTools.keys()], BUILT_IN_NAMES);
}

// Загрузить наборы инструментов целевого воркспейса: ядро + восстановленная
// из памяти активация. Единая замена прежним clear()+core в четырёх местах.
async function loadWorkspaceTools(slug) {
  const tools = await fetchTools();
  activeTools.clear();
  for (const t of tools) {
    if (t.group === 'core' && !BUILT_IN_NAMES.has(t.name)) activeTools.set(t.name, t);
  }
  const restored = applyActivation(activationMemory, slug, tools, (t) => activeTools.set(t.name, t));
  await server.sendToolListChanged();
  return { tools, restored };
}

// Built-in MCP tools handled locally — never load from backend to avoid duplicates
const BUILT_IN_NAMES = new Set([
  'list_workspaces', 'switch_workspace', 'create_workspace',
  'delete_workspace', 'clone_workspace', 'search_tools', 'confirm_action',
]);

// Pending HITL state — each entry carries a short id so confirm_action names
// exactly which pending action it confirms (PM-241: a confirm used to execute
// the OLDEST queued action, not the approved one).
const pendingHitlQueue = []; // [{ id, threadId, action, description, createdAt, onApprove?, onReject? }, ...]
const HITL_QUEUE_MAX_SIZE = 50;
const HITL_QUEUE_TTL_MS = 10 * 60 * 1000; // 10 minutes
let _hitlSeq = 0;
const nextHitlId = () => `c${(++_hitlSeq).toString(36)}${Date.now().toString(36).slice(-4)}`;

async function fetchTools() {
  const data = await apiFetch(`/api/v2/${workspace}/ai/tools`);
  if (!data.ok) throw new Error(`Failed to fetch tools: ${JSON.stringify(data.error)}`);
  allTools = data.data;
  return allTools;
}

// ─── MCP Server (low-level — we pass raw JSON Schema, not Zod) ──────────────

export const INSTRUCTIONS = `Integram — workspace-based platform: tables, documents, reports, automations, permissions, forms, webhooks, files, knowledge graph.
Server: ${BASE_URL}

## Getting started
1. list_workspaces → switch_workspace (required before anything else). Or create_workspace to start fresh.
2. Explore: list_tables, list_documents, list_objects for data; semantic_search for fuzzy lookup.
3. Workspace management: clone_workspace to duplicate an existing workspace; delete_workspace to permanently remove one.

## Tool discovery
Stuck or unsure how the platform works? docs_map() and docs_search(query) are active from the start and read the platform docs corpus (115 documents: backend, portal, frontend, ADRs, guides). Use them before guessing.

Only core tools (CRUD, search, docs corpus, graph, comments, bulk, history) are loaded by default. Use search_tools to activate more — it reports what it activated and names the tools, so it doubles as the group catalog.

Different tools with similar names are NOT interchangeable. Before any call that requires confirmation, verify the exact tool name against its description: set_grant (group "grants") changes access rights, set_portal_config (group "portal") writes the portal config — one is not the other. If the tool you need is not in the active list, call search_tools to activate its group — never substitute a similar active tool.

---

Phrase triggers — user wording maps to a tool group; activate it and use its tools, do NOT fall back to generic objects/documents:
- «создай задачу», «задача в PM», «PM-задача», «task in PM» → group "pm": pm_create_issue in the ACTIVE workspace (module PM, not EAV objects, not documents)
- «создай таблицу» → "schema"; «отчёт/репорт» → "reports"; «документ/заметка» → "docs"

## PM task policy
- One actionable item → one task. Multi-part work → epic + child tasks (parent_id), never one task with a wall-of-text description.
- Infer, don't ask: type (падает/ошибка → bug; «хочу/добавь» → feature; крупное и без краёв → epic; иначе task), priority from urgency words (срочно/блокер → urgent/high), labels from area + tier.
- Labels answer «откуда задача и про что» — self-explanatory words, no cryptic codes: источник («спека»), область (backend/frontend/platform), тема («pm», «orgs»). Срочность живёт в priority, НЕ в метках. 2-4 per task. Setting labels REPLACES the whole array — read current labels first when adding to existing.
- Estimates (1-2-3-5-8-13-21) only for OPEN tasks; don't set on done.
- Never invent due_date; set it only if the user named a date. Done-статус — переходом через pm_update_issue, не сразу при создании.
- Child issues do NOT inherit labels from their epic — set labels explicitly on every create.
- Ask ONLY when: the wording fits both a PM task and something else (EAV record / document), or a bulk breakdown (>3 tasks) has no obvious split.

## Data modeling — the DECISION TREE

For every field, ask: "Where do the values come from?"

1. **User types any value, each entry unique** (name, address, phone, email)
   → **text** (or **memo** for long text)

2. **User picks ONE value from a fixed set** (status, priority, category, city, stage, department, type)
   → **ref** to a lookup table (single select dropdown)
   How: create a lookup table with options → add ref column pointing to it

3. **User picks MULTIPLE values from a fixed set** (tags, skills, features, categories)
   → **ref + multi=true** to a lookup table (multiselect checkboxes/chips)
   How: create a lookup table with options → add ref column with multi=true

4. **User picks a record from another entity** (client on a deal, assignee on a task)
   → **ref** to that entity's table (dropdown showing records from the target table)
   How: add ref column with refTypeId = target table ID

5. **Data is a sub-list owned by a parent** (order items, task steps, contact persons, comments)
   → **child table** with parentTableName (in plan_schema) or parentTypeId (in create_table)
   Child records are created with parentId and shown as nested tabs inside parent record

6. **Numeric value** (price, qty, score) → **number**
7. **Date** (deadline, birthday) → **date**; with time → **datetime**
8. **Yes/No flag** (active, done) → **bool**
9. **File upload** (photo, document) → **file**

## Lookup tables (справочники) — dropdowns & multiselects

A lookup table = regular table where each record is one option. Other tables reference it via ref columns → user sees a dropdown.

**Key rules:**
- Lookup table itself has NO columns — only a name per record (seedRecords in plan_schema)
- The ref column goes in the TABLE THAT USES the dropdown, NOT in the lookup table
- One lookup can serve multiple ref columns across different tables (e.g., "Priorities" used by both "Tasks" and "Deals")
- For multiselect: ref + multi=true. Multiselect WITHOUT a lookup is IMPOSSIBLE.
- When setting ref values in create_object/update_object: pass either the record ID (number) OR the exact record name — the backend resolves names → ids via _v2_objects lookup. For multi: comma-separated ids or names. Ambiguous names (multiple matches) throw an error — pass id to disambiguate.

**Common lookups to create:**
- Statuses: "New", "In Progress", "Done", "Cancelled"
- Priorities: "Low", "Medium", "High", "Critical"
- Categories/Types: domain-specific classification
- Stages: workflow steps ("Lead", "Negotiation", "Contract", "Closed")
- Tags: multi-select labels

## Table relationships — ref vs child vs lookup

| Pattern | Example | How | UI |
|---|---|---|---|
| **Lookup** (fixed options) | Task → Status | lookup table + ref column | dropdown |
| **Lookup multi** (multiple options) | Task → Tags | lookup table + ref + multi=true | checkboxes/chips |
| **Reference** (link to entity) | Deal → Client | ref column pointing to entity table | dropdown with entity records |
| **Child table** (owned sub-records) | Order → Order Items | child table with parentTableName | nested tabs inside parent record |

**When to use ref vs child table:**
- **ref** = link between INDEPENDENT entities. Both exist on their own. Deleting one doesn't delete the other. Example: Deal references Client — Client exists without Deal.
- **child table** = OWNED sub-records. Children don't exist without parent. Shown as tabs inside parent record, NOT in sidebar. Example: Order has Order Items — items don't exist outside the order.

**Child table rules:**
- In plan_schema: set parentTableName = name of parent table
- In create_table: set parentTypeId = ID of parent table
- When creating child records: pass parentId = ID of the parent record
- Child tables appear as nested tabs when viewing the parent record
- Child tables do NOT appear in the sidebar navigation
- A child table can have its own columns, refs, and even its own child tables (nested hierarchy)

## plan_schema — create entire schema in one shot

**ALWAYS use plan_schema when creating 2+ tables.** Activate via search_tools("schema").

plan_schema({ tables: [...] }) creates all tables, columns, refs, and seed records with ONE confirmation.

**Table properties:**
- name (required) — table name
- icon — emoji icon
- valueColumnName — display name for the virtual _value column (record name). Default = table name in singular form (table "Clients" → column "Client"). Use valueColumnName only if you want a different header (e.g. "Full Name" instead of "Client", "Order #" instead of "Order").
- isLookup — true for dropdown/lookup tables (only has seedRecords, no columns)
- seedRecords — array of option names for lookup tables: ["New", "Active", "Closed"]
- parentTableName — name of parent table (for child tables). Must match another table's name in the plan.
- columns — array of column definitions (see below). Do NOT include a "Name"/"Title" column — it duplicates _value.

**Column properties:**
- alias (required) — display name
- type — data type: text/memo/number/date/datetime/bool/file/pwd/uuid/url/duration/currency/percent/rating/status/choice/phone/email/collaborator/http_button/script_button/ai_button (NOT needed if refTable is set)
- refTable — name of another table in the plan for ref/dropdown column
- multi — true for multiselect (REQUIRES refTable)
- required — true for mandatory field
- unique — true for unique constraint (article codes, SKU, email if must be unique)
- size — length limit: "100" (max chars) or "10,2" (precision,scale for numbers e.g. price with 2 decimals)
- kind — set to "FORMULA" for a computed column. Only FORMULA is supported in plan_schema.
- expr — formula for kind=FORMULA. Variables are other column aliases of the SAME table in square brackets: "[Цена] * [Количество]". Variables are resolved to column IDs automatically.

**Smart header grouping — column merging under parent headers:**
Use dot "." in alias to group columns: "Group.Column" → columns with same prefix merge under a shared header.
Example: { "alias": "Contacts.Phone" }, { "alias": "Contacts.Email" }, { "alias": "Contacts.Telegram" } → all three appear under "CONTACTS" parent header.
Rules: at least 2 consecutive columns with same prefix; columns without dot remain standalone.
Use for tables with many related columns (contacts, address, financials, specs). Skip for tables with ≤4 columns.

**CRITICAL — _value virtual column (record name):**
Every table automatically has a virtual _value column — the record's display name (first column in UI, clickable link).
- _value is filled via the "name" field in create_object / bulk_create.
- Do NOT create a separate "Name"/"Title"/"Название" column — it duplicates _value and causes UI confusion.
- Default _value header = table name in singular form ("Products" → "Product"). Use valueColumnName only to override (e.g. "Full Name" instead of "Client").

**CRITICAL rules:**
- Ref columns go in the TABLE THAT REFERENCES, NOT in the lookup. "Status" column → in "Clients", NOT in "Statuses".
- Lookup tables (isLookup=true) have ONLY seedRecords, NO columns array.
- Tables are auto-sorted: lookups first, then parents, then children. No need to order manually.
- refTable must match the exact name of another table in the same plan.
- After plan_schema completes — ALL tables, columns, refs, and seed records are ALREADY created. Do NOT call create_table, add_column, create_object, or plan_schema after it — everything is done. Just tell the user what was created.
- LOOKUP/ROLLUP columns are NOT supported in plan_schema — create the tables first, then add them with create_computed.

**Example — Project Management:**
\`\`\`json
{
  "tables": [
    { "name": "Statuses", "isLookup": true, "seedRecords": ["Backlog", "In Progress", "Review", "Done"] },
    { "name": "Priorities", "isLookup": true, "seedRecords": ["Low", "Medium", "High", "Critical"] },
    { "name": "Tags", "isLookup": true, "seedRecords": ["Bug", "Feature", "Improvement", "Urgent"] },
    { "name": "Projects", "icon": "📁", "columns": [
      { "alias": "Description", "type": "memo" },
      { "alias": "Status", "refTable": "Statuses" },
      { "alias": "Start Date", "type": "date" },
      { "alias": "Budget", "type": "number" }
    ]},
    { "name": "Tasks", "icon": "✅", "columns": [
      { "alias": "Description", "type": "memo" },
      { "alias": "Project", "refTable": "Projects" },
      { "alias": "Status", "refTable": "Statuses" },
      { "alias": "Priority", "refTable": "Priorities" },
      { "alias": "Tags", "refTable": "Tags", "multi": true },
      { "alias": "Deadline", "type": "date" },
      { "alias": "Completed", "type": "bool" }
    ]},
    { "name": "Subtasks", "parentTableName": "Tasks", "icon": "📋", "columns": [
      { "alias": "Done", "type": "bool" }
    ]},
    { "name": "Comments", "parentTableName": "Tasks", "columns": [
      { "alias": "Text", "type": "memo", "required": true },
      { "alias": "Date", "type": "datetime" }
    ]}
  ]
}
\`\`\`

This creates: 3 lookups (dropdown sources), 2 main tables (Projects, Tasks) linked by refs, 2 child tables (Subtasks, Comments nested inside Tasks). Tasks has single-select Status/Priority, multiselect Tags, and a ref to Projects. Note: NO "Name"/"Title" columns — record names are set via _value (the "name" field in create_object).

**Example — Manufacturing (from production template):**

Lookups: Shops, Equipment Statuses ["Working","Maintenance","Broken","Decommissioned"], Maintenance Types ["Planned","Unplanned","Emergency","Diagnostic"], Severity Levels, Units, Positions
Main tables: Equipment (→Shop ref, →Status ref, Model text, Serial text, Commissioned date, Description memo), Spare Parts (SKU text unique, →Unit ref, →Supplier ref, Qty number, MinQty number)
Child tables: Maintenance → child of Equipment (→Type ref, →Executor ref, Planned date, Actual date, Cost number), Incidents → child of Equipment (→Severity ref, Description memo, Downtime number, Resolution memo)
Independent: Suppliers (Contact text, Email text, Phone text), Staff (→Position ref, →Shop ref)

**Example — E-commerce (from production template):**

Lookups: Categories, Product Statuses ["Active","Draft","Discontinued"], Order Statuses ["New","Processing","Shipped","Delivered","Cancelled"], Payment Statuses ["Pending","Paid","Refund"], Ticket Statuses, Document Types ["Invoice","Waybill","Act","Return"]
Main tables: Products (→Category ref, →Status ref, SKU text unique, Price number, Cost number, Description memo, Photo file, InStock bool), Clients (Email text, Phone text, Address memo, Comment memo), Orders (→Client ref, →Status ref, →Payment Status ref, →Warehouse ref, Total number, Tracking text, Date datetime)
Child tables: Order Items → child of Orders (→Product ref, Qty number, Price number, Sum number)
Independent: Warehouses (Address text, Phone text), Stock (→Product ref, →Warehouse ref, Qty number), Support Tickets (→Client ref, →Order ref, →Status ref, Subject text, Description memo)

**Example — Farm Shop (from production template):**

Lookups: Client Sources ["UDS","VK","Instagram","Telegram","Referral","Repeat"], Order Statuses, Payment Statuses, Product Categories, Messengers, Delivery Methods ["CDEK","Russian Post"], Loyalty Levels
Main tables: Clients (valueColumnName="Full Name", Phone text, Email text, →Messenger ref, →Source ref, →Loyalty ref, Points number, Total number), Products (→Category ref, SKU text, Price number, Photo file, Description memo, Weight number, InStock bool), Orders (→Client ref, →Status ref, →Payment ref, →Delivery ref, →Messenger ref, Number text, Total number, Ship date, Tracking text)
Child tables: Addresses → child of Clients (City text, Address memo, Zip text, Primary bool), Order Items → child of Orders (→Product ref, Qty number, Price number), Reorders → child of Orders (Sum number, Comment memo, →Payment ref), Comments → child of Orders (Text memo)

**Advanced patterns (from production systems):**
1. **Shared lookup across tables** — one "Statuses" lookup can be used in Orders, Tasks, Tickets etc. One isLookup table, multiple ref columns in different tables pointing to it. Don't create "Order Statuses" + "Task Statuses" if values are the same.
2. **Multiple refs to same table** — a Contract can reference Contractor THREE times: "Customer", "Executor", "Agent". Each is a separate ref column with different alias but same refTable.
3. **Lookups with extra columns** — if a lookup needs its own data fields (e.g. Bank with BIC, Role with Template), use isLookup=false with both columns AND seedRecords.

**Patterns from production templates:**
- Status, Category, Type, Priority, Payment Method, Source, Messenger, Role, City → ALWAYS lookup table (isLookup + seedRecords), never text
- Order items, Maintenance, Incidents, Addresses, Reorders, Details, Statistics → CHILD tables (parentTableName), not standalone
- Phone, Email, Address, SKU, Tracking, TIN, URL → text
- Price, Qty, Cost, Downtime, Points, Reach, Subscribers → number
- Description, Notes, Resolution, Comment, Details (long) → memo

**Common mistakes to avoid:**
1. Missing lookup table — if a ref column points to "OrderStatuses", a table "OrderStatuses" with isLookup=true MUST exist in the plan
2. Not using child tables — order items, maintenance records, addresses, contacts, details, statistics MUST be child (parentTableName), not standalone root tables
3. Using text for statuses/categories — these are ALWAYS lookups
4. Creating duplicate lookups — if "Statuses" is shared across Orders and Tasks, create ONE lookup, not two separate "Order Statuses" and "Task Statuses" tables
5. Forgetting multiple refs — when an entity has multiple roles (buyer/seller/agent), create separate ref columns with unique aliases pointing to the same refTable

**Manual schema creation (for single table or adding to existing):**
When not using plan_schema — plan ALL tables first. Ref columns need the target table to exist. Steps:
1. Create ALL lookup tables first (statuses, categories, tags)
2. Fill lookup tables with option records (create_object)
3. Create main tables with ref columns pointing to lookups (add_column with refTypeId)
4. Create data — for ref fields, use record IDs from lookup tables

---

## Records (objects)

Records are created with create_object({ typeId, fields, parentId }). Fields is an object { columnAlias: value }.
- For text/number/date/bool: pass the value directly: { "Название": "iPhone 15", "Цена": 999, "В наличии": true }
- For single ref: pass either the record ID as a number OR the exact record name as a string — the backend resolves both: { "Статус": 42 } or { "Статус": "Новый" }. ID is preferred when names may be ambiguous.
- For multiselect: comma-separated ids or names: { "Теги": "urgent, important" } or { "Теги": "12, 13" }
- For child records: include parentId = ID of the parent record

list_objects returns records with column aliases as keys. Use search for free-text search across all fields; filters for exact match on known aliases.

## Computed columns (LOOKUP, ROLLUP, FORMULA)

Computed columns auto-calculate values based on other data. Activate via search_tools("schema"); for computed columns and formulas specifically use search_tools("schema computed formula").

- **LOOKUP** — pull a value from a related record through a reference column. Like VLOOKUP in Excel.
  Example: Order has ref to Product → LOOKUP pulls Product's price into Order table.
  Config: { sourceReqId: refColumnId, targetColId: targetColumnId }

- **ROLLUP** — aggregate values from child records or linked records. Like SUMIF in Excel.
  Example: Order has child table OrderItems → ROLLUP sums all item prices.
  Config: { linkReqId: columnIdInChildTable, targetColId: childColumnId, fn: "SUM"|"AVG"|"COUNT"|"MIN"|"MAX" }
  Note: linkReqId is the column in the CHILD table that references this (parent) table, NOT a column in this table.

- **FORMULA** — calculate a value using an expression with other columns.
  Example: "Сумма" = [Цена] * [Количество]
  Config: { expr: "[Цена] * [Количество]", vars: { "varName": reqId } }
  Use generate_formula(typeId, description) to auto-generate formula from natural language.
  Formula functions: if, switch, coalesce, isnull, abs, round, floor, ceil, sqrt, power, mod, log, sign, int, sum, average, min, max, concat, upper, lower, trim, len, left, right, substr, contains, starts_with, ends_with, find, replace, today, now, year, month, day, hour, minute, weekday, date_diff, date_add, number, text, bool, and, or, not, xor

Workflow: list_computed → create_computed(kind, typeId, alias, config) → update_computed / delete_computed.
Backlinks: get_schema_backlinks(typeId) — show which columns from OTHER tables reference this table. Useful when creating ROLLUP to discover available linkReqId values.

## Validation rules

Set constraints on column values. Activate via search_tools("schema validation rules").
- get_validation_rules(reqId) — see current rules for a column
- set_validation_rules(reqId, rules) — set rules: { minLength, maxLength, minValue, maxValue, regex, unique }
Example: require email format → set_validation_rules(reqId, { regex: "^[\\\\w.-]+@[\\\\w.-]+\\\\.[a-z]{2,}$" })

## AI Buttons

AI Button is a column that shows a clickable button per row. When clicked, it runs an LLM prompt using data from that row and optionally writes the result to another column.

Setup: 1) add_column(typeId, alias, colTypeName="ai") → 2) configure_ai_button(typeId, reqId, prompt, ...)
- In prompt, use [ColumnName] to inject column values: "Summarize: [Description]"
- [ID] = record id, [VAL] = record display name
- outputReqId = column ID where AI result is auto-written (optional)
- temperature: "low" (0.2 — factual), "medium" (0.7 — balanced), "high" (1.2 — creative)
- agentMode: true — run full agent with all tools (web_search, tables, docs, etc.) instead of simple LLM chat
Run per row: run_ai_button(typeId, reqId, objectId). Get config: get_ai_button_config(typeId, reqId).

## HTTP Buttons

HTTP Button (type 1016) is a column that makes a direct HTTP request on button click using row data as placeholders — no LLM involved.

Setup: 1) add_column(typeId, alias, colTypeName="http_button") → 2) configure_http_button(typeId, reqId, url, method?, headers?, bodyTemplate?, responsePath?, outputReqId?)
- url and bodyTemplate support [ColumnName] placeholders (replaced with row values)
- responsePath — dot-notation path to extract value from JSON response (e.g. "data.price")
- outputReqId = column ID where extracted value is auto-written (optional)
Run per row: run_http_button(typeId, reqId, objectId). Get config: get_http_button_config(typeId, reqId).

## Script Buttons

Script Button (type 1020) is a column that runs user-written JavaScript on button click. Scripts execute exclusively in the browser (Web Worker) — server-side execution is disabled for security.

Setup: 1) add_column(typeId, alias, colTypeName="script_button") → 2) configure_script_button(typeId, reqId, script, outputReqId?)
- Script globals: \`row\` (field name → value map, includes row.ID), \`fetch\` (HTTP requests via server proxy), \`ai(prompt, model?)\` (LLM call, default model: "fast"), \`output(value)\` (write result), \`setField(reqId, value)\` (write to any column)
- outputReqId = column ID where result is auto-written (optional)
- Timeout: 60s total (allows time for fetch + ai calls)
- Scripts can only be run by clicking the button in the UI. There is no server-side run tool.
Get config: get_script_button_config(typeId, reqId).

Example scripts:
- \`output(row['Price'] * 1.2)\` — apply markup
- \`const r = await fetch('https://api.example.com?q=' + encodeURIComponent(row['Name'])); const d = await r.json(); output(d.price)\` — fetch from external API
- \`const summary = await ai('Classify this product: ' + row['Name']); output(summary)\` — LLM classification

---

## run_script Tool

Execute JavaScript in an isolated sandbox (isolated-vm, V8 isolate). Requires confirmation (TIER_HIGH).

run_script(script, typeId, objectId?, timeoutMs?)
- script: JavaScript code to execute
- typeId: table ID (for column definitions and row context)
- objectId: record ID (loads row data). If omitted, row = {}
- timeoutMs: execution timeout (max 60000, default 60000)

Script globals: row (record fields object, empty {} if no objectId), fetch(url, opts) → {status, body, ok}, ai(prompt, model?) → string, output(value), setField(reqId, value) (requires objectId — skipped without it), query(typeId, opts) → [{id, value, parentId, typeId}] (metadata only — use getRecord for full fields), getRecord(id), createRecord(typeId, {name, fields}), updateRecord(id, {fields}), deleteRecord(id), console.log(), JSON, Math, Date.
- browse(query, source?) — search marketplace prices. Returns [{name, price, url, source}]. Calls browser service internally.

Returns: { value, fields, logs }
- value: string from output() call
- fields: { reqId: value } from setField() calls (written to DB only if objectId was provided)
- logs: array of console.log() messages

Limits: 128MB RAM, 60s timeout, rate limits per execution (30 queries, 50 mutations, 50 fetch, 10 ai).
SSRF protection: requests to localhost, private IPs, .local, .internal are blocked.

---

## search_prices Tool

Search marketplace prices for a product by name. Returns array of results with name, price, URL, source.

search_prices(query, source?, limit?)
- query: product name to search
- source: marketplace source (default: "komus"). Supported: komus, wildberries, samson.
- limit: max results (default: 10)
- Returns: { items: [{name, price, url, source}], query, total }
- TIER_LOW — no confirmation required.
- Requires browser service running on port 3099.

---

## Reports

Reports aggregate and filter data from tables. Activate via search_tools("reports").

**Creating a report:**
1. create_report(name, parentTypeId) — parentTypeId = source table ID. Returns reportId.
2. add_report_column(reportId, reqTypeId or columnAlias) — add columns. Returns colId.
   **IMPORTANT:** Do NOT add the record name (_value) column — it is included automatically as the first column of every report. Passing valueColumnName (e.g. "Наименование") or the table name as columnAlias creates a broken column with reqTypeId=0 that shows "NaN" in the report.
3. Optionally set func (SUM/AVG/COUNT/MIN/MAX/GROUP_CONCAT), totalFunc (footer totals), storedFrom/storedTo (default filters).
4. update_report(reportId, where) to add WHERE filter.

**WHERE filter syntax:**
- Column alias in WHERE = "c" + colId (from add_report_column response, NOT the original reqTypeId)
- Tokens: [USER] = current username, [USER_ID] = current user id, [TODAY] = today's date, [NOW] = current datetime
- {{DB}} = workspace EAV table name (for subqueries, auto-resolved at execution time)
- Example: \`AND c35768.val = '[USER]'\` — filter to current user's records
- Subquery example: \`AND EXISTS (SELECT 1 FROM {{DB}} _st WHERE _st.up = a.up AND _st.val = '378' AND _st.t = 393)\` — filter child records by parent's ref field (a.up = parent record ID)

**Aggregation in reports:**
- func on a column: SUM, AVG, COUNT, MIN, MAX, GROUP_CONCAT
- totalFunc: shows a total in the report footer
- havingFrom/havingTo: HAVING filters for aggregated columns (e.g., "show only groups with COUNT > 5")
- storedFrom/storedTo: default filter range (pre-applied when user opens the report). Supports [TODAY], [NOW]. For ref columns, use the record ID (not name).

**Cross-table reports (JOIN):**
- create_report_join(reportId, typeId, alias) — add JOIN to another table. For child table reports, JOIN to parent table is auto-detected (uses a.up).
- add_report_column with joinAlias=alias — column from the joined table. Works with ref columns (inverted EAV handled automatically).
- storedFrom/storedTo on joined columns — filter by joined table's field values.
- Example workflow: report on "Order Items" (child) + JOIN to "Orders" (parent, alias="order") + column "Order Status" (joinAlias="order", storedFrom=statusId, storedTo=statusId) → filters child records by parent's status.
- delete_report_join(reportId, joinId) — remove JOIN (requires confirmation).

**Permissions report:** create_report with parentTypeId=9001 (virtual). Columns: 9011=User, 9012=Role, 9013=Object Type, 9014=Access Level, 9015=Export flag, 9016=Delete flag.

Run: get_report(reportId, limit, filters). Structure: describe_report(reportId). History: get_report_history(reportId).
Export: export_report(reportId, filters?, order?, limit?) — export report data to CSV string. Returns { csv, filename, rowCount }.
Bulk update: report_bulk_update(reportId, filters?) — mass-update records using SET expressions defined in report columns (requires confirmation). Only works if report has SET columns configured.

## Documents

Block-based documents (like Notion). Activate via search_tools("документ document"); for a subarea narrow the query: search_tools("документ block"), search_tools("документ folder"), search_tools("документ tag"), search_tools("документ version"), search_tools("документ trash restore"), search_tools("документ template pdf"), search_tools("документ access sharing").

- list_documents(search, folderId) — browse documents
- get_document(docId) / get_document_blocks(docId) — read content and block structure
- create_document(title, parentId) — create new doc (parentId for nesting)
- append_block(docId, text, type, format) — add block at end. Types: text, heading, code, quote, list, todo. format:"delta" — text is a ready Quill delta {"ops":[…]}; without it, markdown autodetect/plain text.
- update_block(docId, blockId, text, format) — modify existing block. format:"delta" — text is a ready Quill delta {"ops":[…]}; without it, plain text.
- delete_block(docId, blockId) — remove block
- update_document_title(docId, title)
- delete_document(docId) — move document to trash (requires confirmation)
- reorder_blocks(docId, order) — reorder blocks in a document. order = array of block IDs in target order.
- create_document_from_template(templateId, title?, folderId?) — create document from a template (doc with is_template=true)
- generate_pdf(objectId, templateId, format?, landscape?) — generate PDF from template document for a specific record. Returns { filename, size, base64 }.

**Trash:**
- list_doc_trash(limit?, offset?) — list deleted documents
- restore_document(docId) — restore document from trash

**Organization:**
- Folders: list_doc_folders, create_doc_folder, update_doc_folder, delete_doc_folder
- Tags: list_doc_tags, create_doc_tag, delete_doc_tag, add_tag_to_doc, remove_tag_from_doc
- Versions: list_doc_versions, get_doc_version(docId, versionId), restore_doc_version
- Block history: get_block_history(docId, blockId, limit?, offset?)
- Purge: purge_document(docId) — permanently delete trashed doc (requires confirmation)
- Sharing: list_doc_sharing, grant_doc_access(docId, targetUserId, role: viewer|editor|admin), revoke_doc_access

## Automations

Event-driven rules: when X happens → check condition → do Y. Activate via search_tools("automations").

create_automation({ name, trigger: { type, typeId }, active?, condition, actions: [{ type, …плоские ключи действия }] }) — действия хранятся с ПЛОСКИМИ ключами: { type: 'run_script', script: '…' }, вложенного config нет
- active: false — создать выключенной (по умолчанию включена; выключенная не встаёт в расписание и не срабатывает)
- Trigger types: on_create, on_update, on_delete, on_deadline, on_webhook, on_form_submit, schedule, manual, ai_analysis, on_metric_threshold, on_metric_silence, on_document, on_ncl_run_completed, on_ncl_requirement_created, on_ncl_evidence_stale, on_telegram_command, on_telegram_message, on_telegram_pre_checkout, on_telegram_shipping, on_telegram_payment, on_telegram_inline, on_telegram_join_request, on_telegram_business_connection, on_telegram_business_message, on_bot_chat_member, pm_deadline, on_issue_commented, on_issue_updated, on_issue_created, on_issue_status_changed, on_sprint_started, on_sprint_completed, on_file_processed, on_member_joined
  on_file_processed: { status?: 'done'|'error'|'skipped'|'confirmed' (пусто = любой терминальный) }; в действиях доступны {{file_id}}, {{file_object_id}}, {{file_status}}, {{file_error}}, {{file_name}}
  on_member_joined: событие member.joined — новый участник воркспейса (пригласительная ссылка); в действиях доступны {{memberUserId}}, {{memberEmail}}, {{memberRole}}, {{workspaceSlug}}, {{meta}}
  pm_deadline: { days: N (за сколько дней до due_date PM-задачи, default 1), hour: 0-23 (час UTC ежедневного скана, default 7) }; в действиях доступны {{pm_title}}, {{pm_number}}, {{pm_due_date}}, {{pm_assignee_email}} (send_notification адресуйте username: '{{pm_assignee_email}}')
  on_issue_commented / on_issue_updated: событие PM-задачи (комментарий / правка полей), pm-переменные те же
- Actions: send_notification, send_notification_to_group, update_field, create_object, delete_object, fire_webhook, run_ai_agent, run_script, run_server_function, run_video_job, send_telegram, send_telegram_media, create_document, run_connector, send_email, update_related_records, set_requisite, update_related, http_request, if_else, switch, transform, wait_delay, request_approval, delegate_to_agent, invoke_agent, send_invoice, telegram_forward, answer_inline_query, telegram_ban, telegram_unban, telegram_restrict, telegram_promote, telegram_approve_join, telegram_decline_join, telegram_pin, telegram_unpin, telegram_get_chat, telegram_post_story, answer_shipping, telegram_business_reply, create_issue, update_issue, link_issue
  create_issue: { title, description?, issue_type?, priority?, assignee_id?, parent_id?, board_id?, sprint_id?, due_date?, estimate?, labels?, assigneeRole?, assigneeStrategy? } — создаёт PM-задачу; результат: {{_created_issue_id}}, {{_created_issue_number}}. assigneeRole — имя EAV-таблицы-роли воркспейса (строки = участники, у каждого логин в колонке «Логин»/«Username»/«Email», колонка ищется по имени или алиасу); assigneeStrategy: least_busy (умолчание) | first; assignee_id и assigneeRole взаимно исключают друг друга — конфликт отвергается при сохранении. Роль без резолвимых участников → задача без исполнителя + уведомление роли (или триггера), прогон не падает.
  link_issue: { issue_id?, issue_number?, target_type?, target_id? } — привязывает задачу к цели через data-links (issue_id или issue_number; без них берётся {{_created_issue_id}} предыдущего create_issue); 409 (связь уже стоит) считается успехом.
  update_issue: { id, title?, description?, issue_type?, status?, priority?, assignee_id?, sprint_id?, parent_id?, estimate?, due_date?, labels? } — правит PM-задачу; id можно взять из {{pm_issue_id}}
  update_related_records: { childTypeId, matchRefReqId, targetTypeId, targetMatchReqId, targetFieldReqId, sourceFieldReqId, operation: 'add'|'subtract'|'set' } — declarative cross-table update (e.g. inventory deduction: order items → match product ref → subtract from stock)
  run_server_function: { repo, fn, args?, resultVar?, idempotencyKey?, idempotencyMinutes? } — call a codespace server function (api/<fn>.js in a workspace git repo) from an automation; this is how repo code gets put on a schedule (trigger.type: 'schedule'), which previously was impossible since server functions were reachable only over HTTP from the portal. Same sandbox, capabilities and limits as the portal path (codespace/server-fn-executor.js); capabilities are declared by a "// capabilities:" comment inside the function file. Replay protection is ON by default: repo+fn+args+record runs once per idempotencyMinutes (default 1) — keep it BELOW the schedule interval or runs are silently skipped; 0 disables it. A failed call releases its claim so the next run retries. Sets {{_server_fn_error}} / {{_server_fn_skipped}}.
  run_video_job: { scenario, resultVar? } — queue a video-engine render job (scenario = steps[] + narration, the pipeline tts→record→assemble lives in the video-engine module). Does NOT wait for the render: jobId lands in {{_video_job_id}} and {{resultVar}}; status/result via /video-engine/jobs/:id. Sets {{_video_job_error}} on failure.
  send_telegram_media: { kind: voice|video|document, botId?, chatId, text? (voice: TTS via Piper + ffmpeg→OGG, ffmpeg failure falls back to WAV document), videoJobId? (video-engine job id), fileUrl?, caption?, resultVar? } — send a voice note / video / file to a Telegram chat. chatId/text/caption accept {{variables}}. Sets {{_tg_media_message_id}} / {{_tg_media_error}}.
  create_document: { title, markdown, resultVar? } — create a workspace document from markdown (a meeting protocol lands on the portal as a document). Owner: ctx.user id or the automation's created_by. Sets {{_document_id}} / {{_document_error}}.
  send_notification_to_group: { typeId, usernameReqId, title, body, filter?: { reqId, val } } — notifies all members of a table whose usernameReqId field is a valid Integram username; optional filter restricts to members where reqId==val (e.g. role filter)
- list_automations, get_automation (single), update_automation, delete_automation, trigger_automation (manual run), get_automation_runs (execution log)

## Permissions (admin only)

Role-based access control. Activate via search_tools("permissions").

- list_members — all workspace users with roles. Returns { items:[{userId,email,name,username,role,roleId,roleName,lastSeenAt}], total }; lastSeenAt is the member's last visit to this workspace (null if never). It is throttled to 5-minute granularity, so treat it as "last seen within ~5 min", not an exact timestamp
- list_roles — all roles and their access levels per table
- get_user_permissions(username or userId) — what a specific user can access
- set_grant(roleId or username, targetTypeId, level) — level: NONE/READ/WRITE/ADMIN. targetTypeId=0 = all tables.
  Optional: canExport (allow CSV export), canDelete (allow record deletion)
- remove_grant — revoke access

## Graph (PostgreSQL)

Knowledge graph of relationships between records stored in PostgreSQL. Activate via search_tools("graph").

- get_related(objId, relType, depth) — find connected records up to depth 1-3
- get_graph_node(objId) — get a single graph node: type, name, edges
- get_graph_neighborhood(objId, direction, limit) — get neighbors (1-hop): edges and connected nodes
- list_graph_nodes(typeId, withEdges, limit, skip) — list graph nodes by table type
- get_shortest_path(fromObjId, toObjId, maxHops) — shortest path between two objects
- graph_query(cypher) — read-only SQL query against graph_objects/graph_edges tables. Only SELECT/WITH. Use $1 for workspace db.
- graph_health() — check graph subsystem health: node count, edge count, connection status
- list_memory_agents() — list agents that store data in graph memory
- browse_graph_memory(agentId) — browse an agent's memory graph: nodes, edges, keys

## Lookups

Dropdown/reference value discovery. Activate via search_tools("lookups").
- get_lookup(typeId, search?, limit?) — get all values from a lookup table (dropdown source). Returns records with id and display name.
- get_ref_options(refId, search?, limit?) — get valid options for a specific reference column by reqId. Use before creating/updating objects to discover allowed values for ref fields.

## Webhooks

HTTP callbacks on events. Activate via search_tools("webhooks").
create_webhook(typeId, events: ["create","update","delete"], url, secret)
- get_webhook_deliveries(webhookId, limit) — delivery history (status, response code, errors)
- retry_webhook_delivery(deliveryId) — retry a failed delivery

## Forms

Public data collection forms linked to a table. Activate via search_tools("forms").
create_form(typeId, config, expiresAt) — generates a public URL for external users to submit records.

## Bulk operations

Activate via search_tools("bulk").
- bulk_create(typeId, rows, parentId?) — create many records at once
- bulk_update(updates: [{ objId, fields }]) — update many records
- bulk_delete(objIds) — delete many records (requires confirmation)
- autofill_batch(typeId, reqId, objectIds) — run AI autofill on multiple rows

## Import / Export

Activate via search_tools("файл import export download").
- import_data(typeId, csv, mapping) — import CSV string into table. Auto-maps columns by header names. mapping override: { columnIndex: "colId" | "__val__" | "__skip__" }
- export_data(typeId, limit, filters) — export table to CSV format
- download_file(fileName, subdir?) — download a file from workspace storage. Returns base64 content (max 10 MB).

## Dashboards

Visual dashboards with widgets. Activate via search_tools("dashboard widgets").
- list_dashboards, get_dashboard(id), create_dashboard(title, widgets, layouts?), update_dashboard, delete_dashboard

## Workspace invitations

Activate via search_tools("workspace").
- list_workspace_invitations — pending invitations (email, role, status)
- cancel_workspace_invitation(invitationId) — cancel an invitation (requires confirmation)

## Sharing

Public links for views and records. Activate via search_tools("workspace share record view link").
- share_view(viewId, typeId, expiresInDays, password) → returns share token/URL
- share_record(objId, typeId, expiresInDays) → returns share token/URL
- revoke_view_share, revoke_record_share — disable public links

## Connectors

External data integrations. Activate via search_tools("workspace connectors"); narrow it: search_tools("workspace api docs fetch") for the AI setup workflow, search_tools("workspace connector test draft schema") for testing and schema generation, search_tools("workspace connectors cdek reconcile") for CDEK reconciliation, search_tools("delete connector") to remove one.
- list_connectors, get_connector, create_connector, update_connector, delete_connector, run_connector, reconcile_cdek
- list_connector_presets — available presets (1C, SAP, SCADA, REST templates)
- AI-assisted connector setup workflow:
  1. fetch_api_docs(url) — load API docs (OpenAPI/Swagger/HTML)
  2. generate_connector_config(apiStructure, description) — LLM generates connector config
  3. test_connector_draft(config, params) — test real HTTP request (requires confirmation)
  4. generate_connector_schema(config, sampleResponse) — generate table schema from response (requires confirmation)
  5. create_connector(...) — save the connector

## Comments & reactions

Activate via search_tools("comments").
- list_comments(objId), create_comment(objId, body, parentCommentId?), update_comment, delete_comment
- add_reaction(commentId, emoji), remove_reaction

## History & rollback

Activate via search_tools("history"); backlinks live in the objects group: search_tools("history objects backlinks").
- get_object_history(objId) — full change log for a record
- rollback_object(objId, auditId) — restore record to state before a specific audit entry (requires confirmation)
- get_object_backlinks(objectId, limit, offset) — find all records that reference this object via ref columns or mentions

## Audit log (admin)

query_audit(type?, actor?, dateFrom?, dateTo?, action?, objectId?, typeId?, reportId?, limit?, offset?) — unified audit log across objects, schema, and reports. type: all|objects|schema|reports (default all). actor filters by username; dateFrom/dateTo are ISO timestamps. objectId narrows type=objects, typeId narrows type=schema, reportId narrows type=reports.

## Notifications

- list_notifications, mark_read(notifId), send_notification(targetUsername, title, body), delete_notification(notifId)
- get_notification_count() — number of unread notifications for current user
- get_unread_across_workspaces() — unread counts across all user's workspaces
- notification_action(notifId, actionKey) — execute action on a notification (e.g. approve/reject a suspended automation). Requires confirmation.
- On startup the server may append an unread-notifications summary to the first tool response — surface it to the user once, then drop it.

## Workspace admin

Read-only workspace metadata available without search_tools activation.
- get_workspace() — current workspace: name, slug, plan, settings (admin only)
- get_template(templateId) — template details: slug, name, description, schema

## Trash

- list_trash(typeId) — see deleted records for a specific table
- restore_from_trash(objectId) — restore a deleted record

## Memory (agent long-term memory)

Activate via search_tools("memory").
- remember(key, value, tags) — save a fact for future conversations
- recall(question) — retrieve relevant memories
- forget(key) — delete a memory
- share_insight(key, value) — share with other agents in shared namespace
- find_procedure(query) — find step-by-step recipes from memory
- list_contradictions / resolve_contradiction — manage conflicting facts

## Portal (admin)

Client-facing portal management. Activate via search_tools("portal"); for @kit blocks use search_tools("portal kit components"), for Telegram chat admin search_tools("portal telegram member join invite") and search_tools("portal telegram pin"), for stories and the business API search_tools("portal telegram story business").

**Configuration:**
- get_portal_config() — current portal config (branding, pages, modules, auth, chat, SEO)
- portal_preview() — get preview URL
- portal_publish(active) — publish (true) or unpublish (false). **Requires confirmation.**

**Data (admin read access, no client filter):**
- get_portal_catalog(category, limit, offset) — products: price, photo, category, stock status
- get_portal_carts(limit, offset) — active client carts: item count, total
- get_portal_orders(status, limit, offset) — orders with status filter
- get_portal_tickets(status, limit, offset) — support tickets with status filter
- get_portal_kb_articles(category, limit, offset) — KB articles: category, date, excerpt
- get_portal_metrics() — order counts by status + total revenue
- get_portal_documents(limit, offset) — client documents

**Clients:**
- get_portal_profile(email, phone, customerId) — find customer by email/phone/ID
- get_portal_client_role(customerId) — role, grants, allowed pages

**Custom Code:**
- Before writing data reading or the markup of a portal section, call kit_list_components — the @kit library already has reading with a completeness proof, EAV value recovery and the three absence states. Don't reinvent them.
- kit_list_components(version?, kind?, search?) — catalog of @kit building blocks: name, kind, one-line summary, module. Generated from the library sources at build time, so it cannot drift from the code. An empty list means an empty filter; a missing catalog comes back as a refusal (KIT_NOT_DEPLOYED / KIT_VERSION_NOT_FOUND / KIT_CATALOG_MISSING / KIT_CATALOG_BROKEN). KIT_NOT_DEPLOYED means the server has no KIT_ASSETS_DIR root or no catalog versions — kit.js itself may still be served by nginx; the fix is deploying the manifest, not moving artifacts.
- kit_get_component(name, version?) — one entry in detail: module, kind, summary, props, slots and uiKeys for components. Unknown name → refusal listing similar names.
- Styling a @kit widget: never invent class names or token names. Node classes go in through the \`ui\` prop — a map of node key to your classes, e.g. \`<DataTable :ui="{ row: 'my-row' }" />\`; the keys are \`uiKeys\` from kit_get_component, your classes are APPENDED to the widget's own, and a key outside that list does not exist (the widget refuses it and warns in the console). Token names come from kit_get_tokens. A widget with no uiKeys field takes no \`ui\` prop at all — either it is headless, or the deployed version predates the prop.
- kit_get_tokens(version?, kind?, component?) — the styling contract: every CSS variable the @kit widgets read (colour, spacing, radius, font, motion) plus the stable class names of each widget. Call it BEFORE writing any style for a @kit widget. A name that is not in this dictionary does not exist: it resolves to nothing, and the section comes out structurally correct, with correct ARIA, and completely unstyled — behavioural tests will not catch it, only looking at the rendered page will. Never invent a token name, never guess a prefix. Each token ships a ready \`usage\` string, e.g. \`var(--kit-color-text, var(--color-text, #1f2328))\` — write it whole, fallback included, because the middle link is the portal shell's own token and that is what makes the widget inherit the portal theme. Refusals: KIT_TOKENS_MISSING (versions up to 0.4.0 carry no dictionary), KIT_NO_STYLING (headless widget, nothing to style).
- The \`classes\` field of that answer is a contract too: those class names are safe to hook your own styles and animations onto. Everything else inside a widget is behind scoped styles and may change.
- kit_list_versions() — which versions of @kit are deployed, plus \`latest\`. Ordering is numeric, so 0.1.10 is newer than 0.1.2.
- The version a portal uses is set by the \`kit\` field in the custom_code module config, not in component code. Omit \`version\` and the catalog answers for the latest deployed one.
- Reading rule: never build a portal API URL by hand. \`readAll(source, {db})\` takes \`type:id\` — the registry knows the path, the page ceiling and how that route proves the end of data. Seven incompatible pagination contracts exist across portal routes; the library hides all of them behind one answer \`{items, total, complete, reason}\`.
- \`total\` may be \`null\` — most routes never state a grand total. Print "N of M" only when \`total\` is a number, and raise the alarm on \`complete === false\`, not on a non-empty \`reason\`: reason is also filled on healthy reads.
- \`doc\` and \`record\` are single entities, not lists — read them with \`fetchOne\`, and note \`record\` is keyed by slug, not by a number.
- Widgets take ready data, not ids: \`DataTable\` gets \`rows\`, and \`Source\` (or \`fetchOne\`) does the reading. \`AiPanel\` is the exception — it owns its own SSE stream against /agent/run.
- commit_portal_component(repo, file, code, message?, branch?) — commit Vue SFC to codespace repo for custom_code module. Repo is auto-created if it doesn't exist.

**Telegram Bots:**
- list_telegram_bots() — list all Telegram bots for the workspace
- create_telegram_bot(name, username, token, config?) — create bot + auto-register webhook. **Requires confirmation.**
- update_telegram_bot(id, ...) — update bot (name, username, token, enabled, config). Token change re-registers webhook. **Requires confirmation.**
- delete_telegram_bot(id) — permanently delete bot. **Requires HITL confirmation.**
- sync_telegram_bot(id) — sync config → Telegram API (commands menu, description, short description, menu button). **Requires confirmation.**
- get_telegram_bot_status(id) — get bot info (getMe) + webhook status (getWebhookInfo). Read-only.
- test_telegram_bot(id, chatId, text) — send test message from bot to a chat. **Requires confirmation.**

**Telegram Messaging:**
- telegram_forward_message(botId, fromChatId, toChatId, messageId, copy?) — forward or copy a message. copy=true removes "Forwarded from". **Requires confirmation.**

**Telegram Payments:**
- telegram_send_invoice(botId, chatId, title, description, payload?, currency?, prices?, providerToken?, photoUrl?) — send payment invoice. currency "XTR" for Telegram Stars. **Requires confirmation.**
- telegram_create_invoice_link(botId, title, description, payload?, currency?, prices?, providerToken?) — create payment URL (no chat needed). Returns { url }.

**Telegram Chat Admin:**
- telegram_ban_member(botId, chatId, userId, untilDate?, revokeMessages?) — ban user. **Requires confirmation.**
- telegram_unban_member(botId, chatId, userId) — unban user. **Requires confirmation.**
- telegram_restrict_member(botId, chatId, userId, permissions?, untilDate?) — restrict user permissions. **Requires confirmation.**
- telegram_promote_member(botId, chatId, userId, canManageChat?, canDeleteMessages?, ...) — promote/demote to admin. **Requires confirmation.**
- telegram_approve_join(botId, chatId, userId) — approve pending join request. **Requires confirmation.**
- telegram_decline_join(botId, chatId, userId) — decline pending join request. **Requires confirmation.**
- telegram_pin_message(botId, chatId, messageId, disableNotification?) — pin a message. **Requires confirmation.**
- telegram_unpin_message(botId, chatId, messageId?) — unpin one or all messages. **Requires confirmation.**
- telegram_get_chat(botId, chatId) — get chat info (title, type, members). Read-only.
- telegram_get_chat_member_count(botId, chatId) — get member count. Read-only.
- telegram_create_invite_link(botId, chatId, name?, expireDate?, memberLimit?, createsJoinRequest?) — create invite link.

**Telegram Stories:**
- telegram_post_story(botId, chatId, content, caption?, activePeriod?) — publish story. content: {type:"photo"|"video", photo/video: "URL"}. **Requires confirmation.**
- telegram_edit_story(botId, chatId, storyId, content?, caption?) — edit story. **Requires confirmation.**
- telegram_delete_story(botId, chatId, storyId) — delete story. **Requires confirmation.**

**Telegram Business API:**
- telegram_get_business_connection(botId, businessConnectionId) — get business connection info. Read-only.
- telegram_set_business_bio(botId, businessConnectionId, bio) — set bio (0-140 chars). **Requires confirmation.**
- telegram_set_business_name(botId, businessConnectionId, firstName, lastName?) — set account name. **Requires confirmation.**

Bot config schema: { description?: "...", shortDescription?: "...", welcomeMessage?: "...", menuButton?: {type: "commands"|"web_app"|"default"}, employeeTable?: {typeId, chatIdReqId, roleReqId, emailReqId?} }.
Bot reactions (commands + keywords) are stored as **automations** with trigger.botId — use create_automation with:
- Command: trigger: { type: "on_telegram_command", command: "status", botId: N }
- Keyword: trigger: { type: "on_telegram_message", pattern: "привет,hello", matchMode: "contains", botId: N }
- Intake (every message, incl. media): trigger: { type: "on_telegram_message", botId: N } — no pattern. Optional messageTypes: ["voice","document"]. Runs alongside keyword rules; template vars _message, _message_type, _from_user_id, _message_id, _date, _file_id, _file_name
- Payment: trigger: { type: "on_telegram_payment", botId: N } — fires on successful payment
- Pre-checkout: trigger: { type: "on_telegram_pre_checkout", botId: N } — validate before charging
- Shipping: trigger: { type: "on_telegram_shipping", botId: N } — provide shipping options
- Inline query: trigger: { type: "on_telegram_inline", botId: N } — respond to @bot queries
- Join request: trigger: { type: "on_telegram_join_request", botId: N, chatId? } — auto-approve/decline
- Business connection: trigger: { type: "on_telegram_business_connection", botId: N }
- Business message: trigger: { type: "on_telegram_business_message", botId: N }
Actions use send_telegram with chatId: "{{_tgChatId}}" to reply to sender.
Template vars: {{_tgCommand}}, {{_tgArgs}}, {{_tgChatId}}, {{_tgFromUsername}}, {{_tgFromFirstName}}, {{_tgMessage}}.
Payment vars: {{_tgPaymentCurrency}}, {{_tgPaymentAmount}}, {{_tgPaymentPayload}}, {{_tgPaymentChargeId}}.
Inline vars: {{_tgInlineQuery}}, {{_tgInlineQueryId}}, {{_tgInlineOffset}}.
Join vars: {{_tgJoinUserId}}, {{_tgJoinUsername}}, {{_tgJoinFirstName}}, {{_tgJoinBio}}.
Business vars: {{_tgBusinessConnectionId}}, {{_tgBusinessUserId}}, {{_tgBusinessChatId}}, {{_tgBusinessCanReply}}.
Filter automations by bot: list_automations with filter by trigger.botId (GET /automations?botId=N).

**Multi-screen keyboards (screens):** send_telegram supports hierarchical navigation via \`screens\`:
\`\`\`
{ screens: {
  main: { text: "Menu", buttons: [{ text: "Orders", go: "orders" }] },
  orders: {
    text: "Orders (page {{_page}})",
    listSource: { queryMode: "table", typeId: 311, pageSize: 6, filterReqId: 378 },
    listButton: { text: "Order #{{name}}", go: "detail" },
    buttons: [
      { text: "New", go: "orders", goFilter: "391" },
      { text: "All", go: "orders" },
      { text: "Back", go: "_back" }
    ]
  },
  detail: {
    text: "Order #{{val}}\\nStatus: {{req_378}}\\nSum: {{req_340}}",
    buttons: [{ text: "Back", go: "_back" }]
  }
}}
\`\`\`
- go: "screenId" — navigate forward; go: "_back" — linear back (preserves page+filter); goBackTo: "screenId" — named back (jumps to specific screen, clears stack above)
- goFilter: "value" — apply filter to listSource (e.g., status ID)
- listSource: dynamic paginated list. queryMode: "table" (root records) | "children". pageSize (default 8). filterReqId — EAV field for goFilter.
- listButton.go — detail screen on item click. Detail screen gets {{id}}, {{val}}, {{req_NNN}} from the object's EAV data.
- {{_breadcrumb}} — breadcrumb trail built from nav stack: «Меню > Заказы > №6278886»
- Navigation stack in Redis (1h TTL) stores {automationId, screenId, page, filterValue}. _back restores full context.
- botId (preferred over botToken) — resolves token from _v2_tg_bots table.

Portal data comes from workspace EAV tables. Portal config maps page types to EAV typeId/reqId references.

## Codespace (git repositories)

Git repository hosting per workspace. Activate via search_tools("codespace").

**Repositories:**
- list_repos() — list all git repos in workspace
- get_repo(slug) — repo info (branches, size, last commit)

**Branches:**
- list_branches(slug) — list branches
- create_branch(slug, name, fromRef?) — create branch from ref/HEAD
- delete_branch(slug, name) — delete branch (cannot delete default branch). **TIER_HIGH**

**Commits & files:**
- list_commits(slug, ref?, limit?, offset?) — list commits on a branch
- get_commit_diff(slug, sha) — unified diff for a single commit (works for initial commit)
- search_code(slug, query, ref?, path?, isRegex?, caseSensitive?, limit?) — git grep across repo contents. Search FIRST before reading whole files. Returns { hits: [{ path, line, text }], total, truncated }
- get_file_tree(slug, ref?, path?) — list files/dirs in a repo. Returns { items: [{ name, type, size, path }], ref, path }
- read_blob(slug, path, ref?, offset?, limit?) — прочитать файл. Возвращает baseCommit — состояние ветки на момент чтения. Если baseCommit пришёл null, файл прочитан не целиком: перечитайте без offset/limit, прежде чем писать.
- patch_file(slug, branch, filePath, oldStr, newStr, message?, baseCommit?) — ПРЕДПОЧТИТЕЛЬНЫЙ способ править существующий файл. Заменяет уникальный кусок текста, файл целиком слать не нужно. oldStr должен встречаться ровно один раз.
- commit_file(slug, branch, filePath, content, message?, baseCommit?) — записать файл целиком. Для новых и коротких файлов; для правки существующих используйте patch_file.
- commit_multi_files(slug, branch, files, message, baseCommit?) — несколько файлов одним коммитом.
- delete_repo_file(slug, branch, filePath, message?, baseCommit?) — удалить файл (git rm + commit). **TIER_HIGH**

Запись ведёт себя как git: коммит создаётся на указанном baseCommit, ветка двигается только если не ушла вперёд, иначе выполняется слияние. Всегда передавайте baseCommit при правке существующего — иначе рискуете затереть чужую работу.

Разрешение конфликта. Ответ MERGE_CONFLICT содержит всё нужное, перечитывать файл не надо:
- details.conflicts — список конфликтующих файлов;
- details.blocks — их содержимое с конфликтными блоками. В блоке три части: ваша версия, исходная (между строками ||||||| и =======), версия ветки. Сравнивайте с исходной — она показывает, что именно меняла каждая сторона;
- details.baseCommit — состояние, на которое надо писать разрешение;
- details.retryable=false — повторять ту же запись бессмысленно, ответ будет тот же.

Порядок разрешения — выполняйте именно так, не сокращая:
1. Для каждого конфликтного блока выпишите ДВА изменения относительно исходной части: что сделала ваша сторона и что сделала сторона ветки.
2. Сформулируйте намерение каждой стороны. Удаление строки — тоже намерение: если исходная часть содержит строку, которой нет в одной из версий, эту строку намеренно удалили, и в итог её возвращать нельзя.
3. Соедините оба намерения. Механическое склеивание обеих половин — типичная ошибка: так в итог попадает то, что одна из сторон осознанно убрала.
4. Соберите итоговый текст без маркеров конфликта и запишите через commit_file с baseCommit из details.

При WRITE_CONTENTION (retryable=true) — наоборот, ничего разбирать не надо, достаточно повторить запись.

**Pull Requests:**
- list_prs(slug, status?, limit?, offset?) — list PRs (status: open|closed|merged|draft)
- get_pr(slug, number) — PR details
- create_pr(slug, title, sourceBranch, targetBranch, description?, mergeStrategy?) — create PR
- update_pr(slug, number, title?, description?, status?, mergeStrategy?) — update PR; pass status="open" to reopen
- merge_pr(slug, number, strategy?) — merge PR into target branch. **TIER_HIGH**
- list_pr_comments(slug, number) — list PR comments
- add_pr_comment(slug, number, body) — add comment to PR

**GitHub Sync:**
- get_github_sync(slug) — get GitHub Sync config (remoteUrl, direction, lastSync, lastError)
- configure_github_sync(slug, remoteUrl, token, direction, autoSync?) — set up sync; direction: push_only | pull_only | both. **TIER_HIGH**
- push_to_github(slug) — manually push all branches to GitHub
- pull_from_github(slug) — manually pull all branches from GitHub

## Advisor (platform expert)

Platform expert for guidance and help. docs_map and docs_search are core — active from the start. The rest: search_tools("advisor"), also reachable by "документация", "справка", "инструкция", "help", "guide".

- ask_advisor(question, topic?) — ask about schema design, best practices, troubleshooting, feature usage. Grounded in the platform docs corpus + current workspace schema. topic: schema/reports/automations/portal/documents/permissions/import/dashboards/integrations/general
- list_platform_capabilities() — full list of Integram features by category (data, columns, analytics, automations, documents, integrations, security, portal, AI, graph)
- docs_map(area?, module?, query?) — map of the platform docs corpus: what documents exist, what each is about, when it last changed. Start here.
- docs_search(query, area?, limit?) — hybrid search over doc fragments; returns citations (path#section). Empty result means "not in what was retrieved", NOT "not in the platform"
- docs_read(path, section?, offset?, maxChars?) — read a doc or one section in full; paginated via nextOffset
- docs_tool(name? | query? | group?) — card for a platform tool: purpose, params, risk tier. Read live from the tool catalog, so counts and names always match the code

Use advisor when user asks "help", "how to", "what can you do", "best practice", or needs guidance on platform features.
Never state a capability, count, or setting you did not confirm via docs_* — say "not covered in the docs" instead.

## Teamchat (internal messaging)

Internal messaging with rooms, topics, and decisions. Activate via search_tools("teamchat"); narrow it: search_tools("teamchat room member"), search_tools("teamchat room delete"), search_tools("teamchat topic read export"), search_tools("teamchat messages").

**Rooms:**
- list_rooms() — list chat rooms the user has access to
- create_room(name, isPublic?) — create a new room
- get_room(roomId) — room details
- update_room(roomId, name?) — rename a room (name is the only editable field)
- delete_room(roomId) — delete room. **Requires confirmation.**
- join_room(roomId) — join a public room

**Room members:**
- list_room_members(roomId) — list members
- add_room_member(roomId, userId) — add a member
- remove_room_member(roomId, userId) — remove a member

**Topics:**
- list_topics(search?, limit?) — list topics across ALL rooms the user is a member of; there is no per-room filter
- list_recent_topics(limit?) — recently active topics
- create_topic(roomId, title, first_message?) — create a topic in a room; first_message posts an opening message
- update_topic(topicId, name?, status?, pinned?, assigned_to?, priority?, deadline_at?) — update topic. The title is called \`name\` here, not \`title\` as in create_topic.
- delete_topic(topicId) — delete topic. **Requires confirmation.**
- summarize_topic(topicId) — AI-generated summary of topic discussion
- mark_topic_read(topicId) — mark topic as read
- export_topic_to_document(topicId) — export topic content to a document

**Messages:**
- list_messages(topicId, limit?, cursor?) — list messages in a topic
- create_message(topicId, text) — post a message
- send_teamchat_message(topicId, text, cards?) — post a message with optional code_cell cards for executable code
- update_message(msgId, text) — edit a message
- delete_message(msgId) — delete a message. **Requires confirmation.**
- move_message(msgId, targetTopicId) — move a message to another topic
- search_teamchat(query, room_id?, limit?, task_only?) — full-text search across messages; task_only narrows to task-flagged messages

**Decisions:**
- create_decision(title, description?, domain?) — create an architectural decision record
- get_decision(id) — get decision details
- update_decision(id, title?, description?, domain?, verdict?, impact?) — update a decision. There is no \`status\` field: the lifecycle field is \`verdict\` (proposed | accepted | rejected | superseded | draft). \`impact\`: critical | high | medium | low. When the caller is an agent account (username starting with \`agent:\`), changing \`verdict\` is not applied immediately — the call returns \`status: "approval_requested"\` and waits for a human.
- delete_decision(id) — delete a decision. **Requires confirmation.**
- search_similar_decisions(query, domain?, limit?) — semantic search for similar decisions
- analyze_decision_conflicts(decisionId) — find conflicts with other decisions
- list_decision_links(id) — list links to/from a decision
- create_decision_link(id, targetId, type) — link two decisions. \`id\` is the SOURCE decision (the "from" side), \`targetId\` is the destination — the link reads id → targetId. type: supersedes|depends_on|related_to|conflicts_with
- delete_decision_link(linkId) — remove a link

**Analytics:**
- get_agent_metrics(agentId?) — AI agent usage metrics
- get_wmatrix(room_id?, days?) — W-matrix (Organizational Network Analysis) for collaboration patterns

## Organizations

Multi-workspace organizations. Activate via search_tools("orgs").
Organizations are addressed by \`slug\`, never by a numeric id.

- list_orgs() — list organizations the user belongs to
- get_org(slug) — organization details
- create_org(name, slug) — create a new organization. **Requires confirmation.**
- update_org(slug, name?) — update organization. **Requires confirmation.**
- delete_org(slug) — delete organization. **Requires confirmation.**
- list_org_members(slug, page?, pageSize?) — list members of an organization, one page at a time (default 50). Compare items length with total and ask for the next page.
- list_org_team(slug) — team of the organization: everyone who inherits membership from its workspaces, with their org roles (должности).
- set_org_member_role(slug, userId, role) — assign org role (admin|editor|viewer) to a team member, or pass "none" to clear it. Only the org owner can do this; the user must be a member of at least one org workspace. **Requires confirmation.**
- add_org_member(slug, email, role?) — add member by e-mail. **Requires confirmation.**
- remove_org_member(slug, memberId) — remove member by membership id (from list_org_members). **Requires confirmation.**
- transfer_org_ownership(slug, userId) — hand ownership to another member; \`userId\` is the member's user id, not the membership id. The former owner stays an admin. **Requires confirmation.**
- leave_org(slug) — leave the organization yourself. An owner must transfer ownership first; the last admin must promote a successor first. **Requires confirmation.**
- invite_to_org(slug, email, role) — invite by e-mail (role: admin, editor or viewer; default viewer). Works for people without an account; the invitation lives 7 days. **Requires confirmation.**
- revoke_org_invitation(slug, invitationId) — revoke a pending invitation (id from list_org_invitations).
- list_org_invitations(slug) — invitations of the organization: pending, accepted and revoked.

## Timeseries

Time-series data ingestion and aggregated queries. Activate via search_tools("timeseries").

- record_timeseries(source_id, metric, value?, text_val?, ts?) — record one data point. \`value\` is numeric, \`text_val\` is its textual alternative — one of the two is required. \`ts\` is an ISO timestamp (defaults to now). There is no \`tags\` field.
- record_timeseries(points) — batch form: points is an array of { source_id, metric, value?, text_val?, ts? }. Every point needs its own source_id and metric.
- query_timeseries(source_id, metric, from?, to?, bucket?, agg?, limit?) — query aggregated data. source_id and metric are REQUIRED. from/to are ISO timestamps. agg: avg|sum|min|max|count (default avg). bucket: 1m|5m|15m|30m|1h|6h|1d|7d|30d (default 1h) — any other value is rejected.
- list_timeseries_sources() — list available data sources and their metrics

## KAG (Knowledge-Augmented Generation)

Knowledge graph search, question answering, and population. Activate via search_tools("kag").

**Read:**
- kag_search(query, limit?) — search entities in the knowledge graph by text
- kag_traverse(entityId, depth?, relType?) — traverse graph from an entity, discover related nodes
- kag_ask(question) — answer a natural language question using knowledge graph context. Auto-searches relevant entities and synthesizes an answer.
- kag_stats() — get entity/class/relation counts
- kag_browse(entityType?, source?, limit?, offset?) — browse entities with filters, returns available entity types
- kag_clusters() — degree-centrality clustering grouped by entity type
- kag_anomalies() — detect hub nodes (overly connected) and isolated entities (no relations)

**Write:**
- kag_import_entities(entities, source?, version?) — import entities into the knowledge graph (max 100 per call). Each entity: {id?, name, entityType, observations?, properties?}. Embeddings generated automatically.
- kag_import_relations(relations, source?, version?) — import typed relations (max 200 per call). Each relation: {sourceId, targetId, type, properties?}. Types: USES, REPLACES, CONFLICTS, PART_OF, DEPENDS_ON, RELATED_TO, IMPLEMENTS, COMPARED_TO.
- kag_import_ontology(classes, source?, version?) — import ontology classes (max 200 per call). Each class: {id, name, description?, parentClassId?}.
- kag_update_tags(entityId, tags) — update access tags on an entity
- kag_delete(source?) — delete KAG data by source (or ALL if no source). ⚠️ Irreversible.

## Objects (advanced operations)

Move, reorder, and duplicate records. Activate via search_tools("objects").

- move_object(objectId, parentId) — move a record to a different parent (change parentId)
- reorder_object(objectId, order, afterId?) — change record position (ord) within its parent
- duplicate_object(objectId) — create a copy of a record with all its field values

## AI (Text-to-Speech)

Text-to-speech synthesis. Activate via search_tools("ai").

- speak_text(text, voice?, speed?) — synthesize speech from text. Returns audio file URL.
- list_tts_voices() — list available TTS voices with language and gender info
- get_tts_status() — check TTS service availability

## Excel export

Create Excel files from raw data. Available via search_tools("workspace excel xlsx").

- create_excel(title?, sheets) — create an XLSX file from raw data. sheets: [{ name, headers: ["Col1","Col2"], rows: [["val1","val2"]] }]. File is saved to workspace storage. Returns download link.

## External agents

Delegate tasks to registered external agents. Activate via search_tools("agents").
- list_agents — discover available external agents and their capabilities
- delegate_to_agent(agentSlug, task, context) — send a task to an external agent and get the result

## Meta KB mode

POST /ai/agent-chat accepts optional agentSlug and topicId params:
- agentSlug: 'teamchat-agent' — bypasses orchestrator, calls teamchat-agent directly
- topicId: number — for multi-turn conversation in teamchat topic
When agentSlug is set, Q&A is saved to teamchat room 'meta-kb' instead of _v2_ai_conversations.

---

## Anti-hallucination rules
- NEVER state record counts, specific values, or data without calling a tool first.
- Any question like "how many records", "what's in the table", "show records" MUST call list_objects.
- If unsure about data — always call a tool, never guess.

## Confirmation flow
Destructive and schema operations return "REQUIRES CONFIRMATION". Ask the user to confirm, then call confirm_action(approved=true/false). Never auto-confirm without explicit user approval.

## Reporting platform issues
- report_platform_issue(toolName, title, whatHappened, errorCode?, errorMessage?, category?, severity?, mcpVersion?) — отправить отчёт о проблеме платформы мейнтейнеру. ЗОВИ ЕГО: (1) после необъяснимого отказа инструмента — отказ не по правам/данным, а похожий на поломку (500, INTERNAL, противоречивый ответ); (2) когда несколько попыток подряд не приводят к цели и причина непонятна; (3) когда сам понял, что сделал не то, чего хотел пользователь, и это следствие ограничения платформы, а не твоей ошибки; (4) когда пользователь просит сообщить о проблеме. НЕ зови при обычных отказах прав (FORBIDDEN, NO_READ_ACCESS) — это законные ответы, не баги. Категория: bug — платформа сломалась; missing_capability — нужной возможности нет; docs — документация неясна или неверна; ux — работает, но против всякого здравого смысла. Перед вызовом составь черновик из контекста (что было целью, что делал, сколько попыток, что ответил сервер) и покажи пользователю. Секреты в поля не писать — сервер дополнительно санитизирует. Ответ содержит номер issue — назови его пользователю.
`;

const server = new Server(
  { name: 'integram', version: PKG.version },
  { capabilities: { tools: { listChanged: true }, elicitation: {} }, instructions: INSTRUCTIONS },
);

// ─── Built-in tool definitions (always present) ─────────────────────────────

const LIST_WORKSPACES_DEF = {
  name: 'list_workspaces',
  description: 'Use to see all available workspaces and which one is currently active. Call this FIRST before any other operation. Response includes server URL so you know which environment (local/prod) you are connected to. Returns: { items:[{id,slug,name}], total }.',
  inputSchema: { type: 'object', properties: {} },
  annotations: { readOnlyHint: true },
};

const SWITCH_WORKSPACE_DEF = {
  name: 'switch_workspace',
  description: 'Use to select a workspace by slug or name (fuzzy match). Reloads all available tools for the new workspace. Call list_workspaces first to see available options. Returns: { message }.',
  inputSchema: {
    type: 'object',
    properties: {
      slug: { type: 'string', description: 'Workspace slug or part of workspace name to match' },
    },
    required: ['slug'],
  },
};

const CREATE_WORKSPACE_DEF = {
  name: 'create_workspace',
  description: 'Create a new workspace. Requires name and slug. Slug must be lowercase, 3-64 chars, start with a letter, only a-z 0-9 _ -. Optionally apply a template. After creation, automatically switches to the new workspace. Returns: { id, type:"workspace", slug, message }.',
  inputSchema: {
    type: 'object',
    properties: {
      name: { type: 'string', description: 'Display name for the workspace (1-255 chars)' },
      slug: { type: 'string', description: 'URL slug: lowercase, 3-64 chars, a-z start, only a-z0-9_- (e.g. "my-project")' },
      template: { type: 'string', description: 'DEPRECATED: use templateId instead. Optional template db_name string.' },
      templateId: { type: 'number', description: 'Optional template ID (from list_templates) to create workspace with predefined schema structure' },
      blocks: { type: 'array', items: { type: 'string' }, description: 'Optional block keys (from template manifest.blocks) to carry over. Omit = carry the whole template; empty array = skeleton only' },
    },
    required: ['name', 'slug'],
  },
};

const SEARCH_TOOLS_DEF = {
  name: 'search_tools',
  description: 'Use to discover and activate additional tools by keyword. Core tools (CRUD, search) are loaded by default. Use this for: schema changes ("create table", "add column"), reports, permissions, documents, automations, webhooks, forms, import/export. Activated tools appear in your tool list immediately. Returns: { items:[{name,description}], total }.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Capability you need — e.g. "create table", "manage permissions", "work with documents", "reports"' },
    },
    required: ['query'],
  },
  annotations: { readOnlyHint: true },
};

const CONFIRM_ACTION_DEF = {
  name: 'confirm_action',
  description: 'Use to confirm or reject a pending action after "REQUIRES CONFIRMATION" response. ALWAYS ask the user first before calling this. Never auto-confirm without explicit user approval. Returns: depends on confirmed action.',
  inputSchema: {
    type: 'object',
    properties: {
      approved: { type: 'boolean', description: 'true = user confirmed, false = user rejected' },
      confirmId: { type: 'string', description: 'id of the pending action (printed in the REQUIRES CONFIRMATION response). Required when several actions are pending.' },
    },
    required: ['approved'],
  },
};

const DELETE_WORKSPACE_DEF = {
  name: 'delete_workspace',
  description: 'Permanently delete a workspace and ALL its data (tables, records, documents, files, etc.). This action is irreversible. Requires the workspace slug. Returns: { message }.',
  inputSchema: {
    type: 'object',
    properties: {
      slug: { type: 'string', description: 'Slug of the workspace to delete' },
    },
    required: ['slug'],
  },
  annotations: { destructiveHint: true },
};

const CLONE_WORKSPACE_DEF = {
  name: 'clone_workspace',
  description: 'Clone an existing workspace into a new one. Copies schema (tables, columns, views) and optionally documents and members. After cloning, automatically switches to the new workspace. Returns: { id, type:"workspace", slug, message }.',
  inputSchema: {
    type: 'object',
    properties: {
      sourceSlug: { type: 'string', description: 'Slug of the workspace to clone from' },
      name: { type: 'string', description: 'Display name for the new workspace' },
      slug: { type: 'string', description: 'URL slug for the new workspace: lowercase, 3-64 chars, a-z start, only a-z0-9_-' },
      includeDocuments: { type: 'boolean', description: 'Copy documents from the source workspace (default: false)' },
      includeMembers: { type: 'boolean', description: 'Copy member list and roles from the source workspace (default: false)' },
    },
    required: ['sourceSlug', 'name', 'slug'],
  },
};

// Tools that only read data
const READ_ONLY_TOOLS = new Set([
  'list_tables', 'list_objects', 'list_views', 'get_view', 'get_object', 'get_related', 'graph_query',
  'list_documents', 'get_object_history', 'list_comments', 'semantic_search',
  'get_table_schema', 'list_reports', 'get_report', 'describe_report',
  'list_members', 'list_roles', 'get_user_permissions', 'list_grants',
  'search_documents', 'get_document', 'get_document_blocks',
  'list_doc_versions', 'list_doc_sharing', 'list_doc_folders', 'list_doc_tags', 'preview_document',
  'get_block_history', 'get_doc_version',
  'recall', 'find_procedure', 'list_contradictions',
  'get_schema_history', 'get_schema_snapshot', 'get_report_history', 'get_columns_batch',
  'list_templates', 'list_workspace_templates',
  // new
  'get_automation', 'get_webhook_deliveries',
  'list_workspace_invitations', 'get_object_backlinks',
  'fetch_api_docs',
  'get_lookup', 'get_ref_options',
  'get_graph_node', 'get_graph_neighborhood', 'list_graph_nodes', 'get_shortest_path',
  'graph_health', 'list_memory_agents', 'browse_graph_memory',
  'download_file', 'get_file_meta', 'get_notification_count', 'get_workspace', 'get_template',
  'get_unread_across_workspaces',
  'count_objects', 'import_preview', 'get_trash_item',
  // teamchat & decisions
  'search_teamchat', 'search_similar_decisions', 'analyze_decision_conflicts', 'get_agent_metrics',
  'get_wmatrix', 'list_recent_topics', 'list_topics', 'summarize_topic',
  'list_decisions', 'get_decision_history', 'get_decision_iterations',
  // meta-kb
  'mk_welcome', 'mk_list_rules', 'mk_gift_matrix', 'mk_gift_closed',
  'mk_list_iterations', 'mk_get_debate',
  'export_type', 'list_qa_results', 'list_test_sessions', 'get_test_session',
  'get_batch_status',
  // resolution
  'get_resolution_config', 'verify_client', 'get_client_lineage',
  // reports
  'export_report',
]);

// Tools that delete or destroy data
const DESTRUCTIVE_TOOLS = new Set([
  'delete_object', 'bulk_delete', 'delete_table', 'delete_column',
  'delete_report', 'delete_report_column', 'delete_comment',
  'remove_grant', 'delete_document', 'delete_block',
  'delete_doc_folder', 'delete_doc_tag', 'remove_tag_from_doc', 'purge_doc_versions', 'purge_document',
  'revoke_doc_access', 'forget',
  'restore_doc_version', 'rollback_object', 'delete_workspace',
  // new
  'cancel_workspace_invitation', 'delete_report_join', 'delete_notification',
  'test_connector_draft', 'generate_connector_schema', 'delete_resolution_config',
  'invite_member', 'update_member_role',
  'start_normalization', 'cancel_normalization',
  'delete_topic',
  'change_object_id',
  'delete_test_session',
  'mk_delete_rule',
  'delete_agent',
  'report_bulk_update',
]);

// English descriptions for MCP — backend TOOL_DEFS are in Russian for the in-app agent.
// Add entries here when introducing new tools so MCP clients see English descriptions.
export const EN_DESCRIPTIONS = {
  // Lookups
  get_lookup: 'Get dropdown values for a lookup table by ID. Use it to learn the allowed values of ref fields. Returns an array of records with id and display name.',
  get_ref_options: 'Get available options for a reference column by reqId. Use before creating/updating objects to discover valid values for ref fields.',
  // Graph
  get_graph_node: 'Get a graph node by object ID. Returns type, name, and edges.',
  get_graph_neighborhood: 'Get neighbors of a graph node (1-hop). Returns edges and connected nodes.',
  list_graph_nodes: 'List graph nodes by table type ID. Optionally includes edges.',
  get_shortest_path: 'Find the shortest path between two objects in the graph.',
  graph_health: 'Check graph subsystem health: node count, edge count, status.',
  list_memory_agents: 'List agents that store data in graph memory.',
  browse_graph_memory: 'Browse an agent memory graph — nodes, edges, keys. Optional agentId filter.',
  // Files
  download_file: 'Download a file from workspace storage by name. Returns base64 content, size, filename (max 10 MB).',
  get_file_meta: 'Get file metadata: processing status, extracted text, classification, extracted fields.',
  confirm_extracted_fields: 'Confirm extracted fields from a file and create an object from them.',
  reprocess_file: 'Re-trigger file processing (OCR, text extraction, classification).',
  mark_file_imported: 'Mark a file as imported and link it to a created object.',
  // Codespace
  get_file_tree: 'List files and directories in a codespace repository at a given path and ref (branch/commit). Returns: { items: [{ name, type, size, path }], ref, path }.',
  read_blob: 'Read file content from a codespace repository. Returns text for text files (up to 200K chars, supports offset/limit for pagination), metadata only for binary files. Returns: { content, path, ref, binary, size, truncated, baseCommit }. Pass baseCommit to patch_file/commit_file so your write merges with concurrent changes instead of overwriting them. baseCommit is null when the read was truncated or offset — re-read in full before writing.',
  search_code: 'Search repository file contents with git grep. Use this FIRST to locate where a string or function lives — do not download the whole tree. Fixed-string substring by default (case-insensitive); isRegex: true switches to extended regex. Returns: { hits: [{ path, line, text }], total, truncated }. If truncated is true, narrow with path.',
  patch_file: 'Replace one unique snippet of text in a repository file. Preferred over commit_file for editing existing files: no need to send the whole file, works at any file size, rarely conflicts. oldStr must occur exactly once — lengthen the anchor if it does not. Matching is exact, including indentation.',
  // Notifications
  get_notification_count: 'Get the number of unread notifications for the current user. Returns: { count }.',
  get_unread_across_workspaces: 'Unread notification counts across ALL workspaces the user is a member of. Returns: { total, items: [{ workspace, count }] }. Poll this instead of switching workspaces to check each one.',
  // Workspace
  get_workspace: 'Get current workspace details: name, slug, plan, settings (admin only).',
  get_template: 'Get details of a workspace template by ID (schema, description). Returns: { id, slug, name, description, icon, category, schema }.',
  list_workspace_templates: 'List available templates for creating new workspaces.',
  create_workspace_from_template: 'Create a new workspace from a template. Provide templateId, name, and slug.',
  // Decisions
  create_decision: 'Create a new team decision. Optionally creates a chat room. Returns: { decision: {id, title, domain, ...}, message: string }.',
  search_teamchat: 'Search team chat messages. Hybrid full-text + vector search — finds messages by meaning, not only by exact words. Returns: { items: [{id, topic_name, room_name, author, text, score}] }.',
  search_similar_decisions: 'Find semantically similar decisions with an AI recommendation. Returns: { similar: [{id, title, domain, verdict, team, score}], recommendation }. IMPORTANT: id is a DECISION id — use get_decision(id) to load details, NOT get_object.',
  get_agent_metrics: 'Get performance metrics for AI agents. If agentId is provided, returns metrics for that agent only; otherwise all agents. Returns { data: [{ agentId, totalMessages, messages24h, topicsInvolved, trustScore }] }.',
  analyze_decision_conflicts: 'Analyze a decision for conflicts, contradictions, and overlaps with other decisions. Returns analysis with conflict descriptions.',
  list_decisions: 'List all architectural decisions with optional search and filters.',
  get_decision_history: 'Get change history for a decision — who changed what and when.',
  get_decision_iterations: 'Get reasoning iterations for a decision — evolution of thinking.',
  get_wmatrix: 'W-matrix (ONA graph): collaboration graph between team members. Shows hubs, bridges, isolated members. Edges: reply (answers) and co-topic (co-participation). Params: room_id (optional filter), days (1-365, default 30).',
  list_recent_topics: 'List recent active topics across all rooms the user belongs to. Filters: all, participated, unread, resolved, assigned_to_me, overdue, pinned.',
  summarize_topic: 'Generate an AI summary of a teamchat topic discussion. Extracts key conclusions, decisions made, and open questions.',
  list_topics: 'Search topics by name across all rooms the user belongs to. Returns matching topics with their IDs, names, and linked room names.',
  delete_topic: 'Permanently delete a teamchat topic and all its messages. Requires room admin rights. This action is IRREVERSIBLE.',
  // Meetings
  meetings_status: 'Meeting conveyor status for the workspace: saved config and installed meetings: * automations. Returns: {configured, config, automations:[{id,name,active}]}.',
  meetings_setup: 'Install or update the meeting conveyor (requires confirmation): creates/updates the meetings: intake and meetings: protocol automations from config. Idempotent on repeated calls (upsert by name). Column aliases must match real column names byte-for-byte; the meetings table must have all 8 meet.cols columns (including record), the messages table all 12 tg.cols (including Транскрипт). Returns: {created, updated, message}.',
  meetings_teardown: 'Deactivate the meeting conveyor automations (every meetings: * name, requires confirmation). The workspace config is kept. Returns: {deactivated, message}.',
  // Meta-KB
  mk_revoke_entity: 'Revoke all knowledge base entities derived from a specified decision. Use when a decision was found to be incorrect. Returns { revoked: number, message: string }.',
  mk_list_debates: 'List recent expert debates in the workspace. Returns { debates: Array, total: number }. Each debate has id, question, consensus, verdict, created_by, created_at.',
  mk_start_debate: 'Start an expert debate on a question. The experts are the internal agents of the workspace; all active ones participate by default — pass agents=[slug] to pick one or more for the question. Returns the consensus of the experts and debateId; the full protocol is in mk_get_debate(debateId).',
  mk_analytics: 'Get knowledge base analytics: entity/relation/class counts, orphan nodes, breakdown by source/type/status.',
  mk_research: 'Research a concept in the knowledge graph: find matching entities, graph neighbors, and knowledge gaps.',
  mk_propose_change: 'Propose a knowledge base change (add/update/delete entity). Creates a change request for human review. Returns { id, status: "pending" }.',
  mk_list_snapshots: 'List knowledge base snapshots. Shows date, label, and stats for each snapshot.',
  mk_create_snapshot: 'Create a snapshot of the current knowledge base state. Captures current state for later comparison.',
  mk_diff_snapshots: 'Compare two knowledge base snapshots. Shows added/removed entities and stat changes.',
  mk_review_change: 'Approve or reject a proposed knowledge base change.',
  mk_export_debate: 'Export a debate to Markdown format.',
  mk_list_topics: 'List topics in the meta-knowledge-base (meta-kb room).',
  mk_appropriate_decision: 'Run Socratic appropriation gate for a debate: generate consensus questions or evaluate answers. Step 1: without answers — returns questions. Step 2: with answers — evaluates and, on success, records a covenant act.',
  mk_welcome: 'Get Meta-KB welcome summary: stats, recent debates, recommendations.',
  mk_list_rules: 'List Meta-KB validation rules.',
  // Admin — export/import/QA
  export_type: 'Export a table definition (schema + data) by typeId (admin only).',
  bki_import: 'Import BKI format (tables + data from a previous export). Provide content as a JSON string (admin only).',
  list_qa_results: 'List QA test sessions and their results (admin only).',
  list_test_sessions: 'List QA test sessions with aggregate stats (total, passed, failed, skipped).',
  create_test_session: 'Create a new QA test session. Optional notes parameter.',
  get_test_session: 'Get a QA test session with all test results.',
  delete_test_session: 'Delete a QA test session.',
  upsert_test_result: 'Record a test result (passed/failed/skipped) in a QA session.',
  mk_run_rules: 'Run validation rules on specified entity IDs. Returns violations.',
  mk_gift_matrix: 'Get gift/contribution matrix of debate participants.',
  mk_gift_closed: 'Get participants with balanced contribution ratios over a period.',
  // Resolution
  get_resolution_config: 'Get entity resolution config for a table type — matching rules, merge strategy, field weights.',
  set_resolution_config: 'Create or update entity resolution config for a table type.',
  delete_resolution_config: 'Delete entity resolution config. Destructive — HITL required.',
  recompute_client: 'Recompute a client golden record from source records. Triggers re-merge.',
  verify_client: 'Verify client record — check data quality, shipping validity, duplicate risk.',
  get_client_lineage: 'Get lineage for a client — source records, merge history, field provenance.',
  mk_create_rule: 'Create a Meta-KB validation rule. Condition and action are JSON objects.',
  mk_delete_rule: 'Delete a Meta-KB validation rule by ID.',
  mk_list_iterations: 'List Meta-KB iterations with optional status filter (in_progress, proposed, accepted, rejected, ignored).',
  mk_get_debate: 'Get a full debate by ID: question, opinions, consensus, verdict.',
  // Objects — new tools
  count_objects: 'Fast count of objects in a table without loading data. Supports parentId, text search (q), and requisite filters. Returns: { count }.',
  change_object_id: 'Change an object ID to a new value (requires confirmation). Atomic operation — updates id, references (up), types (t). Returns: { oldId, newId }.',
  import_preview: 'Preview CSV data before import. Parses CSV text and returns headers + first rows for mapping. Returns: { format, headers, preview, totalRows }.',
  import_create_table: 'Import CSV data as a new table — auto-creates type, columns from headers, and records. Returns: { typeId, typeName, columnsCreated, created, ids, errors }.',
  get_trash_item: 'Get a deleted object from trash by ID — with saved requisites. Returns: { id, typeId, parentId, val, ord, reqs, deletedAt, deletedBy }.',
  // Schema batch & maintenance
  get_columns_batch: 'Get column definitions for multiple tables in one request. Pass array of typeIds.',
  rebuild_flat_views: 'Rebuild all flat views (admin). Use after migrations or schema corruption.',
  set_type_visibility: 'Show or hide a table in navigation. Set hidden=true to hide, false to show.',
  // Documents — new tools
  import_document: 'Import an external file (DOCX, HTML, MD) as a document.',
  create_from_system_template: 'Create a document from a built-in system template by templateId.',
  purge_doc_versions: 'Permanently delete document versions. HITL required. Destructive.',
  preview_document: 'Generate a preview/PDF render of a document.',
  get_block_history: 'Get version history for a specific document block. Read-only.',
  get_doc_version: 'Get a specific version snapshot of a document. Read-only.',
  purge_document: 'Permanently delete a trashed document. HITL required. Destructive and irreversible.',
  // Automations — seed & batch
  seed_system_automations: 'Restore/seed system automations — creates standard rules if missing.',
  get_batch_status: 'Get status of an automation batch run — progress, errors, completion.',
  // Agent registry
  register_agent: 'Register a new external AI agent with endpoint URL, capabilities, and authentication.',
  update_agent: 'Update an external agent configuration — endpoint, capabilities, description.',
  delete_agent: 'Delete a registered external agent. Destructive — HITL required.',
  // Specs (data invariants)
  create_spec: 'Create a data spec (declarative invariant, ADR-019) for a table. definition: { rules: [{ field, op, value?, problem? }] }. Returns: { id, typeId, name, definition, enabled }.',
  update_spec: 'Update a spec: name, definition, enabled. Pass definition in FULL — it replaces the stored one. Returns: { id, ...fields }.',
  delete_spec: 'Delete a spec by ID (requires confirmation). View the spec via list_specs first. Returns: { id, deleted: true }.',
  // Documents — new tools
  update_document_fields: 'Update document fields: parent_id, folder_id, sort_order, is_template, is_public, icon, cover_url (for the title alone use update_document_title). null resets a value where allowed. Returns the updated document.',
  restore_block_version: 'Restore block content from a history version (browse history via get_block_history). Requires confirmation. Returns the updated block.',
  list_document_variables: 'List template variables for a table type — system fields and columns that can be interpolated into document templates. Returns: { typeId, variables: [{ name, label, type }] }.',
  // Agent memory
  list_memories: 'Browse stored memories as a list: keys, values, tags, scopes. Unlike recall (question search), this is an overview of memory contents. Optional tag filter, includeShared, limit (default 50, max 200).',
  hybrid_search_memory: 'Hybrid search over agent memory (vector + BM25 + MMR) — more precise than recall for pinpoint queries. tags/scope/minScore filters apply after ranking. Returns ranked results with scores.',
  get_memory_history: 'Bitemporal change history of a memory record by key — which values were written and when. Returns a list of versions.',
  get_shared_state_log: 'Event log of shared state changes — who changed which key and when. Omit key for the full log. Admin only.',
  get_memory_audit: 'Audit log of workspace memory operations. Admin only. Optional agentId filter.',
  link_agent_memory: 'Link an agent memory record to a workspace object (RELATES_TO_OBJ edge in memory_edges). Idempotent — repeated calls with the same arguments change nothing.',
  // Import & files
  import_create_all_sheets: 'Import EVERY sheet of an XLSX workbook as a separate table (creates types and columns from headers; requires confirmation). Returns: { tables: [{ sheet, sheetIndex, typeId, typeName, columnsCreated, created, ids, errors }], totalSheets, created }.',
  list_file_meta: 'List uploaded file metadata (_v2_files): processing status, classification, object link. Optional objectId filter and pagination. Returns: { files: [...], total }.',
  // Comments
  get_comment_reactions: 'Get reactions on an object comment. Returns: { commentId, reactions: [{ emoji, count, authors }] }.',
  // Workspace templates & bots
  save_workspace_template: 'Save a workspace as a template. Requires admin/owner in the source workspace. Provide source_slug, name, slug; optional description, icon, visibility (private|org|public), include_data.',
  apply_workspace_template: 'Apply a template to an EXISTING workspace (creating a new one from a template is a separate tool). Requires admin/owner. dry_run=true shows the plan without changes. Optional blocks: array of block keys to carry (omit = whole template, [] = skeleton only). Requires confirmation.',
  copy_table_to_workspace: 'Copy a table from one workspace to another together with its relations: lookups, ref targets and child tables are pulled in automatically (transitive closure). Creates a private fragment template with deterministic slug copy-<typeId>-from-<source> and applies it with ID remapping. Re-running updates the copy (idempotent). Records travel with include_data=true. Views, reports, automations and portal are NOT carried. dry_run=true shows the apply plan, but the private fragment template is still created/updated. Requires admin on both workspaces. Requires confirmation.',
  leave_workspace: 'Leave a workspace yourself. Owners and the last admin cannot leave — the service refuses. Requires confirmation.',
  update_workspace_template: 'Update workspace template metadata: name, description, icon, visibility. Only the template owner can change it.',
  delete_workspace_template: 'Delete a workspace template by ID. Irreversible — requires confirmation.',
  update_service_bot_role: 'Change a service bot role (admin|editor|viewer). Admin/owner only; a role cannot be raised above your own.',
  revoke_service_key: 'Revoke a service bot API key. The key stops working immediately; irreversible. Requires confirmation.',
  // KAG
  kag_get_edges: 'Batch-get knowledge graph edges for a list of entities plus any missing neighbors. Use kag_traverse to walk from a single entity.',
  // Agents — suggestions & secrets
  rotate_agent_secret: 'Rotate the callback secret of a registered agent. The old secret stops accepting callbacks immediately (requires confirmation). Returns: { id, slug, callbackSecret, message }.',
  get_agent_suggestion: 'Details of a single agent-creation suggestion: pattern, rationale, status. Returns: { id, status, pattern, rationale, ... }.',
  get_agent_suggestion_telemetry: 'Telemetry for agent suggestions: counts per status, average confidence, top patterns. Admin only. Returns: { pending, applied, dismissed, ... }.',
  find_similar_suggestions: 'Search OPEN (pending) agent suggestions by substring. Returns: { suggestions: [...], total }.',
  // CDEK & DaData
  cdek_get_config: 'Get the portal CDEK integration config (staff): whether the connector is configured, sender city, bound reqIds for dimensions, phone, and recipient city. Read-only.',
  cdek_calculate_tariff: 'Calculate CDEK delivery cost for a portal order — dimensions and city come from the order requisites; optional PVZ code. Returns: { tariffs, city }.',
  cdek_list_pvz: 'List CDEK pickup points by city name. Returns matching cities; the full point list only when exactly one city matched. Returns: { cities, points }.',
  cdek_create_shipment: 'Create a CDEK waybill for a portal order (mode: "pvz" or "door"; pvzCode required for "pvz"). EXTERNAL IRREVERSIBLE ACTION: every call creates a REAL waybill — do not retry on an unclear result, check the order first. Requires confirmation.',
  cdek_get_label: 'Get the CDEK label PDF for a portal order — fetches the barcode by order UUID and waits up to ~12s for the PDF. Returns: { filename, size, base64 }.',
  dadata_suggest: 'DaData suggestions via server proxy with the platform token: address, company by INN/name, bank, full name, email. mode=findById does an exact lookup by identifier (INN). Returns [{ value, data }].',
  // Portal orders
  get_portal_order: 'Get a single portal order in full (admin): status, date, amount, tracking number, items. Unlike get_portal_orders (list), reads one record by ID with no customer filter.',
  get_portal_order_linked: 'Get portal orders linked to a given order (admin): the merge group of one customer and the group main order. Returns: { linked: [{ id, name, isMain }], mainId }.',
  add_portal_order_item: 'Add a product to a portal order (admin): creates a child item record; the price is taken from the product unless given. Returns: { id, name, qty, price, variant }.',
  collect_portal_order_items: 'Portal order assembly (admin), one tool with action: collect_all (default) — mark ALL items collected and move a "Picking" order to "Picked"; check — verify whether all items are collected (no changes); toggle — flip the "collected" flag of ONE item (needs itemId).',
  merge_portal_orders: 'Merge portal orders (admin): donor items move to the master order, donors get "Cancelled" status with a comment, empty master fields are filled from donors, the amount is recalculated. All orders must belong to one customer and not be in a terminal status. Reversible only manually. Requires confirmation.',
  // Portal client mutations (TD-012b)
  add_portal_cart_item: 'Add a product to a portal customer cart (admin, acts on behalf of the customer at their request): creates an item or increments the quantity of an existing one. Returns: { items: [{ id, objId, name, qty, price, variant }] }.',
  update_portal_cart_item: 'Change the quantity of a cart item for a portal customer (admin). Returns: { items }; when the item does not exist — { error: "NOT_FOUND" }.',
  remove_portal_cart_item: 'Remove an item from a portal customer cart (admin). Returns: { items }; when the item does not exist — { error: "NOT_FOUND" }.',
  clear_portal_cart: 'Completely clear a portal customer cart (admin): IRREVERSIBLY deletes ALL items of someone else\'s cart. Requires confirmation.',
  create_portal_ticket: 'Open a support ticket on behalf of a portal customer (admin): a ticket in the support module linked to the customer with an initial status. Returns: { id, subject }.',
  create_portal_order: 'Place a portal order on behalf of a customer (admin): creates a REAL order with money — an order record with items at server catalog prices. WITHOUT idempotencyKey a repeated call creates a DUPLICATE order — pass the key on retries. Requires confirmation.',
  // Portal
  invoke_server_function: 'Execute a codespace server function (api/<name>.js in the workspace git repo). Arbitrary code in a sandbox — requires confirmation. Optional idempotencyMinutes suppresses retries with identical args within an N-minute window — enable for functions with external side effects.',
  list_portal_config_history: 'List portal config snapshot history (admin): recent saves with dates and authors. Call BEFORE restore_portal_config.',
  restore_portal_config: 'Roll the portal config back to a history snapshot (admin). Overwrites the ENTIRE current config — call list_portal_config_history first and tell the user what will be lost. The portal cache is invalidated automatically. Requires confirmation.',
  get_portal_analytics: 'Portal visit and order stats (admin): page/product views and orders created over 1d|7d|30d (default 7d).',
  search_portal_kb: 'Semantic search in the portal knowledge base (table bound by the kb module). Returns: { configured, items: [{ id, title, score }] }; configured=false when the kb module has no bound table.',
  // Codespace — review gates & repo policy
  run_review_gate: 'Run the AI review gate on a PR diff: reviewer + opponent + council verdict. Slow (LLM calls).',
  enqueue_machine_gate: 'Enqueue the machine gate (automated checks) for a PR. Returns jobId, or { enqueued: false } when Redis is unavailable.',
  get_machine_gate: 'Get the latest machine gate result for a PR. error NOT_FOUND when there is no result yet.',
  set_repo_write_mode: 'Change repository write mode: requireBaseCommit (forbid writes without a fresh baseCommit) and the protectedBranches list. Admin only. Security policy change — expects confirmation.',
  get_tree_commits: 'Last commit per file for a batch of entries (up to 500) — a cheap way to annotate a file tree. Returns a commits map { path: { sha, subject, timestamp, authorName } }.',
  // Normalizer
  list_normalization_jobs: 'List recent workspace normalization jobs (last 100). Use get_normalization_status by jobId for details. Returns: { jobs: [{ jobId, status: { stage, progress, errors } }], total }.',
  // Decisions
  get_decision_graph: 'Graph of all workspace decisions: nodes (decisions with verdict, impact, domain) and edges (compatible/conflict/parent/supersedes) with colors and widths for visualization.',
  get_decision_kag_stats: 'How many knowledge base (KAG) entities and relations were derived from a given decision. Requires decision ID.',
  // Teamchat — new tools
  list_call_history: 'Call history of the current user — both incoming and outgoing (as initiator or participant). Optional limit (default 50, max 200).',
  list_public_rooms: 'List public teamchat rooms the user can join via join_room. Returns: { data: [{ id, name, description, roomType, visibility, isMember }] }.',
  forward_message: 'Forward a teamchat message to another topic: the text is copied with author attribution. Returns: { data: { id, targetTopicId } }.',
  send_topic_file: 'Attach an already-uploaded workspace file to a chat topic message by fileId (file card like a UI upload). Does not upload binaries — the file must exist in _v2_files. Returns the created message { data: { id, cards } }.',
  refresh_topic_document: 'Append new topic messages to an already-exported document (export_topic_to_document only creates it; this one continues it). Returns: { data: { documentId, addedBlocks } }.',
  create_reminder: 'Create a reminder in a chat topic — the user gets a notification at fireAt. The date must be in the future. Returns: { data: { id, fireAt } }.',
  list_reminders: 'List the current user pending reminders across all chat topics. Returns: { data: [{ id, topicId, topicName, note, fireAt, status }] }.',
  delete_reminder: 'Cancel your own pending reminder (reminders of others are refused — ownership is checked server-side). Returns: { data: { cancelled: true } }.',
  get_message_reactions: 'Get reactions on a teamchat message grouped by emoji. Not to be confused with object-comment reactions (get_comment_reactions). Returns: { data: [{ emoji, count, authors }] }.',
  add_message_reaction: 'Add your emoji reaction to a teamchat message. Requires membership in the topic room. Returns: { data: [{ emoji, count, authors }] }.',
  remove_message_reaction: 'Remove YOUR reaction from a teamchat message. Not to be confused with remove_reaction (object comments). Returns: { data: [{ emoji, count, authors }] }.',
  request_topic_approval: 'Ask topic room admins to approve an agent action (merge_pr — merge a PR, change_verdict — change a decision verdict, or a custom type). Creates a request and notifies admins; the decision stays with a human. Returns: { suspendedId, jobKey }.',
  list_topic_tasks: 'List chat tasks (topics with an assignee) with filters by status, priority, ANY assignee, room, and name search; sort: priority/recent/deadline. Unlike list_recent_topics (assigned_to_me only, sorted by messages). Returns: { data: { tasks: [{ id, name, status, priority, assignedTo, deadlineAt, roomName }], nextCursor } }.',
  update_room_member_role: 'Change a chat room member role: admin or member. Requires room admin rights (checked server-side); the last admin cannot be demoted. Returns: { data: { roomId, userId, role } }.',
  // Meta-KB — new tools
  mk_get_debate_by_topic: 'Get the latest saved debate of a topic (by topicId): question, opinions, consensus, verdict.',
  mk_list_changes: 'List knowledge base change requests — the review queue. Read it here first, then review via mk_review_change. status: pending (default) | approved | rejected.',
  mk_update_iteration: 'Close a Meta-KB reasoning iteration: accept, reject, or shelve it. status: accepted | rejected | ignored.',
  mk_list_debates: 'List expert debates. Without filters — recent across the workspace; topicId — all debates of a topic; decisionId — debates linked to a decision. Pass only ONE filter.',
  mk_export_debate: 'Export a debate. format=md (default) — Markdown in the markdown field; format=docx — DOCX in the base64 field (save it via create_file, the filename is already chosen).',
  // Organizations
  org_list_workspaces: 'List workspaces attached to an organization: slug, name, roles. Returns: { items, total, page, pageSize }.',
  org_attach_workspace: 'Attach an existing workspace to an organization. Requires admin/owner in the organization AND rights on the workspace (checked server-side). Requires confirmation.',
  org_detach_workspace: 'Detach a workspace from an organization. Available to the workspace owner or an organization admin/owner. Requires confirmation.',
  org_get_pm_defaults: 'Get the organization reference task types and statuses (used when creating issues in member workspaces).',
  org_set_pm_defaults: 'Set the organization reference task types and statuses (up to 16 types, up to 32 statuses; kind: open/active/done/canceled). Organization owner only — checked server-side.',
  org_suggest_assignee: 'Suggest an assignee in an organization workspace: candidates ranked by overdue work, active load, and points.',
  // PM — boards, statuses, checklists, analytics
  pm_add_checklist_item: 'Add a new item to a PM issue checklist. Returns the item with its id — use it with pm_toggle_checklist / pm_remove_checklist_item.',
  pm_remove_checklist_item: 'Remove one item from a PM issue checklist by item id (ids come from the issue checklist field).',
  pm_create_board: 'Create a PM board. By default it is seeded with a COPY of the first board statuses (or from copy_statuses_from); empty=true creates it without columns.',
  pm_update_board: 'Rename a PM board and/or change its sort order.',
  pm_delete_board: 'Delete a PM board. The last board cannot be deleted; live issues require move_to (statuses are mapped by kind). Requires confirmation.',
  pm_create_status: 'Add a status column to a PM board. kind is one of open, active, done, canceled. Max 32 statuses per board; a duplicate name on the board is a conflict.',
  pm_update_status: 'Update a PM status label, kind, or sort. The status NAME cannot be changed (issues reference it).',
  pm_delete_status: 'Delete a PM status. Refused with 409 while live issues use it; refused with 400 if its kind category would become empty. Requires confirmation.',
  pm_get_cfd: 'Cumulative flow diagram: issue counts per status over time (sibling of pm_get_velocity / pm_get_burndown). Optional days window 1-365, default 30.',
  pm_list_issues_by_target: 'List PM issues linked to an EAV target (data links). Sibling of pm_list_data_links, which lists links of ONE issue. Requires target_type (table|document|report|object) and target_id.',
  // CNM
  ncl_list_edges: 'List active edges of the requirement graph with optional filters.',
  ncl_create_proposal: 'Create a generic ModelChangeProposal (any kind: model_change, handler_mapping, artifact_structure). Nothing enters the CNM until accepted via ncl_decide_proposal. Prefer ncl_formalize for formalizing free text.',
  // Presentations
  pres_update: 'Update presentation metadata: title, is_public, status (draft|published|archived).',
  pres_list_versions: 'List saved versions (snapshots) of a presentation, newest first.',
  pres_create_version: 'Save a version snapshot of the presentation right now.',
  pres_restore_version: 'Restore slides from a saved version. The current state is snapshotted automatically before the restore.',
  pres_get_sharing: 'List per-user sharing entries of a presentation.',
  pres_set_sharing: 'Grant or update a user role on a presentation (viewer|editor|admin). Requires admin role on the presentation.',
  pres_revoke_sharing: 'Revoke a sharing entry of a presentation by its sharing id.',
  pres_export: 'Export a presentation to PPTX or PDF. Returns { filename, size, base64 } — decode base64 and save as a binary file.',
  pres_import: 'Import a PPTX file (base64, max 50 MB) as a new presentation. Returns presId and import warnings.',
  pres_preview_bindings: 'Resolve binding placeholders ({{...}}) in text against workspace data, same as the editor insert-value button. Requires editor role.',
  // DLP
  list_dlp_rules: 'List the workspace DLP (data loss prevention) rules. Admin only.',
  create_dlp_rule: 'Create a DLP rule. rule_type: keyword|regex|type_block|llm_classify; severity: block|warn|audit. Admin only.',
  update_dlp_rule: 'Update a DLP rule by id. Pass only the fields to change. Admin only. Security policy change — expects confirmation.',
  delete_dlp_rule: 'Delete a DLP rule by id. Admin only. Security policy change — expects confirmation.',
  // Reports & audit — changed semantics
  get_report: 'Run a report and get data rows. Accepts the same selection params as REST POST /reports/:id/run: order, totals, select, fieldNames, filterId. Returns: { data, total, columns }.',
  query_audit: 'Query the workspace audit log — changes to objects, schema, reports, and AI tool calls (admin only). type: objects|schema|reports|ai|all; for type=ai filter by action substring or exact toolName. Returns: { items: [...], total }.',
  export_audit_log: 'Export the workspace audit log (objects, schema, reports, ai) to JSON or CSV (admin only). Returns { data: [...], meta: { total } } for json; CSV text for csv.',
  // ── Remaining tools (translated from TOOL_DEFS) ──
  // Core
  _load_schema_guide: 'Load the data modeling guide with schema examples. ALWAYS call before plan_schema or when you need to create/modify table structure.',
  search_tools: 'Discover and activate additional tools by keyword. Use when you need a capability missing from the current set (reports, schema, permissions, documents, automations).',
  list_tables: 'List workspace tables. Returns ID, name, column count, creation date. Supports search and sorting. Returns: { items:[{id,name,columns}], total }.',
  list_objects: 'Get records from a table. THE ONLY source of record data — always call for "how many records", "show", "find". Response has fields aliased by column name plus summary (aggregation over ref columns: top values with counts). Filter with where: { "Column name": "value" } — simple substring match, e.g. { "Status": "Active" }. Use search for full-text lookup when the column alias is unknown. VIEWS: pass viewId to apply the filters of a saved view automatically (list them via list_views); viewId combines with where (extra filters applied on top). PAGINATION: if hasMore=true, request page=2,3... until all data collected. USE summary FOR THE BIG PICTURE: do not enumerate all rows when there are many — rely on summary (distribution by country, type, manufacturer). Records without a value appear as a separate { value: null, count: N, noValue: true } row — count them or "how many X" won\'t match total. For a single ref the count sum equals total; for a multi ref (:MULTI:) it is legitimately larger. If _summaryTruncated is set, only the most frequent values are shown for those columns.',
  get_object: 'Get a full object record by ID. Returns: { id, type:"object", ...fields }. Error: { error:"NOT_FOUND", message }. NOT for documents: if the ID is a document, use get_document(docId).',
  resolve_client: 'Recompute a client golden record from source rows using deterministic survivorship rules: per-field source priority + validators + lineage. Governed writeback — the only sanctioned way to write golden fields. Returns: { clientId, resolved, lineage, conflicts, goldenAddressId }.',
  list_specs: 'List specs (declarative data invariants) of a table. Returns: { items:[{id,name,definition,enabled}], total }.',
  check_record: 'Check a record against its table specs (or a specific specId). Returns: { objectId, pass, results:[{specId,name,pass,violations:[{field,op,problem}]}] }.',
  run_spec: 'Run a spec across all records of a table and return violating rows. Returns: { specId, name, checked, failed, capped, violations:[{objectId,name,violations}] }.',
  verify_client_shipping: 'Check whether a client is ready for physical shipping: valid phone, golden address, no unresolved source conflicts. Read-only. Returns: { clientId, ready, issues:[{field,problem}], conflicts }.',
  create_object: 'Create a new record in a table. For child-table records pass parentId — the parent record ID. Ref fields accept either an id (number) or the exact record name — the backend resolves name to id; ambiguous names throw an error (pass id instead). NOT for PM tasks: "create a task" — pm_create_issue. Returns: { id, type:"object", name, message }.',
  update_object: 'Update fields of an existing record. Ref fields accept an id or the exact record name (resolved by backend). Returns: { id, type:"object", message }.',
  delete_object: 'Delete a RECORD (object/row) from a table (requires confirmation). NOT for deleting tables — use delete_table for that. Returns: { message }.',
  semantic_search: 'Semantic search across the whole workspace — finds meaningfully similar objects and documents. Use to find "something about X" without an exact name. Do NOT use for structural queries or when you already know the typeId.',
  // Graph
  get_related: 'Find objects related to a given one through the knowledge graph of the workspace. Shows records connected to the object via ref columns and child tables.',
  graph_query: 'Run an arbitrary read-only SQL query against graph tables (graph_objects, graph_edges). SELECT only. Tables are automatically scoped to the current workspace — no WHERE db = $1 needed.',
  upsert_graph_node: 'Create or update a graph node. If a node with this objId exists, it is updated.',
  delete_graph_node: 'Delete a graph node together with all its edges. Irreversible.',
  upsert_graph_edge: 'Create or update a directed edge between two graph nodes.',
  delete_graph_edge: 'Delete an edge between two graph nodes. Irreversible.',
  // Documents
  list_documents: 'List workspace documents. Returns ID, title, author, created/updated dates. Returns: { items:[{id,title}], total }.',
  search_documents: 'Search documents by keywords. For meaning-based search use semantic_search.',
  get_document: 'Get document content by ID. Returns: { id, type:"document", title, blocks:[...] }. If docId is a table record ID, use get_object(objId). List blocks only — get_document_blocks(docId).',
  get_document_blocks: 'Get the list of document blocks with their IDs. For the full document content use get_document(docId).',
  update_document_title: 'Change a document title. Returns: { id, type:"document", title, message }.',
  append_block: 'Append a text block to the end of a document. format:"delta" — text is a ready Quill delta {"ops":[…]}; without it, markdown autodetect/plain text. Returns: { type:"block", docId, message }.',
  update_block: 'Update the content of a document block. format:"delta" — text is a ready Quill delta {"ops":[…]}; without it, plain text. Returns: { id, type:"block", docId, message }.',
  delete_block: 'Delete a block from a document (requires confirmation). Returns: { message }.',
  delete_document: 'Delete a document (moves to trash, requires HITL confirmation). Returns: { message }.',
  get_doc_settings: 'Get document settings (access, visibility, permissions). Returns: { settings }.',
  update_doc_settings: 'Update document settings. Returns: { settings, message }.',
  create_doc_invite: 'Create an invite granting access to a document. Returns: { invite }.',
  list_doc_invites: 'List invites for a document. Returns: { items, total }.',
  revoke_doc_invite: 'Revoke a document invite. Returns: { message }.',
  // Editor ops — server-side writes; any open tab receives changes over WS
  editor_insert_text: 'Write text to the end of document docId (server-side; an open tab updates itself over WS). position: "cursor" is treated as "end".',
  editor_str_replace: 'Find and replace a substring in document docId (first occurrence, against persisted text). Not found — structured TEXT_NOT_FOUND error.',
  editor_insert_heading: 'Write a heading (level 1-6) to the end of document docId (server-side).',
  editor_insert_callout: 'Write a callout block to the end of document docId (server-side).',
  editor_insert_table: 'Write a table to the end of document docId (server-side).',
  editor_insert_list: 'Write a bulleted or numbered list to the end of document docId (server-side).',
  editor_insert_mermaid: 'Write a Mermaid diagram to the end of document docId (server-side).',
  editor_clear_and_write: 'Clear document docId and write new content (server-side; requires HITL confirmation).',
  editor_append_section: 'Append a section of text to the end of document docId (server-side).',
  // Memory
  remember: 'Save important information to long-term memory for future conversations.',
  recall: 'Retrieve narrative context from long-term memory.',
  forget: 'Delete a memory by key.',
  inspect_agent_memory: 'Inspect another agent memory — list its stored entries.',
  write_agent_memory: 'Write to another agent memory (requires confirmation).',
  delete_agent_memory: 'Delete an entry from an agent memory (irreversible).',
  share_insight: 'Share an insight into the shared swarm memory ($shared namespace).',
  list_contradictions: 'Show unresolved contradictions in memory. Use when you need to clarify with the user what is current.',
  resolve_contradiction: 'Resolve a contradiction between two memory facts after clarifying with the user.',
  find_procedure: 'Find a procedure (step-by-step recipe) in memory by topic. Use before complex operations.',
  list_rules: 'Show all workspace rules — positive instructions all agents must follow.',
  add_rule: 'Add a workspace rule — a positive instruction for all agents (max 500 chars, up to 50 rules).',
  remove_rule: 'Remove a workspace rule by key. Get keys via list_rules.',
  list_shared_memories: 'List shared memories available to all agents.',
  get_shared_state: 'Get a value from the shared state. Without a key — all entries.',
  set_shared_state: 'Set a value in the shared state to coordinate between agents.',
  delete_shared_state: 'Delete a key from the shared state.',
  get_memory_stats: 'Memory statistics: entry counts, by agent, by tag.',
  extract_session_insights: 'Extract insights from the conversation history and save them to memory.',
  reflect_on_failure: 'Analyze a tool failure and save an insight to prevent recurrence. Returns: { reflection }.',
  upvote_memory: 'Increase memory relevance (positive feedback).',
  downvote_memory: 'Decrease memory relevance (negative feedback).',
  // Schema management
  create_table: 'Create a table (root or child). For a child table pass parentTypeId. After creation add columns via add_column. If you plan to fill data, design all columns up front, including lookup (ref) tables, so records can be created with complete data right away. Returns: { id, type:"table", name, message }.',
  add_column: 'Add a column to a table (requires confirmation). colTypeName: text/number/date/bool. For a lookup (ref to another table) pass refTypeId. For MULTISELECT (multiple values): 1) create a lookup table with the options, 2) pass refTypeId=that table id + multi=true. Multiselect WITHOUT refTypeId is impossible — it errors. For a workspace member (assignee, responsible person) use colTypeName "collaborator" — the value is the user\'s id; accepts id, email or username of a workspace member. Returns: { id, type:"column", alias, message }.',
  update_table: 'Rename a table, change its icon, or change its parent (requires confirmation). Returns: { id, type:"table", message }.',
  update_column: 'Modify a column: rename, change type, required, multi (requires confirmation). Returns: { id, type:"column", message }.',
  reorder_columns: 'Change the position of a column in a table.',
  get_schema_history: 'Show table structure change history (audit: creation, renaming, column add/remove).',
  get_schema_snapshot: 'Get the table structure snapshot saved before a destructive operation (column deletion etc).',
  get_schema_backlinks: 'Show which columns from OTHER tables reference this table (backlinks). Useful when building ROLLUP — shows available links. Returns: { items:[{colId,colName,fromTypeId,fromTypeName}] }.',
  // Plan schema
  plan_schema: 'Create a COMPLETE data schema in one shot — tables, columns, lookups, links, child tables — in a single action with one user confirmation. USE INSTEAD OF create_table + add_column when creating 2+ tables. IMPORTANT: specify columns ONLY in the source table (the one that REFERENCES), not in the lookup table. Do NOT create a "Name"/"Title" column — it duplicates _value. Use valueColumnName for the display title. Computed FORMULA columns: {alias, kind: "FORMULA", expr: "[Price] * [Qty]"}. LOOKUP/ROLLUP are not supported here — use create_computed. Returns: { type:"schema", tables:[{id,name}], created, skipped, errors, message }.',
  // AI Button
  get_ai_button_config: 'Get AI button configuration (prompt, model, outputReqId, temperature).',
  configure_ai_button: 'Configure an AI button — set the prompt, model, and where to write the result. In the prompt use [ColumnName] to substitute row values, [ID] for the record id, [VAL] for the record name. outputReqId — column ID to auto-write the result (optional). temperature: "low"(0.2)/"medium"(0.7)/"high"(1.2). agentMode: true runs a full AI agent with access to all tools (web_search, tables, documents etc).',
  run_ai_button: 'Press the AI button for a specific record. Runs the prompt with row data and returns the result (or writes it to outputReqId if configured). Returns: { type:"ai_result", result, message }.',
  get_http_button_config: 'Get HTTP Button configuration (type 1016) — method, URL, headers, body, responsePath, outputReqId.',
  configure_http_button: 'Configure an HTTP Button (type 1016) — set method, URL, headers, request body, and the path to the value in the response. URL and bodyTemplate support [ColumnName] placeholders. responsePath — a JSONPath expression to extract the value from the response (e.g. "data.price"). outputReqId — column ID to auto-write the result.',
  run_http_button: 'Run the HTTP Button for a specific record. Returns: { type:"http_result", value, writtenTo, outputReqId }.',
  get_script_button_config: 'Get Script Button configuration (type 1020) — the JS script and outputReqId.',
  configure_script_button: 'Configure a Script Button (type 1020) — set the JS script and the result column. The script runs in the browser (Web Worker). Globals: row (row data), fetch (HTTP via proxy), ai(prompt, model?) (LLM call), output(value) (write result), setField(reqId, value). Timeout: 60s.',
  // Reports
  list_reports: 'List all reports. Returns: { items:[{id,name}], total }.',
  describe_report: 'Get report structure: columns and settings (func, where, storedFrom/To, havingFrom/To).',
  create_report: 'Create a report. parentTypeId=9001 for a user-permissions report (admin only). Returns: { id, type:"report", message }.',
  update_report: 'Modify a report: name, icon, WHERE filter. WHERE supports [USER] [USER_ID] [TODAY] [NOW]. A column alias in WHERE is "c" + column id (from add_report_column or describe_report). Subqueries are allowed: the workspace table must be referenced only via the {{DB}} placeholder (e.g. FROM {{DB}} _t), and a subquery alias must start with an underscore (AS _sub, not AS sub; _abc123 is fine). Forbidden: ";", SQL comments (-- and /* */), $$ quoting. Example: AND c123.val IN (SELECT id FROM {{DB}} _t WHERE _t.t = 3) where 123 is the real column id. Returns: { id, type:"report", message }.',
  delete_report: 'Delete a report (requires confirmation). Returns: { message }.',
  add_report_column: 'Add a column to a report. Returns the column id — use it for WHERE in update_report: alias = "c" + id. Do NOT add a column named after the record title (_value / valueColumnName) — it is already shown as the first report column automatically. Passing valueColumnName (e.g. the title column) as columnAlias creates a broken column with reqTypeId=0 and the report shows "NaN". For a virtual permissions report reqTypeId: 9011=User, 9012=Role, 9013=Object type, 9014=Access level, 9015=Export, 9016=Delete. Returns: { id, type:"report_column", message }.',
  update_report_column: 'Modify a report column: func (aggregation), displayName, default filter (storedFrom/storedTo), HAVING for aggregates (havingFrom/havingTo), hidden, totalFunc. Returns: { id, type:"report_column", message }.',
  delete_report_column: 'Remove a column from a report (requires confirmation). Returns: { message }.',
  reorder_report_columns: 'Change report column order. order — array of colIds in the desired order.',
  get_report_history: 'Show report change history (audit: creation, renaming, column changes).',
  export_report: 'Export report data to CSV. Returns a CSV string with header and data. Returns: { csv, filename, rowCount }.',
  report_bulk_update: 'Bulk-update records via SET expressions on report columns (requires confirmation). Works only if the report has SET columns. Returns: { count, preview } or a confirmation status.',
  set_report_visibility: 'Show or hide a report in the list.',
  // Grants / permissions
  list_members: 'Show all workspace users with their roles and access level. Use for "show users", "who has access", "permissions", "member list" (admin only). Returns: { items:[{id,userId,email,name,username,role,roleId,roleName,lastSeenAt}], total }, where id is the membership ID (needed for remove_member and update_member_role — it is NOT userId), lastSeenAt — last visit, null if never visited.',
  list_roles: 'Show all roles and their access rights to object types (READ/WRITE/ADMIN). Use for "what roles exist", "role permissions", "what can an editor do" (admin only). Returns: { items:[{id,name}], total }.',
  get_user_permissions: 'Show all permissions of a specific user — which objects and at what level (READ/WRITE/ADMIN), whether they can export and delete (admin only).',
  get_permissions_report: 'Permissions matrix: users, roles, grants on object types (admin only).',
  set_grant: 'Grant or change access of a role or user to an object type (requires confirmation). level: NONE/READ/WRITE/ADMIN. targetTypeId=0 means all types (admin only). NOT for portal settings: portal config — set_portal_config.',
  remove_grant: 'Revoke access of a role or user to an object type (requires confirmation, admin only).',
  list_grants: 'List all workspace grants from the _v2_grants table. Filter by roleId or username. Returns: { items:[{id, role_id, username, target_type_id, level, can_export, can_delete}], total }.',
  // Roles
  create_role: 'Create a custom role in the workspace (admin only). Returns: { id, type:"role", name, message }.',
  update_role: 'Update a role: name or description (admin only, requires confirmation). Returns: { id, type:"role", message }.',
  delete_role: 'Delete a custom role (admin only, requires confirmation). System roles cannot be deleted. Returns: { message }.',
  // Row rules
  list_row_rules: 'List row-level security rules (admin only). Returns: { items:[{id,typeId,rule}], total }.',
  create_row_rule: 'Create a row-level security rule (requires confirmation, admin only). Returns: { id, type:"row_rule", message }.',
  delete_row_rule: 'Delete a row-level security rule (requires confirmation, admin only). Returns: { message }.',
  // Schema destructive
  delete_table: 'Delete a table entirely (requires confirmation). All data will be lost. Returns: { message }.',
  delete_column: 'Delete a column from a table (requires confirmation). Column data will be lost. Returns: { message }.',
  // Documents create
  create_document: 'Create a new document. Returns: { id, type:"document", title, message }.',
  move_document: 'Move a document into a folder, or out of one (folderId=null).',
  reorder_blocks: 'Change the order of blocks in a document. Pass an array of block IDs in the desired order.',
  list_doc_trash: 'List deleted documents (trash). Returns: { items:[{id,title,deletedAt}], total }.',
  restore_document: 'Restore a document from trash. Returns: { message }.',
  create_document_from_template: 'Create a new document from a template. A template is a document with is_template=true. Returns: { id, title }.',
  generate_pdf: 'Generate a PDF from a template for a specific record. A template is a document with [Column] variables. Returns: { filename, size, base64 }.',
  generate_docx: 'Generate a DOCX from a record using a template. templateDocId — ID of a .docx file in the workspace file storage. Returns: { filename, message }.',
  // Automations
  list_automations: 'List all automations in the workspace. Returns: { items:[{id,name}], total }.',
  create_automation: 'Create an automation (trigger, condition, actions). Returns: { id, type:"automation", name, message }.',
  delete_automation: 'Delete an automation (requires confirmation). Returns: { message }.',
  // Webhooks
  list_webhooks: 'List webhooks in the workspace. Returns: { items:[{id,url,events}], total }.',
  create_webhook: 'Create a webhook to receive event notifications. Returns: { id, type:"webhook", url, message }.',
  delete_webhook: 'Delete a webhook (requires confirmation). Returns: { message }.',
  // Forms
  list_forms: 'List data-entry forms. Returns: { items:[{token,config}], total }.',
  create_form: 'Create a form that collects data into a table. Returns: { type:"form", token, message }. Public URL of the form: {app origin}/forms/<token> (the token is in the response).',
  delete_form: 'Delete a form (requires confirmation). Returns: { message }.',
  // Files
  list_files: 'List uploaded files. Each file includes: processingStatus (pending/extracting/classifying/done/skipped/error), ocrEngine (mistral/pdf-parse/null), classifiedName (recognized document type).',
  delete_file: 'Delete a file from storage (requires confirmation).',
  mkdir: 'Create a directory in the file storage.',
  import_data: 'Import data from a CSV string into a table (requires confirmation). For small datasets up to ~100 rows. Returns: { created, errors:[{index,message}], message }.',
  export_data: 'Export table data to CSV.',
  create_excel: 'Create an Excel (XLSX) file from raw data. The file is saved to workspace storage. Returns a download link.',
  create_file: 'Create a file (document, report, note, presentation) and return a download link. Formats: md, txt, docx, pdf, pptx. Use when the user asks to write, generate, or format text into a file — including PDF or presentation requests. IMPORTANT: take the link ONLY from the downloadUrl of this call and paste it verbatim. Never invent a link or build one from a previous one — the signature is verified and a made-up link returns 403. Need a file — call the tool, even if you created a similar one before.',
  read_file: 'Read the content of an uploaded file by ID. Returns extracted text (OCR), metadata, recognized document type, and extracted fields. Use list_files to learn file IDs. Long files are read in pages: the response has totalChars, hasMore and nextOffset — when hasMore=true pass nextOffset as offset in the next call.',
  search_files: 'Full-text search over the content of uploaded files (OCR text). Returns match snippets, file names and IDs.',
  // Connectors
  list_connectors: 'List external connectors. Returns: { items:[{id,name}], total }.',
  cancel_connector: 'Stop a running connector by notification ID. Returns: { cancelled, message }.',
  // Members
  list_workspace_members: 'List workspace members (id, email, name, role, lastSeenAt — last visit, null if never visited) — basic list without permission details.',
  // Bulk
  bulk_create: 'Create multiple records in a table in one call. For ref (lookup) columns pass record IDs from the target table. Before calling, make sure you know the table schema (get_table_schema) and lookup record IDs (list_objects). Returns: { ids, created, errors:[{index,message}], message }.',
  bulk_delete: 'Delete multiple records (requires confirmation). Returns: { deleted, errors:[{index,message}], message }.',
  bulk_update: 'Update multiple records in one call (requires confirmation). Returns: { updated, errors:[{index,message}], message }.',
  // Document versions
  list_doc_versions: 'Show document version history.',
  restore_doc_version: 'Restore a document to the specified version (requires confirmation).',
  // Document sharing
  list_doc_sharing: 'Show who a document is shared with.',
  grant_doc_access: 'Grant a user access to a document.',
  revoke_doc_access: 'Revoke a user access to a document.',
  // Document folders
  list_doc_folders: 'Show document folders.',
  create_doc_folder: 'Create a document folder. Returns: { id, type:"folder", message }.',
  update_doc_folder: 'Rename a document folder.',
  delete_doc_folder: 'Delete a document folder (requires confirmation). Returns: { message }.',
  // Document tags
  list_doc_tags: 'Show all document tags.',
  create_doc_tag: 'Create a document tag. Returns: { id, type:"tag", message }.',
  delete_doc_tag: 'Delete a tag. Returns: { message }.',
  add_tag_to_doc: 'Assign a tag to a document.',
  remove_tag_from_doc: 'Remove a tag from a document.',
  // Automations update
  update_automation: 'Update an automation: name, trigger, condition, actions, enabled (requires confirmation). Returns: { id, type:"automation", message }.',
  trigger_automation: 'Run an automation manually (requires confirmation). Returns: { id, type:"automation", message }.',
  search_prices: 'Find product prices on marketplaces. Returns [{name, price, url, source}]. Sources: komus (office supplies), wildberries (general), samson (building materials), yandex-market (general), megamarket (general), lemanapro (building materials, requires home proxy), price-ru (general aggregator), petrovich (building materials). Returns: { items, query, source }. Call once per source.',
  run_script: 'Execute JavaScript in an isolated sandbox (isolated-vm). Available globals: row (current record), fetch(url,opts), ai(prompt,model?), output(value), setField(reqId,value) (requires objectId), query(typeId,opts) (returns metadata, not full fields), getRecord(id), createRecord(typeId,{name,fields}), updateRecord(id,{fields}), deleteRecord(id), browse(query,source?) (price search), console.log(), JSON, Math, Date. Limits: 128MB RAM, 60s timeout, rate limits on calls. Returns: { value, fields, logs }. (requires confirmation)',
  get_automation_runs: 'Show the run history of an automation.',
  // Webhooks update
  update_webhook: 'Update a webhook: URL, events, enabled (requires confirmation). Returns: { id, type:"webhook", message }.',
  // Forms update
  update_form: 'Update a form: field configuration, expiry (requires confirmation). Returns: { type:"form", token, message }.',
  // Connectors CRUD
  get_connector: 'Get connector details.',
  create_connector: 'Create an external connector (requires confirmation). For 1C/SAP/SCADA first call list_connector_presets and use configTemplate as the base of config. Returns: { id, type:"connector", name, message }.',
  list_connector_presets: 'List available connector presets (1C, SAP, SCADA). Use before create_connector.',
  update_connector: 'Update a connector (requires confirmation). Returns: { id, type:"connector", message }.',
  delete_connector: 'Delete a connector (requires confirmation). Returns: { message }.',
  run_connector: 'Run a connector (requires confirmation — may send data to an external system). Returns: { id, type:"connector", message }.',
  discover_connector_schema: 'Discover the external system schema via OData $metadata. Connects to the connector server, loads the structure (tables, fields, types) and proposes a mapping to Integram types. Works with 1C OData, SAP OData and other OData sources. Returns: { entities: [{name, synonym, type, fields, autoMapping}], url, total }.',
  reconcile_cdek: 'Reconcile CDEK order statuses with the API. Checks orders with a UUID in "In delivery" status, updates when CDEK reports delivered/pickup/return. Run manually or by cron (requires confirmation).',
  fetch_api_docs: 'Fetch API documentation by URL (OpenAPI/Swagger, HTML). Use before generate_connector_config to analyze the API. Returns: { source, content, endpoints }.',
  generate_connector_config: 'Generate connector config from the API structure (LLM). Use fetch_api_docs, then generate_connector_config, then test_connector_draft, then create_connector. Returns: { config, placeholders }.',
  test_connector_draft: 'Test-run a connector draft (requires confirmation — makes a real HTTP request). Returns: { ok, status, data }.',
  generate_connector_schema: 'Generate a table schema from a connector response (requires confirmation — creates a table). Returns: { tableName, columns }.',
  // Object history
  get_object_history: 'Show object change history (audit).',
  rollback_object: 'Roll an object back to the state before the specified change (requires confirmation). Returns: { id, type:"object", message }.',
  list_object_versions: 'List row versions (В1, В2, …) of a record — snapshots of the row together with its child tables.',
  create_object_version: 'Create a new version (Вn) of a record: snapshot of the row and ALL its child tables. Optional value/requisites are applied before the snapshot — an edit becomes a new version instead of overwriting cells.',
  activate_object_version: 'Switch a record to version Вn: live rows are replaced with the version content; the current state is auto-saved as a new version first (requires confirmation).',
  // Comments
  list_comments: 'Show comments on an object. Returns: { items:[{id,text,author}], total }.',
  create_comment: 'Add a comment to an object. Returns: { id, type:"comment", message }.',
  update_comment: 'Edit comment text. Returns: { id, type:"comment", message }.',
  delete_comment: 'Delete a comment. Returns: { message }.',
  add_reaction: 'Add a reaction (emoji) to a comment.',
  remove_reaction: 'Remove a reaction from a comment.',
  // Notifications
  list_notifications: 'Show user notifications. Returns: { items:[...], total }.',
  mark_read: 'Mark a notification as read. Without notifId — marks all.',
  send_notification: 'Send a notification to a user.',
  mark_all_notifications_read: 'Mark all notifications as read. Returns: { message }.',
  notification_action: 'Perform the action of a notification (e.g. approve/reject a paused automation). Returns: { message, result }.',
  // Trash
  list_trash: 'Show deleted objects (trash) for a table.',
  restore_from_trash: 'Restore an object from trash.',
  // Object move
  move_object: 'Move an object to a different parent.',
  reorder_object: 'Change the position of an object (sort order).',
  duplicate_object: 'Duplicate (copy) a record. Creates a new record with the same field values (except files and computed columns). " (copy)" is appended to the title. Returns: { id, type:"object", message }.',
  // Templates
  list_templates: 'List available workspace templates. Use before create_workspace to learn templateId. Returns: { items:[{id,slug,name,description,icon,category}], total }.',
  // Data templates
  list_data_templates: 'List record templates for a table. A template is a set of pre-filled fields for quick record creation.',
  create_data_template: 'Create a record template with pre-filled fields for a table.',
  delete_data_template: 'Delete a record template by ID. Irreversible.',
  // Workspace settings
  get_workspace_settings: 'Get workspace settings (admin only).',
  update_workspace_settings: 'Update workspace settings (admin only, requires confirmation). Returns: { message }.',
  // Backup
  create_backup: 'Take a full workspace backup: records, schema satellites, and workspace rows in shared tables (admin only, requires confirmation). Returns: { type:"backup", filename, path, rows, tables, secretsMode, secretsDropped[], diskIncluded, unknownKind[], skipped[], message }. The backup at this path does NOT carry secret columns: the encryption word is not accepted here (it would sit in the pending-actions table in plain text), and what was left out is listed in secretsDropped. Such a backup will not restore bot tokens, form keys, or webhook signatures; for those, take a backup from the administration screen. diskIncluded=false means the backup has file records but not the files themselves.',
  restore_backup: 'Restore a workspace from a backup file by name (admin only, requires confirmation). Restores ONLY into its own workspace: the backup carries values unique across the installation (portal address, webhook secret, form key) — copying a workspace into another one is clone_workspace. Returns: { status:"pending_confirmation", dryRun:{ format, tables[], restored, shortfall[], secretsMissing[], secretsRenewed[], secretsStripped[], usersMissing[], missing[], kept[], willArm[], verified, disk }, willArm[], secretsMissing[], secretsRenewed[], shortfall[], message }. Before confirmation a TRIAL restore runs (executed and rolled back), so the numbers are real. willArm — automations that will wake up after restore; secretsMissing — secrets the backup does not carry; secretsRenewed — secrets issued ANEW because the database requires a value (form key, invite token): references to the old ones are dead after restore; verified — how many archive entries were checksum-verified against the manifest, and verified.why is set when contents were not verified at all (an older single-file backup carries no checksums). The target must be EMPTY, otherwise mode:\'replace\' + confirm:\'REPLACE\' is required: there is no merging of a backup into a live workspace. This path cannot restore an encrypted backup (a human word is not accepted here) — do that from the administration screen.',
  list_dlq_jobs: 'List failed background jobs (dead letter queue).',
  retry_dlq_job: 'Retry a failed background job (admin only).',
  create_workspace: 'Create a new workspace (optionally from a template).',
  list_service_bots: 'List workspace service bots (service accounts).',
  create_service_bot: 'Create a service bot with an API key (admin only).',
  delete_service_bot: 'Delete a service bot and revoke all its keys. Irreversible.',
  list_service_keys: 'List API keys of a service bot.',
  issue_service_key: 'Issue a new API key for a service bot. The key is shown once.',
  export_workspace_data: 'Export table data to JSON (admin only).',
  bki_export: 'Export table data in BKI format (structured, admin only).',
  // Views
  list_views: 'List saved views (tabs) of a table. Each view = a set of filters + sorting + display settings (e.g. an "Active" tab = filter Status=Active). Use to learn which data slices are configured, then pass viewId to list_objects to load data with that view filters. Returns: { items:[{id,name}], total }.',
  create_view: 'Create a new table view with the given filters, sorting, and columns. Returns: { id, type:"view", message }.',
  update_view: 'Update a view: name, configuration, visibility (requires confirmation). Returns: { id, type:"view", message }.',
  get_view: 'Get the full view configuration (filters, sorting, columns) by ID. Returns: { id, typeId, owner, name, config, isShared, isDefault, createdAt, updatedAt }.',
  delete_view: 'Delete a table view (requires confirmation). Returns: { message }.',
  // Member management
  invite_member: 'Invite a user to the workspace by email (admin only).',
  create_invite_link: 'Create a one-time invite link for the workspace. Role is capped at the caller level, link expires in 7 days. Returns { url, token, role } (requires confirmation).',
  remove_member: 'Remove a member from the workspace (admin only, requires confirmation).',
  update_member_role: 'Change the role of a workspace member (admin only, requires confirmation).',
  // Schema detail
  get_table_schema: 'Get the detailed schema of a table by typeId (ID from list_tables). Parameter: typeId (integer). Returns: { id, type:"table", name, columns:[{id, name, type, refTable?, refTableId?, multi?}] }. Ref columns: refTable is the target table name, refTableId its typeId.',
  // KAG
  kag_search: 'Search the knowledge base (KAG). Finds entities, facts and concepts. Use when the user asks "what is known about...", "who is...", "what is...", or requests information from the knowledge base.',
  kag_traverse: 'Traverse an entity relations in the knowledge graph. Shows related entities and relation types.',
  kag_ask: 'Answer a question using the knowledge base. Automatically finds relevant entities and builds an answer from knowledge graph context.',
  kag_import_entities: 'Import entities into the knowledge graph (KAG). Each entity is a node with a name, type and observations. Embeddings are generated automatically.',
  kag_import_relations: 'Import relations between entities into the knowledge graph (KAG). Relation types: USES, REPLACES, CONFLICTS, PART_OF, DEPENDS_ON, RELATED_TO, IMPLEMENTS, COMPARED_TO.',
  kag_import_ontology: 'Import ontology classes into KAG. Classes define the concept hierarchy (SUBCLASS_OF via parentClassId).',
  kag_stats: 'KAG knowledge base statistics: counts of entities, classes and relations.',
  kag_browse: 'Browse KAG entities filtered by type and source. Returns the entity list and available types.',
  kag_clusters: 'Cluster entities by type and degree centrality. Shows which entity types are most connected.',
  kag_anomalies: 'Detect anomalies in the knowledge graph: hubs (over-connected nodes) and isolated entities (no relations).',
  kag_delete: 'Delete KAG data. Can delete everything or only a specific source. Removes relations, entities and classes. Irreversible.',
  kag_update_tags: 'Update entity tags in KAG. Tags are used for access control and filtering.',
  // View sharing
  share_view: 'Create a public link to a table view (optional password and expiry).',
  get_view_share: 'Get the current public access token of a view.',
  revoke_view_share: 'Revoke the public link of a view (requires confirmation).',
  // Record sharing
  share_record: 'Create a public link to a record.',
  get_record_share: 'Get the current public access token of a record.',
  revoke_record_share: 'Revoke the public link of a record (requires confirmation).',
  // Aggregate
  aggregate_objects: 'Aggregate table data — SUM, AVG, COUNT, MIN, MAX over columns. Returns computed values. Filters are not supported and are rejected with a 400 error; columns[] is supported.',
  group_objects: 'Group records by a column with a count per group. Does not accept filters (rejected with a 400 error); per-column filtering uses the filter (DSL) param.',
  pivot_objects: 'Pivot table — rows by one column, columns by another, values = an aggregate. valueField — numeric column id for the aggregate; agg — COUNT|SUM|AVG|MIN|MAX, default COUNT, SUM with valueField. SUM/AVG/MIN/MAX without valueField return a 400 error. Ref columns are read in both storage patterns, pivot keys are target names. Filters are not supported and are rejected with a 400 error.',
  // Dashboards
  list_dashboards: 'List workspace dashboards with widget counts.',
  get_dashboard: 'Get a dashboard by ID — title, widget list with types and configuration, grid layout.',
  create_dashboard: 'Create a dashboard with widgets (requires HITL confirmation). Grid is 12 columns wide. Widgets go in widgets[], positions in layouts.lg[]. WIDGET TYPES AND CONFIG: kpi={typeId,title,aggregation:count|sum|avg,fieldReqId?} — a single number; chart={typeId,groupByReqId,aggregation:count|sum,chartType:bar|line|pie|doughnut,title} — grouping chart; table={typeId,limit,title?} — record table; text={content,title?} — markdown; kanban={typeId,groupByReqId,title?}; gallery={typeId,limit,title?}; card={typeId,objectId,title?}. LAYOUT: each widget in layouts.lg: {i,x,y,w,h} where w+x<=12. Recommended sizes: kpi=3x2, chart=6x5, table=6x5, text=12x3. WORKFLOW: first list_objects or get_table_schema to learn typeId and the reqId of columns for grouping. Returns: { id, type:"dashboard", title, message }.',
  add_dashboard_widget: 'Add a single widget to an existing dashboard (requires HITL confirmation). IMPORTANT: type and config are separate parameters, NOT nested in a widget object. Position is automatic — the widget goes below all existing ones. TYPES AND CONFIG: kpi={typeId,aggregation:count|sum|avg,fieldReqId?}; chart={typeId,groupByReqId,aggregation:count|sum,chartType:bar|line|pie|doughnut}; table={typeId,limit?}; text={content}; kanban={typeId,groupByReqId}; gallery={typeId,limit?}; report={reportId}; document={docId}. Size (w,h) optional — defaults: kpi=3x2, chart=6x5, table=6x5, report=6x4, kanban=8x6. Returns: { widgetId, dashboardId, type:"dashboard", message }.',
  remove_dashboard_widget: 'Remove a widget from a dashboard by its ID (requires HITL confirmation). widgetId comes from get_dashboard, widgets[].i.',
  update_dashboard: 'Fully update a dashboard — title and/or ALL widgets (requires HITL). To add/remove a single widget use add_dashboard_widget / remove_dashboard_widget. For renaming pass only title. NOT for the portal: editing a portal module — update_portal_module(slug, config). Returns: { id, type:"dashboard", message }.',
  delete_dashboard: 'Delete a dashboard entirely (requires HITL confirmation). Returns: { message }.',
  // AI formula
  generate_formula: 'AI-generate a FORMULA column expression — natural language description to {expr, vars}. Only for kind=FORMULA. For LOOKUP/ROLLUP use create_computed directly.',
  autofill_batch: 'Batch AI autofill — run the AI button for multiple records at once (up to 500).',
  // Computed
  list_computed: 'List computed columns of a table (LOOKUP, ROLLUP, FORMULA). Returns: { items:[{id,label,kind}], total }.',
  create_computed: 'Create a computed column (requires confirmation). kind: LOOKUP (value from a linked table — needs sourceReqId: the ref column in THIS table, targetColId: the column in the linked table), ROLLUP (aggregation over child records — needs linkReqId: the column in the CHILD table referencing THIS table, targetColId: the child column to aggregate, fn: COUNT|SUM|AVG|MIN|MAX), FORMULA (expr: expression, vars: {varName: reqId}). Returns: { id, type:"computed", alias, kind, message }.',
  update_computed: 'Update a computed column (requires confirmation). Returns: { id, type:"computed", message }.',
  delete_computed: 'Delete a computed column (requires confirmation). Returns: { message }.',
  // Validation
  get_validation_rules: 'Get validation rules for a column (minLength, maxLength, minValue, maxValue, regex, unique).',
  set_validation_rules: 'Set validation rules for a column (requires confirmation).',
  // Schema graph
  get_schema_graph: 'Get the workspace schema graph — all tables, columns and relations between them. Use to analyze data structure and find dependencies. Returns: { types:[...], edges:[...] }.',
  convert_column_to_ref: 'Convert a text column into a reference. Creates a lookup table from the unique column values and replaces the column with a ref (requires confirmation — changes the schema).',
  // External agents
  list_agents: 'List registered external agents and their capabilities. Use to discover available specialists before delegating tasks.',
  delegate_to_agent: 'Delegate a task to an external agent by slug. The agent processes the task and returns a result. Returns: { type:"agent_response", message }.',
  list_agent_suggestions: 'List agent-creation suggestions based on behavioral patterns.',
  apply_agent_suggestion: 'Apply a suggestion — create an agent from the detected pattern (requires confirmation).',
  dismiss_agent_suggestion: 'Dismiss an agent-creation suggestion.',
  get_agent: 'Get details of a registered agent: endpoint, capabilities, metrics.',
  check_agent_health: 'Check external agent availability (health check).',
  get_agent_tasks: 'Task history of an external agent: statuses, results, errors.',
  // Portal
  get_portal_config: 'Get the current portal config of the workspace: active flag, custom domain, module config. config.auth.requireAuth (boolean) closes the whole portal for anonymous visitors (API answers 401 except /api/config, /api/auth/*, /api/files/*, /api/bots*, webhooks; pages redirect to /auth); config.auth.allowRegistration (boolean, default true) — when false, only EXISTING clients can log in (new client creation is refused with REGISTRATION_CLOSED).',
  set_portal_config: 'Create or update the portal config (branding, auth, pages). Without merge — full replacement. With merge: true — deep-merge a partial config into the existing one (no need to pass the whole config). Writes verify references: custom_code repo/file and bindings table:N must exist in this workspace — otherwise REPO_NOT_IN_WORKSPACE / FILE_NOT_IN_REPO / TABLE_NOT_IN_WORKSPACE (defects already present in the previous config do not block the edit). The previous config is pushed to history before writing (GET /portal/api/config/history, rollback via POST /portal/api/config/restore). Editing one module — update_portal_module(slug, config). config.auth.requireAuth: true closes the WHOLE portal: anonymous API answers 401 (open only /api/config, /api/auth/*, /api/files/*, /api/bots*, CDEK/UDS webhooks) and pages redirect to /auth — warn the user that guest storefront (guest orders, cart, catalog) becomes unavailable, and requireAuth/allowRegistration must be booleans. config.auth.allowRegistration: false forbids creating a new client at login (existing clients only). NOT for access rights: grants — set_grant. Requires confirmation.',
  update_portal_module: 'Update the config of a single portal module (by slug) without overwriting the rest. Deep merge: nested objects (e.g. bindings) merge by key; `null` deletes a key; arrays and scalars are replaced wholesale. Reference checks as in set_portal_config: repo/file/bindings must exist in this workspace. NOT for dashboards: editing a dashboard — update_dashboard(id). Full config replacement — set_portal_config.',
  portal_preview: 'Get the portal preview URL.',
  portal_publish: 'Enable (active=true) or disable (active=false) the portal. Requires confirmation.',
  // Telegram management
  list_telegram_bots: 'List workspace Telegram bots. Returns ID, name, username, enabled, config.',
  create_telegram_bot: 'Create a new Telegram bot. Registers the webhook automatically. name — display name, username — the @username of the bot in Telegram, token — the token from @BotFather. config.commands — array of commands: [{command:"/status", description:"Status", action:"reply", replyText:"Your order..."}]. Requires confirmation.',
  update_telegram_bot: 'Update a Telegram bot. If token changes, the webhook is re-registered. Requires confirmation.',
  delete_telegram_bot: 'Delete a Telegram bot. Irreversible. Requires HITL confirmation.',
  sync_telegram_bot: 'Sync the bot config with the Telegram API — sends commands (setMyCommands), description (setMyDescription), short description (setMyShortDescription), menu button (setChatMenuButton). Requires confirmation.',
  get_telegram_bot_status: 'Get the bot status from Telegram — bot info (getMe) and webhook state (getWebhookInfo: URL, pending updates, last error).',
  test_telegram_bot: 'Send a test message from the bot to the given chat. chatId — numeric Telegram chat ID.',
  // Telegram extended
  telegram_forward_message: 'Forward or copy a message from one chat to another.',
  telegram_send_invoice: 'Send a payment invoice (Telegram Stars or provider). currency "XTR" for Stars.',
  telegram_create_invoice_link: 'Create a payment invoice link (no chat needed). Returns URL.',
  telegram_ban_member: 'Ban a user in a group/supergroup/channel.',
  telegram_unban_member: 'Unban a user in a group/supergroup/channel.',
  telegram_restrict_member: 'Restrict user permissions in a supergroup (mute, read-only, etc).',
  telegram_get_chat: 'Get up-to-date information about a chat (title, members count, etc).',
  telegram_get_chat_member_count: 'Get the number of members in a chat.',
  telegram_create_invite_link: 'Create an additional invite link for a chat.',
  telegram_post_story: 'Post a story to a channel (bot must be admin with post_stories permission).',
  telegram_delete_story: 'Delete a previously posted story.',
  telegram_get_business_connection: 'Get info about a business connection (Business API).',
  telegram_promote_member: 'Promote or demote a user to admin in a group/channel.',
  telegram_pin_message: 'Pin a message in a chat.',
  telegram_unpin_message: 'Unpin a message (or all if no messageId) in a chat.',
  telegram_approve_join: 'Approve a pending chat join request.',
  telegram_decline_join: 'Decline a pending chat join request.',
  telegram_edit_story: 'Edit a previously posted story.',
  telegram_set_business_bio: 'Set the bio of the connected business account (0-140 chars).',
  telegram_set_business_name: 'Set the name of the connected business account.',
  get_portal_orders: 'List all portal orders (admin). Optional filter by status.',
  get_portal_metrics: 'Portal summary statistics: order count, revenue, breakdown by status.',
  get_portal_documents: 'List portal documents (admin). Returns all documents without a client filter.',
  get_portal_profile: 'Find a portal client profile by email, phone or ID.',
  // Codespace
  list_repos: 'List git repositories in the workspace. Returns: { items: [{ id, name, slug, description, default_branch, size_bytes }], total }.',
  get_repo: 'Repository info (branches, last commit, size). Returns: { id, name, slug, default_branch, size_bytes, ... }.',
  list_branches: 'List repository branches. Returns: { items: [branchName, ...], total }.',
  create_branch: 'Create a new branch in a repository. Returns: { created: true, name, fromRef }.',
  delete_branch: 'Delete a repository branch. The default branch cannot be deleted. Returns: { deleted: true, name }.',
  list_commits: 'List commits of a branch/ref. Returns: { items: [{ sha, message, author, date }], total }.',
  get_commit_diff: 'Diff of a specific commit (works including the initial commit). Returns: { sha, diff }.',
  commit_file: 'Create or update a single file in a repository (one commit). Writes like git: the commit is created on the given baseCommit, and the branch moves only if it has not advanced; otherwise a merge is performed. Returns merged=true when a merge was needed and unchanged=true when content matched and no commit was required. Returns: { committed: true, slug, branch, filePath, commitHash }.',
  commit_multi_files: 'Atomically commit multiple files in a single commit. Prefer over several commit_file calls when changing multiple files. Returns: { committed: true, slug, branch, files, commitHash }.',
  delete_repo_file: 'Delete a file from a repository (git rm + commit). Returns: { deleted: true, slug, branch, filePath, commitHash }.',
  list_prs: 'List repository pull requests. Returns: { items: [{ id, number, title, status, sourceBranch, targetBranch, ... }], total }.',
  get_pr: 'Pull request details. Returns: { id, number, title, description, status, sourceBranch, targetBranch, mergeStrategy, ... }.',
  create_pr: 'Create a pull request. Returns: { id, number, title, status, ... }.',
  update_pr: 'Update a PR (title, description, status, strategy). To reopen pass status="open". Returns the updated PR.',
  merge_pr: 'Merge a pull request into the target branch. Returns: { merged: true, commitHash, ... }.',
  list_pr_comments: 'List PR comments. Returns: { items: [{ id, body, author_username, created_at }], total }.',
  add_pr_comment: 'Add a comment to a PR. Returns: { id, body, author_id, created_at }.',
  get_github_sync: 'Get the GitHub Sync configuration of a repository. Returns: { configured, remoteUrl, direction, autoSync, hasToken, lastSync, lastError }.',
  configure_github_sync: 'Configure GitHub Sync for a repository. direction: push_only (Integram-to-GitHub), pull_only (GitHub-to-Integram), both (two-way). Returns: { configured, direction, webhookSecret }.',
  push_to_github: 'Manually push all repository branches to GitHub. Returns: { pushed: true }.',
  pull_from_github: 'Manually pull all branches from GitHub into the local repository. Returns: { pulled: true }.',
  get_blame: 'Get blame (per-line authorship) for a file in a repository. Returns: { path, ref, lines:[{lineNo, content, sha, author, summary}], totalLines }.',
  create_repo: 'Create a new git repository in the workspace.',
  delete_repo: 'Delete a git repository. Irreversible.',
  get_diff_range: 'Diff between two branches or commits. Returns: { diff }.',
  remove_github_sync: 'Remove the GitHub binding of a repository. Irreversible.',
  get_evidence_card: 'Get an evidence card for a pull request — an AI-generated card with change analysis.',
  commit_portal_component: 'Write a generated Vue SFC component into a codespace repository for use in a portal custom_code module. The repository is created automatically if it does not exist. Requires confirmation.',
  kit_list_components: 'List @kit library building blocks for portals: value reading/recovery helpers, empty-state handling, components. Returns name, kind and a one-line summary. Take the version from the kit field of the custom_code module config; without a version the latest published one is used. Returns: { version, builtAt, items:[{name,kind,summary,module}], total, catalogTotal }. Errors distinguish "library not published", "version missing", "version exists but has no catalog" and "catalog unreadable" — an empty list only means an empty filter.',
  kit_get_component: 'Details of a single @kit building block: module, kind, description, props, slots, and uiKeys for components. Unknown names return an error with similar names. uiKeys — node keys that accept custom classes via the ui prop: <DataTable :ui="{ row: \'my-row\' }" />. Classes are appended to the block own classes, not replacing them. A key not present in uiKeys does not exist: the block will not accept it and warns in the console — never invent node names. There is no uiKeys field at all when the block has no own nodes (headless) or the version predates the release where the ui prop appeared. Returns: { version, name, kind, summary, module, props?, slots?, uiKeys? }.',
  kit_get_tokens: 'Dictionary of @kit library styling tokens: CSS variable names that define color, spacing, radius, font and motion of the building blocks, plus stable class names of each block. CALL BEFORE writing styles for @kit blocks: a name absent here does not exist — an invented name resolves to nothing and the component comes out structurally correct with zero styling. Each token carries a usage field — a ready-made string like var(--kit-color-text, var(--color-text, #1f2328)); write it in full, including the fallback value. Returns: { version, builtAt, items:[{name,kind,purpose,usage,fallback,shell}], total, catalogTotal, kinds, shellTokens, byComponent:[{name,layer,tokens,classes}] }. Errors: KIT_TOKENS_MISSING — the version has no dictionary (introduced after 0.4.0), KIT_NO_STYLING — the block has no markup.',
  kit_list_versions: 'Which @kit library versions are published. Needed to know which version a project runs on and what is available. Returns: { items:[version], total, latest }. Order and "latest" are computed numerically, so 0.1.10 is newer than 0.1.2.',
  get_portal_catalog: 'Get the portal catalog product list (admin). Returns price, photo, category, availability.',
  get_portal_carts: 'List active portal customer carts (admin). Returns item count and total.',
  get_portal_tickets: 'List portal support tickets (admin). Can filter by status.',
  get_portal_kb_articles: 'List portal knowledge base articles (admin). Returns category, date, excerpt.',
  get_portal_client_role: 'Get the role and access permissions of a portal client by ID.',
  // Normalizer
  start_normalization: 'Start normalization of files from a folder. mode=auto — fully automatic; mode=assisted — with schema confirmation. Returns a jobId for tracking.',
  get_normalization_status: 'Get normalization job status by jobId.',
  confirm_normalization_schema: 'Confirm the data schema designed by the normalizer (HITL step). Call when status.stage = "architecting".',
  confirm_normalization_resolution: 'Confirm entity matching (deduplication). Call when pendingApprovals > 0.',
  cancel_normalization: 'Cancel a normalization job.',
  // Timeseries
  record_timeseries: 'Record one or more timeseries points.',
  query_timeseries: 'Query a timeseries with aggregation.',
  list_timeseries_sources: 'List timeseries sources in the workspace.',
  ask_advisor: 'Ask the platform expert — advice on schema design, best practices, troubleshooting, feature explanations. Gives a detailed advice grounded in the current workspace schema. Returns: { advice }.',
  web_search: 'Search the internet. Returns a list of results with title, URL and snippet. Use for price lookups, product info, current data from open sources. Returns: { query, results:[{title, url, snippet}], total }.',
  list_platform_capabilities: 'Full list of platform capabilities by category: data, columns, analytics, automations, documents, integrations, security, portal, AI, graph. Use when the user asks "what can the platform do?" or "what features are there?". Returns: { items:[{category, features}] }.',
  docs_map: 'Map of the platform documentation: which documents exist, what each covers and when it last changed. Start here for questions about how the platform works. Returns: { total, areas, docs:[{path, area, module, title, summary, updatedAt}] }.',
  docs_read: 'Read a documentation page in full or a single section. Take the path from docs_map or docs_search. Long text is read in pages: when hasMore=true pass nextOffset as offset. Returns: { path, title, section, headings, text, totalChars, hasMore, lastCommit }.',
  docs_search: 'Find a place in the platform documentation: hybrid search (meaning + exact names) over fragments with document and section references. An empty result means "not in the found documents", NOT "absent from the documentation". Returns: { results:[{path, section, text, citation, score}], total }.',
  docs_tool: 'Card of a platform tool: purpose, parameters, risk tier, group. Read from the live catalog, so it always matches the code — unlike figures quoted in documentation prose. Without name returns a filtered list. Returns: { name, group, riskTier, description, params } or { results, total }.',
  // Automation single
  get_automation: 'Get details of a single automation (trigger, condition, actions, status). Returns: { id, name, trigger, condition, actions, active }.',
  // Automation insights
  get_automation_insights: 'List AI insights about workspace automations (anomalies, recommendations, observations). Returns: [{ type, headline, reasoning, confidence, priority, dismissed_type_key, sourceTypeId }].',
  dismiss_automation_insight: 'Dismiss an insight by its type key (dismissedTypeKey). Returns: { dismissedTypeKey }.',
  submit_automation_insight_feedback: 'Submit feedback on an insight: useful (+1) or irrelevant (-1). Returns: {}.',
  start_automation_batch: 'Run an automation in batch across all records of a table (HITL — requires confirmation). Returns: { batchId, total }.',
  // Webhook deliveries
  get_webhook_deliveries: 'Webhook delivery history: status, server response, errors. Returns: { items:[{id, status, responseCode, error, createdAt}], total }.',
  retry_webhook_delivery: 'Retry a webhook delivery (for failed attempts). Returns: { success, deliveryId }.',
  delete_notification: 'Delete a user notification by ID. Returns: { message }.',
  // Workspace invitations
  list_workspace_invitations: 'List active workspace invitations (admin only; email, role, status). Returns: { items, total }.',
  cancel_workspace_invitation: 'Cancel a workspace invitation by ID (admin only, requires confirmation). Returns: { message }.',
  // Object backlinks
  get_object_backlinks: 'Find all records referencing this object (mentions, ref fields). Returns: { items:[{id, typeId, typeName, fieldName}], total }.',
  // Report joins
  create_report_join: 'Add a JOIN to a report to combine it with another table. For child tables the JOIN to the parent table is auto-detected (child→parent via a.up). Without leftField/rightColId no ON condition is generated — the default pattern is used. The alias is needed to bind columns via joinAlias in add_report_column. Returns: { joinId, ... }.',
  delete_report_join: 'Remove a JOIN from a report by ID (requires confirmation). Returns: { deleted }.',
  // Teamchat
  send_teamchat_message: 'Send a message to a teamchat topic. Supports code_cell cards for executable code.',
  get_decision: 'Get a decision by ID together with its links and discussions. Returns: { decision: {id, title, domain, verdict, description, chatRoomId, ...}, links: {rel_type: [{id, decisionId, title, direction}]}, discussions: {roomId, roomName, recentTopics} }.',
  update_decision: 'Update decision fields (title, description, verdict, domain etc). Returns: { id }.',
  delete_decision: 'Delete a decision by ID (irreversible). Returns: { id, deleted: true }.',
  list_decision_links: 'List outgoing links of a decision, grouped by type. Returns: { data: { rel_type: [{id, decisionId, title, createdBy, createdAt}] } }.',
  create_decision_link: 'Create a typed link between decisions. Types: supersedes, depends_on, related_to, conflicts_with, conflicts etc. Returns: { id, fromId, toId, relType }.',
  delete_decision_link: 'Delete a link between decisions by link ID (irreversible). Returns: { id, deleted: true }.',
  create_topic: 'Create a new topic in a chat room.',
  update_topic: 'Update a teamchat topic: rename, change status or priority, assign an assignee, pin, set a deadline.',
  // Teamchat rooms
  list_rooms: 'List all teamchat rooms available to the current user. Returns: { data: [{id, name, description, room_type, visibility, created_by, created_at}] }.',
  create_room: 'Create a new teamchat room. Returns: { data: {id, name, visibility} }.',
  create_dm: 'Create or get an existing direct message (DM) room with a user. Returns: { id, name, room_type:"direct" }.',
  get_room: 'Get teamchat room details by ID. Returns: { data: {id, name, description, room_type, visibility, created_by, created_at} }.',
  update_room: 'Rename a teamchat room. Returns: { data: {id, name} }.',
  delete_room: 'Delete a teamchat room with all its topics and messages. Irreversible. Returns: { deleted: true }.',
  join_room: 'Join a public teamchat room. Returns: { joined: true }.',
  // Teamchat members
  list_room_members: 'List members of a teamchat room. Returns: { data: [{user_id, role, joined_at}] }.',
  add_room_member: 'Add a member to a teamchat room. Returns: { added: true }.',
  remove_room_member: 'Remove a member from a teamchat room. Irreversible. Returns: { removed: true }.',
  // Teamchat messages
  list_messages: 'Get messages from a teamchat topic. Cursor-based pagination.',
  create_message: 'Send a message to a chat topic as the current user.',
  update_message: 'Edit a message in teamchat.',
  delete_message: 'Delete a message from teamchat. Irreversible.',
  move_message: 'Move a message to another topic.',
  mark_topic_read: 'Mark all messages in a topic as read.',
  export_topic_to_document: 'Export a chat topic to a document. Returns: { data: {documentId, url} }.',
  // Activity Intelligence
  get_team_activity: 'Team activity stats: messages, closed topics, tasks (including overdue), decisions, debates, reactions per member. Hot topics, blockers, recent decisions.',
  get_user_activity: 'Get activity for a specific user: messages, tasks (open/completed/overdue), decisions, blockers assigned to them.',
  generate_team_digest: 'AI team digest: who completed what, blockers, overdue items, accepted decisions, participation balance.',
  // Orgs
  list_orgs: 'List organizations of the current user.',
  get_org: 'Get organization info by slug.',
  org_my_issues: 'Issue summary across all organization workspaces. Filters: assignee ("me" — mine), status, type, workspace (slug), cursor pagination (nextCursor from the response).',
  org_people: 'People workload across organization areas: active and overdue issues, points.',
  org_portfolio: 'Organization portfolio: per area total/done/active/overdue/progress and the active sprint.',
  org_activity: 'Feed of recent organization issue changes (PM history): who, what, when.',
  org_metrics: 'Organization aggregate metrics: velocity per sprint, cycle time, lead time.',
  org_search: 'Search records across all organization workspaces: where found, id, table. For precise search within one area use list_objects.',
  create_org: 'Create a new organization.',
  update_org: 'Rename an organization.',
  delete_org: 'Delete an organization. Irreversible.',
  list_org_members: 'List organization members. Returned in pages: compare items length with total and request the next page via page.',
  list_org_team: 'Organization roster by inheritance: all members of its workspaces with job titles (organization roles). Titles are assigned only by the owner.',
  set_org_member_role: 'Assign a job title (organization role: admin, editor, viewer) to an organization member or remove it (role: none). Only the organization owner assigns titles; the member must belong to at least one of its workspaces. Requires confirmation.',
  add_org_member: 'Add a member to an organization by email.',
  remove_org_member: 'Remove a member from an organization.',
  transfer_org_ownership: 'Transfer organization ownership to another member. The former owner remains an administrator. Irreversible without the new owner consent.',
  leave_org: 'Leave an organization yourself. The owner first transfers ownership; the last administrator appoints a successor.',
  invite_to_org: 'Invite to an organization by email. The invitation is sent by mail and lives 7 days; unregistered users can be invited too.',
  revoke_org_invitation: 'Revoke an unused organization invitation.',
  list_org_invitations: 'List organization invitations: pending, accepted and revoked.',
  // Object-layer
  resolve_aliases: 'Build role aliases from source records. Each record is bound to a canonical object via an alias child record. With apply=true creates aliases (dedup by productId+source_system+source_pk+name).',
  resolve_identity: 'Probabilistic resolution of records without a strong key — pgvector candidates, an opponent challenges false matches, a human confirms via HITL. Creates identity resolution clusters.',
  get_canonical_movement: 'Get a canonical object together with its movement across relations (graph traversal). Returns the object, its role aliases and related records.',
  // TTS
  speak_text: 'Speak text via Piper TTS (neural speech synthesis). Returns base64 audio. Lets you listen to arbitrary text — a generated answer, a document, an analysis result.',
  list_tts_voices: 'List available Piper TTS voices on the server.',
  get_tts_status: 'Check TTS (Piper) availability. Returns: { available, engine }.',
  // Workspace tools
  list_workspace_tools: 'List custom workspace tools executed in an isolated sandbox (isolated-vm). Optional: filter to active only.',
  register_workspace_tool: 'Register a new custom workspace tool. Code runs in an isolated sandbox (isolated-vm).',
  update_workspace_tool: 'Update an existing custom workspace tool.',
  delete_workspace_tool: 'Delete a custom workspace tool.',
  import_tool_pack: 'Bulk-import a tool pack (set of custom tools) into the workspace.',
  // PM
  pm_list_issues: 'List PM issues with optional filters.',
  pm_get_issue: 'Get full details of a PM issue by ID.',
  pm_create_issue: 'Create a new PM issue. Trigger phrases: "create a task", "task in PM" — prefer this over create_object and documents. NOT for plain table records: create_object(typeId, fields). For multi-part work create an epic and attach child issues (parent_id) with labels — not one task with a wall of text.',
  pm_update_issue: 'Update an existing PM issue. A checklist field passed here is ignored — checklist items are edited one at a time via pm_toggle_checklist and the issue checklist routes; pm_bulk_update rejects the field with a 400.',
  pm_delete_issue: 'Soft-delete a PM issue.',
  pm_move_issue: 'Move an issue to a different sprint, parent, or reorder within a list.',
  pm_add_comment: 'Add a comment to a PM issue.',
  pm_link_issues: 'Create a link between two PM issues.',
  pm_unlink_issues: 'Remove a link between PM issues.',
  pm_link_data: 'Link a PM issue to workspace data: a table, document, or report. Use to connect a task with its source record.',
  pm_unlink_data: 'Remove a data link between a PM issue and workspace data.',
  pm_list_data_links: 'List data links of a PM issue (linked tables, documents, reports).',
  pm_toggle_checklist: 'Toggle a checklist item on a PM issue by item id. Omit done to flip the current state. Item ids come from the issue checklist field; positions are not addressable.',
  pm_bulk_update: 'Update multiple PM issues at once (e.g. set status/priority/assignee for a batch).',
  pm_bulk_delete: 'Soft-delete multiple PM issues (move to trash).',
  pm_list_comments: 'List comments of a PM issue.',
  pm_update_comment: 'Edit a PM issue comment (author only).',
  pm_delete_comment: 'Delete a PM issue comment (author only).',
  pm_watch_issue: 'Subscribe to notifications for a PM issue.',
  pm_unwatch_issue: 'Unsubscribe from notifications for a PM issue.',
  pm_list_watchers: 'List watchers (subscribers) of a PM issue.',
  pm_list_trash: 'List deleted PM issues (trash).',
  pm_restore_issue: 'Restore a PM issue from trash.',
  pm_list_templates: 'List PM issue templates.',
  pm_create_template: 'Create a PM issue template.',
  pm_update_template: 'Update a PM issue template.',
  pm_delete_template: 'Delete a PM issue template.',
  pm_list_members: 'List workspace members (for assignee selection in PM).',
  pm_list_boards: 'List PM boards of the workspace with issue counts.',
  pm_list_statuses: 'List PM statuses of the workspace with their kind (open/active/done/canceled). Use before create/update to pick a valid status name.',
  pm_move_to_board: 'Move an issue to another board. The status is mapped to the closest one in the target board (by kind); the response reports the mapping.',
  pm_export_csv: 'Export PM issues to CSV. Returns { csv, rowCount }. Supports the same filters as pm_list_issues.',
  pm_list_sprints: 'List all sprints in the workspace.',
  report_platform_issue: 'Report a platform problem (unexplained tool failure, confusing result, unclear documentation) to the platform maintainer. Call after an unexplained tool error or on explicit user request; draft the report from the failure context first. The report body is sanitized of secrets, and the user confirms sending.',
  pm_create_sprint: 'Create a new sprint.',
  pm_update_sprint: 'Update an existing sprint.',
  pm_start_sprint: 'Start a sprint (changes status to active).',
  pm_complete_sprint: 'Complete a sprint (moves incomplete issues to backlog).',
  pm_delete_sprint: 'Delete a sprint.',
  pm_get_board: 'Get the Kanban board view (issues grouped by status columns). Optional filters: sprint_id, board_id, milestone_id, show_all, labels.',
  pm_get_backlog: 'Get the backlog (unassigned issues not in any sprint). Optionally filter by milestone with milestone_id.',
  pm_get_sprint_progress: 'Get sprint progress (burndown, velocity, completion stats).',
  pm_list_milestones: 'List milestones with progress (issues/points done vs total) and effective_status: planned/active/completed, or missed when overdue.',
  pm_create_milestone: 'Create a milestone.',
  pm_update_milestone: 'Update an existing milestone.',
  pm_complete_milestone: 'Complete a milestone. Unclosed issues move to backlog (default) or to the next milestone with move_to set to next.',
  pm_delete_milestone: 'Delete a milestone. Issues are unlinked, not deleted.',
  pm_get_roadmap: 'Roadmap data: epic timeline ranges (computed from descendant issues) plus milestones with progress.',
  pm_get_velocity: 'Get velocity metrics for completed sprints — done points, total points, average velocity.',
  pm_get_burndown: 'Get burndown chart data for a sprint — remaining points per day with ideal line.',
  pm_get_cycle_time: 'Get cycle time metrics — time from in_progress to done, with avg/median.',
  pm_get_lead_time: 'Get lead time metrics — time from creation to close, with avg/median.',
  pm_get_workload: 'Get workload distribution across team members — active issues, in-progress, overdue, points.',
  pm_detect_blockers: 'Find blocked/stale/overdue issues. Returns blockers with reasons.',
  pm_summarize_sprint: 'AI summary of a sprint — done, remaining, overdue, points. Useful for standup/review.',
  pm_triage_issue: 'Auto-classify an issue: suggest type, priority, labels based on title/description.',
  pm_decompose_issue: 'Break down an issue into sub-tasks. Extracts checklists/headers from the description, or suggests a generic breakdown.',
  pm_suggest_estimate: 'Suggest a story point estimate based on historical data or a heuristic.',
  pm_plan_sprint: 'AI sprint planning: select backlog issues up to capacity based on priority and velocity.',
  pm_org_my_issues: 'Issues across the workspaces of an org. Filter to one project with workspace; the response repeats it back and sets workspaceNotFound when no visible workspace matches.',
  pm_org_workload: 'Team workload across all org workspaces.',
  pm_org_portfolio: 'Portfolio status of all projects in an org.',
  pm_org_create_issue: 'Create an issue in a specific workspace through an org.',
  // Nightcall
  ncl_create_requirement: 'Create a new requirement in the Canonical Normative Model.',
  ncl_list_requirements: 'List requirements in the CNM with optional filters.',
  ncl_get_requirement: 'Get requirement details with the connected graph.',
  ncl_update_requirement: 'Update a requirement. Status transitions are enforced; transitioning to accepted requires governance provenance — use ncl_governance_decision instead of setting status directly.',
  ncl_create_edge: 'Create a typed edge between objects in the requirement graph.',
  ncl_create_intent: 'Create a VerificationIntent — what needs to be verified for a requirement.',
  ncl_find_conflicts: 'Find requirements that conflict with a given requirement.',
  ncl_get_graph: 'Get the subgraph around a node in the requirement graph.',
  ncl_governance_decision: 'Make a governance decision to accept/reject a requirement. Accepting a requirement changes its status.',
  ncl_create_source: 'Create a SourceStatement — a traceable fragment from a document or decision.',
  ncl_update_source: 'Update a SourceStatement (text, status, validity window). Dependent evidence of requirements derived from this source is marked STALE.',
  ncl_formalize: 'System A: Formalize natural language text into an Extraction IR and store it as a ModelChangeProposal. Extracts atomic statements, modalities, proposed VerificationIntents, and ambiguities. Nothing enters the CNM until the proposal is accepted via ncl_decide_proposal.',
  ncl_list_proposals: 'List ModelChangeProposals (pending Extraction IRs awaiting a governance decision).',
  ncl_get_proposal: 'Get a ModelChangeProposal with its full Extraction IR (requirement candidates, concepts, unresolved issues).',
  ncl_decide_proposal: 'Governance decision on a ModelChangeProposal. verdict=accepted publishes the Extraction IR into the CNM (requirements created as accepted with a GovernanceDecision link); rejected or needs_clarification leaves the CNM untouched.',
  ncl_save_artifact_spec: 'Save a new version of an ArtifactSpecification (artifact type schema + generation dependencies). The previous active version is superseded. The compiler uses the active spec instead of built-in QBR defaults.',
  ncl_list_artifact_specs: 'List stored ArtifactSpecifications (versions of artifact type schemas).',
  ncl_waive: 'Authorized waiver of a known requirement violation. Does NOT erase the violation; a run whose every violation is waived gets release verdict WAIVED instead of REJECTED.',
  ncl_propose_mapping: 'System D2: propose a verification backend mapping for an intent kind that has no deterministic D1 handler. The result is a candidate handler_mapping proposal requiring ncl_decide_proposal — it is never silently activated.',
  ncl_run: 'Execute the full Nightcall cycle: resolve spec, compile, generate, verify, decision. Returns the run result with verdict.',
  ncl_resolve_spec: 'System C: Resolve EffectiveSpecification from TaskContext. Computes applicable requirements, detects conflicts, creates obligations. Returns an immutable frozen spec.',
  ncl_list_runs: 'List verification runs with pagination.',
  ncl_get_run: 'Get full run details: effective spec, compilation IR, attempts, obligations, evidence, decisions, verification runs.',
  ncl_compare_runs: 'Compare two runs across 7 canon-12 §10.4 slices: task context, effective spec, schema, generation graph, value transfer, evidence, verdicts.',
  ncl_list_intents: 'List VerificationIntents with optional filters.',
  ncl_create_requirement_version: 'Create a new version of an existing requirement (by stable_id). Computes the next version number automatically.',
  ncl_list_source_definitions: 'List Source Plane definitions — registered data sources and their snapshot modes.',
  ncl_get_source_definition: 'Get a single Source Plane definition by ID.',
  ncl_list_baselines: 'List requirement baselines — frozen snapshots of active requirements.',
  ncl_get_baseline: 'Get baseline details: included requirements, intents, specs, edges and their counts.',
  ncl_publish_baseline: 'Publish a new baseline — freezes the current active requirements, intents, specs, and edges.',
  ncl_list_families: 'List artifact families — lineage chains of runs that produced accepted artifacts.',
  ncl_get_family: 'Get family details: all runs, accepted artifacts, schema versions, comparison policy.',
  ncl_list_grants: 'List authority grants — who has which nightcall permissions.',
  ncl_grant_authority: 'Grant a nightcall authority to a user. Authorities: APPROVE_REQUIREMENT, REJECT_REQUIREMENT, GRANT_WAIVER, REVOKE_WAIVER, CLASSIFY, DECLASSIFY, PUBLISH_BASELINE.',
  ncl_list_waivers: 'List authority waivers — obligation-level exceptions from verification.',
  ncl_create_authority_waiver: 'Create an authority waiver for a specific obligation. Distinct from ncl_waive (requirement-level decision) — this is an obligation-level exception through the authority system.',
  ncl_list_declassifications: 'List declassification records — classification level reductions for run artifacts.',
  ncl_create_declassification: 'Declassify the artifacts of a run — lower the classification level. Levels: public, internal, confidential, restricted.',
  ncl_list_outbox: 'List transactional outbox events — pending and published domain events.',
  ncl_drain_outbox: 'Drain the transactional outbox — publish all pending events. Returns counts of published/failed/skipped.',
  ncl_render_artifact_view: 'Render an accepted run artifact into a block document. Only works on runs with ACCEPTED verdict. Returns {documentId, blockCount, rebuilt}.',
  // Presentations
  pres_list: 'List presentations in the workspace.',
  pres_get: 'Get one presentation with its slides.',
  pres_create_from_outline: 'Create a presentation from a markdown outline (# heading = one slide). Returns presId.',
  pres_save_slides: 'Replace all slides of a presentation with the given canonical model.',
  pres_delete: 'Soft-delete a presentation.',
  // Video engine
  vid_create_job: 'Create a training-video render job: the scenario (JSON: title, viewport, steps[] with narration) is recorded in a browser and assembled with TTS narration; returns jobId.',
  vid_get_job: 'Get video-engine job status: stage (queued/tts/recording/rendering/done/error/cancelled), progress, path to the rendered mp4.',
  vid_list_jobs: 'List video-engine jobs of the workspace.',
  vid_cancel_job: 'Cancel a video-engine job (if it has not finished yet).',
  vid_validate_scenario: 'Validate a video scenario against the schema without creating anything: returns normalized steps or errors.',
  vid_publish_job: 'Publish a finished video-engine job mp4 into workspace files: the file appears in Files and becomes servable to the portal via /portal/api/files/<filename>. Idempotent.',
  // Financial model
  fin_grid: 'Computed financial-model grid: period columns, rows with per-period values, totals and the sheet structure. scenario picks a scenario (defaults to the model first one), sheetId narrows to one sheet. Rows with an id like "g123" are group subtotals and have no record in the database.',
  fin_graph: 'Dependency graph of a financial model: the order cells are computed in and which cell depends on which. A circular reference is returned in the cycle field with an empty order — in that case the grid does not compute at all.',
  fin_goal_seek: 'Goal seek: which levers bring a target cell to the wanted value. target.rowId is a row id (or "g123" for a group subtotal), levers are input rows that may change, with optional min/max bounds. Without apply:true it only computes; with apply:true it writes the solution, and only when the target was reached. Failure is named in reason: unknown_target, no_sensitivity, flat, bounds, no_convergence.',
  // Synced lookups (external lookup tables pulled from another workspace)
  synced_lookup_create: 'Attach an external lookup: the local table becomes a synced copy of a table from another workspace. Requires access to the source workspace.',
  synced_lookup_delete: 'Detach an external lookup: removes the sync config (the target table keeps its data). Requires confirmation (TIER_HIGH).',
  synced_lookup_list: 'List external lookups of the current workspace with their schedules and last sync status.',
  synced_lookup_reschedule: 'Change the sync schedule of an external lookup.',
  synced_lookup_sync: 'Run the sync of an external lookup immediately.',

};

/** Convert backend tool def → MCP tool listing entry */
function toMcpTool(t) {
  const entry = {
    name: t.name,
    description: EN_DESCRIPTIONS[t.name] || t.description || t.name,
    inputSchema: t.parameters || { type: 'object', properties: {} },
  };
  // Add behavioral annotations
  const annotations = {};
  if (READ_ONLY_TOOLS.has(t.name)) annotations.readOnlyHint = true;
  if (DESTRUCTIVE_TOOLS.has(t.name)) annotations.destructiveHint = true;
  if (Object.keys(annotations).length) entry.annotations = annotations;
  return entry;
}

// Handler: list tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [LIST_WORKSPACES_DEF, SWITCH_WORKSPACE_DEF, CREATE_WORKSPACE_DEF, DELETE_WORKSPACE_DEF, CLONE_WORKSPACE_DEF, SEARCH_TOOLS_DEF, CONFIRM_ACTION_DEF];
  for (const [, t] of activeTools) {
    tools.push(toMcpTool(t));
  }
  return { tools };
});

// Handler: call tool
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  return withUpdateNotice(await dispatchTool(request));
});

async function dispatchTool(request) {
  const { name, arguments: args } = request.params;

  // Built-in tools
  if (name === 'list_workspaces') return handleListWorkspaces();
  if (name === 'switch_workspace') return handleSwitchWorkspace(args?.slug || '');
  if (name === 'create_workspace') return handleCreateWorkspace(args || {});
  if (name === 'delete_workspace') return handleDeleteWorkspace(args?.slug || '');
  if (name === 'clone_workspace') return handleCloneWorkspace(args || {});
  if (name === 'search_tools') return handleSearchTools(args?.query || '');
  if (name === 'confirm_action') return handleConfirmAction(args?.approved === true, args?.confirmId);

  // Check workspace is set
  if (!workspace) {
    return { content: [{ type: 'text', text: 'No workspace selected. Use list_workspaces to see available workspaces, then switch_workspace to select one.' }], isError: true };
  }

  // Regular tool call → proxy to backend
  if (!activeTools.has(name)) {
    // PM-164: называем похожие инструменты, чтобы модель не подменяла имя.
    const catalog = (allTools || []).map((t) => ({ name: t.name, group: t.group, description: t.description }));
    const text = buildNotActiveText(name, catalog, [...activeTools]);
    return { content: [{ type: 'text', text }], isError: true };
  }

  try {
    await ensureAuth();
    const callId = crypto.randomUUID();
    const data = await apiFetch(`/api/v2/${workspace}/ai/tool`, {
      method: 'POST',
      body: JSON.stringify({ name, args: args || {}, skipHitl: SKIP_HITL, callId }),
    });
    const result = data.ok ? data.data : data;

    // Check if this is a HITL confirmation request
    if (result?.status === 'pending_confirmation') {
      const now = Date.now();
      const entry = enqueuePending(pendingHitlQueue, {
        id: nextHitlId(),
        threadId: result.threadId,
        action: name,
        description: result.message || `Pending: ${name}`,
        createdAt: now,
      }, { now, ttlMs: HITL_QUEUE_TTL_MS, maxSize: HITL_QUEUE_MAX_SIZE });
      return {
        content: [{ type: 'text', text: buildHitlConfirmationText({ tool: name, message: result.message, queued: pendingHitlQueue.length, confirmId: entry.id }) }],
      };
    }

    // Handle elicitation sentinel — ask the MCP client for structured input
    if (data?.data?.__elicit) {
      try {
        const elicitResult = await server.elicit(
          data.data.prompt,
          { schema: data.data.schema }
        );
        if (elicitResult.action === 'cancel') {
          return { content: [{ type: 'text', text: 'Elicitation cancelled by user.' }] };
        }
        // Re-call the tool with the elicited answer injected into args
        const originalArgs = args || {};
        let resumeData;
        try {
          resumeData = await apiFetch(`/api/v2/${workspace}/ai/tool`, {
            method: 'POST',
            body: JSON.stringify({
              name,
              args: { ...originalArgs, elicitedAnswer: elicitResult.content },
              threadId: data?.data?.threadId,
              schemaCtx: null,
            }),
            headers: { 'Content-Type': 'application/json' },
          });
        } catch (resumeErr) {
          // TD-065: отказ повторного вызова — ошибка тула, а не «требуется ввод»
          return toolErrorResult(resumeErr);
        }
        return {
          content: [{ type: 'text', text: typeof resumeData.data === 'string' ? resumeData.data : JSON.stringify(resumeData.data) }],
        };
      } catch (e) {
        log(`Elicitation not supported by client or failed: ${e.message}`);
        return {
          content: [{ type: 'text', text: `Требуется ввод: ${data.data.prompt}. Передайте ответ в аргументах инструмента.` }],
        };
      }
    }

    // Detect tool-level errors returned as structured JSON from backend
    if (result?.error === true && result?.message) {
      // details несёт то, без чего ошибку не исправить: блоки конфликта
      // с исходной версией, новый baseCommit, признак повторяемости.
      // Без него вызывающий видит только текст и вынужден гадать.
      const text = result.details
        ? `Error: ${result.message}\n\n${JSON.stringify(result.details, null, 2)}`
        : `Error: ${result.message}`;
      return { content: [{ type: 'text', text }], isError: true };
    }

    return {
      content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }],
    };
  } catch (err) {
    return toolErrorResult(err);
  }
}

// ─── confirm_action handler ──────────────────────────────────────────────────

async function handleConfirmAction(approved, confirmId) {
  // PM-241: подтверждение идёт ПО ИМЕНИ ожидания. Без имени берётся
  // единственное ожидание; при нескольких — отказ с перечнем, не угадывание.
  const taken = takePending(pendingHitlQueue, confirmId, { ttlMs: HITL_QUEUE_TTL_MS });
  if (taken.error === 'EMPTY') {
    return { content: [{ type: 'text', text: 'No pending action to confirm.' }], isError: true };
  }
  if (taken.error === 'AMBIGUOUS') {
    return { content: [{ type: 'text', text: `Multiple pending actions; pass confirmId of the one the user approved: ${taken.available.join(', ')}.` }], isError: true };
  }
  if (taken.error === 'UNKNOWN_CONFIRM_ID') {
    return { content: [{ type: 'text', text: `No pending action with confirmId "${confirmId}". Live ids: ${taken.available.join(', ') || 'none'}.` }], isError: true };
  }

  const pending = taken.entry;
  try {
    let msg;
    if (pending.onApprove) {
      // Local HITL (e.g. delete_workspace) — execute callback directly
      if (approved === true) {
        msg = await pending.onApprove();
      } else {
        if (pending.onReject) pending.onReject();
        msg = 'Action rejected.';
      }
    } else {
      // Backend HITL — proxy to /mcp-resume
      await ensureAuth();
      let data;
      try {
        data = await apiFetch(`/api/v2/${workspace}/ai/mcp-resume`, {
          method: 'POST',
          body: JSON.stringify({ threadId: pending.threadId, approved }),
        });
      } catch (resumeErr) {
        // TD-065: раньше отказ /mcp-resume читался как текст успеха
        return toolErrorResult(resumeErr);
      }
      msg = data.data?.message || (approved ? 'Action confirmed and executed.' : 'Action rejected.');
    }

    const remaining = pendingHitlQueue.length > 0 ? ` (${pendingHitlQueue.length} more pending — call confirm_action again)` : '';
    return { content: [{ type: 'text', text: `[${pending.action}] ${msg}${remaining}` }] };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error confirming action: ${err.message}` }], isError: true };
  }
}

// ─── create_workspace handler ─────────────────────────────────────────────────

async function handleCreateWorkspace({ name, slug, template, templateId, blocks }) {
  if (!name || !slug) {
    return { content: [{ type: 'text', text: 'Error: name and slug are required' }], isError: true };
  }
  if (!/^[a-z][a-z0-9_-]{1,62}[a-z0-9]$/.test(slug)) {
    return { content: [{ type: 'text', text: 'Error: slug must be 3-64 chars, start with a letter, only a-z 0-9 _ -' }], isError: true };
  }
  try {
    await ensureAuth();
    const body = { name, slug };
    if (templateId) body.templateId = templateId;
    else if (template) body.template = template;
    // blocks едут как есть: отсутствие поля = «весь шаблон», [] = «только
    // основа» — различение держит REST-схема (blockPickSchema), здесь его не
    // стирать: `if (blocks)` не отличает [] от отсутствия, что и требуется.
    if (Array.isArray(blocks)) body.blocks = blocks;
    const data = await apiFetch('/api/v2/workspaces', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!data.ok) throw new Error(JSON.stringify(data.error || data));

    const ws = data.data;
    log(`Created workspace "${ws.slug}" (id=${ws.id}, db=${ws.dbName})`);

    // Auto-switch to the new workspace
    rememberActivation();
    workspace = ws.slug;
    await loadWorkspaceTools(ws.slug);

    return {
      content: [{ type: 'text', text: `Workspace "${ws.name}" created (slug: ${ws.slug}). Automatically switched to it. ${activeTools.size} core tools loaded.` }],
    };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error creating workspace: ${err.message}` }], isError: true };
  }
}

// ─── delete_workspace handler ─────────────────────────────────────────────────

let _pendingDeleteSlug = null;

async function handleDeleteWorkspace(slug) {
  if (!slug) {
    return { content: [{ type: 'text', text: 'Error: slug is required' }], isError: true };
  }

  // Require explicit confirmation via confirm_action before deleting
  if (_pendingDeleteSlug !== slug) {
    _pendingDeleteSlug = slug;
    const now = Date.now();
    const entry = enqueuePending(pendingHitlQueue, {
      id: nextHitlId(),
      threadId: `delete-ws-${slug}`,
      action: 'delete_workspace',
      description: `Permanently delete workspace "${slug}" and ALL its data`,
      createdAt: now,
      onApprove: async () => {
        await ensureAuth();
        const data = await apiFetch(`/api/v2/workspaces/${slug}`, { method: 'DELETE' });
        if (!data.ok) throw new Error(JSON.stringify(data.error || data));
        log(`Deleted workspace "${slug}"`);
        forgetActivation(activationMemory, slug);
        if (workspace === slug) {
          workspace = '';
          activeTools.clear();
          await server.sendToolListChanged();
        }
        _pendingDeleteSlug = null;
        return `Workspace "${slug}" and all its data have been permanently deleted.`;
      },
      onReject: () => { _pendingDeleteSlug = null; },
    }, { now, ttlMs: HITL_QUEUE_TTL_MS, maxSize: HITL_QUEUE_MAX_SIZE });
    return {
      content: [{ type: 'text', text: `⚠️ REQUIRES CONFIRMATION: Permanently delete workspace "${slug}" and ALL its data. This action is irreversible.\n\nAsk the user to confirm or reject, then call confirm_action(approved=true/false).` }],
    };
  }

  // If already pending for same slug, remind
  return {
    content: [{ type: 'text', text: `Deletion of workspace "${slug}" is already pending confirmation. Call confirm_action(approved=true/false).` }],
  };
}

// ─── clone_workspace handler ──────────────────────────────────────────────────

/**
 * Чего в клоне нет ПО УСТРОЙСТВУ — одной строкой и без потерь.
 *
 * Перечень отдаёт реестр платформы (registry/workspace-carry.js) записями вида
 * {table, kind, home, why} — 54 штуки. Печатать их подряд нельзя: в простыне из
 * 54 имён тонет ровно то, ради чего перечень и нужен. Печатать усечённо — тоже
 * нельзя: «Not carried by design: …» читается как ПОЛНЫЙ перечень, и раньше он
 * им не был (13 имён из 54).
 *
 * Отсюда деление по роду. Числом — журналы и выводимое: у клона своя жизнь с
 * чистого листа, а выводимое он отстроит сам; знать, что их 46 и 3, достаточно.
 * ВСЁ ОСТАЛЬНОЕ — поимённо: это не след прошедшего, а отсутствие того, чем
 * область пользовалась, и узнать об этом хозяин клона обязан из ответа, а не из
 * пустого раздела через неделю.
 *
 * ПОЧЕМУ ЗАШИТ ТОЛЬКО СВОРАЧИВАЕМЫЙ ПЕРЕЧЕНЬ. Реестр рода объявляет на сервере
 * (registry/workspace-carry.js, KINDS), а пакет выложен в npm и живёт дольше
 * сервера, к которому подключён: спросить у реестра ему нечем, новый род приедет
 * в ответе раньше обновления. Перечень называемых поимённо здесь стоял тоже — и
 * незнакомый род молча выпадал из печати, оставаясь в числе заголовка: замер
 * 20.08.2026, запись {kind:'право'} давала «(55)» и ни одного упоминания имени.
 * Это ровно тот изъян, против которого печать и писалась. Теперь называется
 * ВСЁ, кроме двух названных родов: отстанет этот перечень — незнакомое станет
 * многословным, а не пропадёт. Направление ошибки выбрано, а не оставлено.
 */
function notCarriedLine(list) {
  // Сервер прежней выкладки отдаёт имена строками: рода у них нет, и такая
  // запись называется поимённо — свернуть неизвестное числом значит потерять его.
  const items = list.map(x => (typeof x === 'string' ? { table: x, kind: null } : x));

  // Единственное зашитое знание о родах: что вправе свернуться числом.
  const FOLD = { 'журнал': 'logs', 'выводимое': 'derived tables' };
  // Подписи родов, называемых поимённо. Незнакомый род печатается своим именем —
  // отсутствие подписи не повод не назвать записи.
  const LABEL = { 'секрет': 'secrets', 'содержимое': 'content', 'настройка': 'settings' };
  const ORDER = ['secrets', 'content', 'settings'];

  const named = new Map();   // подпись рода → имена таблиц
  const folded = new Map();  // подпись рода → счёт
  for (const item of items) {
    const kind = item.kind || null;
    if (kind && FOLD[kind]) {
      folded.set(FOLD[kind], (folded.get(FOLD[kind]) || 0) + 1);
      continue;
    }
    // Пустой ключ — записи без рода (сервер прежней выкладки): подписывать нечем.
    const label = kind ? (LABEL[kind] || kind) : '';
    if (!named.has(label)) named.set(label, []);
    named.get(label).push(item.table);
  }

  // Порядок: известные рода как прежде, следом незнакомые, последними —
  // безродные. Внутри рода — порядок реестра.
  const rank = (label) => (label === '' ? 2 : ORDER.indexOf(label) === -1 ? 1 : 0);
  const parts = [...named.entries()]
    .sort((a, b) => rank(a[0]) - rank(b[0])
      || (rank(a[0]) === 0 ? ORDER.indexOf(a[0]) - ORDER.indexOf(b[0]) : a[0].localeCompare(b[0])))
    .map(([label, names]) => (label ? `${label} — ${names.join(', ')}` : names.join(', ')));

  const tail = [...folded.entries()].map(([label, n]) => `${n} ${label}`);
  if (tail.length) parts.push(`plus ${tail.join(' and ')} (source history and data the clone rebuilds itself)`);

  return `Not carried by design (${items.length}): ${parts.join('; ')}.`;
}

async function handleCloneWorkspace({ sourceSlug, name, slug, includeDocuments, includeMembers }) {
  if (!sourceSlug || !name || !slug) {
    return { content: [{ type: 'text', text: 'Error: sourceSlug, name, and slug are required' }], isError: true };
  }
  try {
    await ensureAuth();
    const body = { name, slug };
    // Имена полей — те, что объявляет маршрут (include_documents / include_members).
    // Zod срезает неизвестные поля молча: в camelCase клон уезжал без документов
    // и без участников, а вызов при этом выглядел успешным.
    if (includeDocuments !== undefined) body.include_documents = includeDocuments;
    if (includeMembers !== undefined) body.include_members = includeMembers;
    const data = await apiFetch(`/api/v2/workspaces/${sourceSlug}/clone`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!data.ok) throw new Error(JSON.stringify(data.error || data));

    const ws = data.data;
    log(`Cloned workspace "${sourceSlug}" → "${ws.slug}" (id=${ws.id})`);

    // Auto-switch to the new workspace
    rememberActivation();
    workspace = ws.slug;
    await loadWorkspaceTools(ws.slug);

    // Чего в клоне НЕТ — обязано быть сказано словами. Отсутствующее опаснее
    // пустого: пустой раздел зритель видит, отсутствующий — нет.
    const gaps = [];
    if (ws.notCarried?.length) gaps.push(notCarriedLine(ws.notCarried));
    if (ws.carryFailed?.length) {
      gaps.push(`Failed to carry: ${ws.carryFailed.map(f => `${f.table} (${f.reason})`).join('; ')}.`);
    }
    if (ws.carryPartial?.length) {
      gaps.push(`Carried partially: ${ws.carryPartial
        .map(p => `${p.table} (columns missing in target: ${[...p.missing, ...p.unsafe].join(', ')})`).join('; ')}.`);
    }

    return {
      content: [{ type: 'text', text: `Workspace "${sourceSlug}" cloned into "${ws.name}" (slug: ${ws.slug}). Automatically switched to it. ${activeTools.size} core tools loaded.${gaps.length ? ' ' + gaps.join(' ') : ''}` }],
    };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error cloning workspace: ${err.message}` }], isError: true };
  }
}

// ─── search_tools handler ────────────────────────────────────────────────────

// Built-in tool descriptors for search — always available, no activation needed
const BUILT_IN_TOOL_DEFS = [
  LIST_WORKSPACES_DEF,
  SWITCH_WORKSPACE_DEF,
  CREATE_WORKSPACE_DEF,
  DELETE_WORKSPACE_DEF,
  CLONE_WORKSPACE_DEF,
  SEARCH_TOOLS_DEF,
  CONFIRM_ACTION_DEF,
];

// Group alias map — maps Russian/English SYNONYMS to TOOL_DEFS group names.
// Exact group names are matched dynamically against the live catalog (allTools),
// so a new backend group is picked up automatically — add here only synonyms.
//
// A value may be an ARRAY when one word honestly names two groups. That is not a
// convenience: `automations` is the name of a 5-tool group (run details, webhook
// delivery log) AND the everyday word for editing automations, which lives in
// `workspace`. Sending the word to one group only silently hid the other half —
// the prompt said `search_tools("automations")` and then named `create_automation`,
// which the query could never activate. Same shape for connectors and forms.
export const GROUP_ALIASES = {
  документ: 'docs', документы: 'docs', docs: 'docs', doc: 'docs',
  отчёт: 'reports', отчеты: 'reports', отчёты: 'reports', report: 'reports', reports: 'reports',
  схема: 'schema', таблица: 'schema', колонк: 'schema', schema: 'schema',
  права: 'grants', роли: 'grants', доступ: 'grants', grants: 'grants',
  permissions: 'grants', permission: 'grants', acl: 'grants', role: 'grants', member: 'grants',
  автоматизац: ['workspace', 'automations'], коннектор: 'workspace', форм: 'workspace',
  // Вебхук заведён в `workspace`, а журнал его доставки (`get_webhook_deliveries`,
  // `retry_webhook_delivery`) — в `automations`. Раздел подсказки называет и то и другое.
  вебхук: ['workspace', 'automations'],
  webhook: ['workspace', 'automations'], webhooks: ['workspace', 'automations'],
  form: 'workspace', forms: 'workspace',
  connector: 'workspace', connectors: 'workspace', dashboard: 'workspace', dashboards: 'workspace',
  invitation: 'workspace', invitations: 'workspace', backup: 'workspace', audit: 'workspace',
  файл: 'workspace', файлы: 'workspace', file: 'workspace', files: 'workspace',
  портал: 'portal', телеграм: 'portal', telegram: 'portal', portal: 'portal',
  граф: 'graph', связи: 'graph', graph: 'graph',
  память: 'memory', memory: 'memory', запомни: 'memory',
  комментар: 'comments', comments: 'comments',
  git: 'codespace', github: 'codespace', репозитор: 'codespace', codespace: 'codespace',
  teamchat: 'teamchat', решени: 'teamchat', дискусс: 'teamchat',
  timeseries: 'timeseries', метрик: 'timeseries',
  объект: 'objects', запис: 'objects', bulk: 'bulk', массов: 'bulk',
  kag: 'kag', знани: 'kag',
  tts: 'ai', озвучк: 'ai', голос: 'ai', speak: 'ai',
  advisor: 'advisor', совет: 'advisor', консультант: 'advisor',
  // Словами, которыми спрашивают справку. Без них войти в группу можно было
  // только словом `advisor`, которого спрашивающий не знает, а «документация»
  // уводила в `docs` — документы воркспейса. `справочник` намеренно НЕ здесь:
  // ниже он отдан `lookups`, и это верно — в Integram так зовут таблицу-справочник.
  документац: 'advisor', справк: 'advisor', инструкц: 'advisor',
  руководств: 'advisor', help: 'advisor', guide: 'advisor', устроен: 'advisor',
  agents: 'agents', агент: 'agents', делегир: 'agents',
  orgs: 'orgs', организаци: 'orgs', org: 'orgs',
  automations: ['automations', 'workspace'], automation: ['automations', 'workspace'],
  // Раздел «History & rollback» называет и `get_object_backlinks`, а оно в `objects`.
  history: ['history', 'objects'], истори: ['history', 'objects'],
  lookups: 'lookups', lookup: 'lookups', справочник: 'lookups',
  'meta-kb': 'meta-kb', metakb: 'meta-kb', дебат: 'meta-kb', дискусси: 'meta-kb',
  pm: 'pm', проект: 'pm', задач: 'pm', спринт: 'pm', канбан: 'pm', бэклог: 'pm', issue: 'pm', sprint: 'pm', backlog: 'pm', board: 'pm',
  встреч: 'meetings', совещан: 'meetings', meeting: 'meetings',
  // Средства уровня области: без этих слов группа звалась только точным
  // именем `workspace-tools`. Пришли из бэкендового словаря при сведении.
  инструмент: 'workspace-tools', пакет: 'workspace-tools', организац: 'orgs',
  найткол: 'nightcall', требован: 'nightcall', спецификац: 'nightcall', верификац: 'nightcall',
  формализ: 'nightcall', formaliz: 'nightcall', governance: 'nightcall', evidence: 'nightcall',
  // Само имя группы `finmodel` по-русски не ищется: слово «финмодель» с ним не
  // совпадает ни одной из сторон.
  финмодел: 'finmodel',
};

/**
 * Pure selection step of search_tools — exported so the guard test can run the REAL
 * matcher over the REAL catalog instead of a copy of it. A copied matcher is how the
 * prompt drifted away from what activation actually returns in the first place.
 *
 * @param {string} query
 * @param {Array<{name:string,description?:string,group?:string}>} catalog
 * @param {(t:object)=>boolean} available
 * @returns {{matched:Array<object>, groupExact:number, total:number, droppedByGroup:Object<string,number>}}
 */
export function selectTools(query, catalog, available = () => true) {
  const q = String(query || '').toLowerCase();
  const words = q.split(/\s+/).filter(Boolean);
  // Live group catalog — single source of truth, new backend groups appear automatically
  const knownGroups = [...new Set(catalog.map(t => t.group).filter(g => g && g !== 'core'))];
  const toolText = t => `${t.name} ${t.description || ''} ${t.group || ''}`.toLowerCase();
  const allTools = catalog;
  {

    // Phase 1: group-based match — if any query word names a group (exact, or prefix
    // when at least 4 chars to avoid short-name false hits) or hits a synonym alias,
    // return all tools from that group
    const matchedGroups = new Set();
    for (const w of words) {
      for (const g of knownGroups) {
        const minLen = Math.min(w.length, g.length);
        if (w === g || (minLen >= 4 && (g.startsWith(w) || w.startsWith(g)))) matchedGroups.add(g);
      }
      for (const [alias, group] of Object.entries(GROUP_ALIASES)) {
        const minLen = Math.min(w.length, alias.length);
        if (w === alias || (minLen >= 4 && (alias.startsWith(w) || w.startsWith(alias)))) {
          for (const g of Array.isArray(group) ? group : [group]) matchedGroups.add(g);
        }
      }
    }

    // Счёт релевантности: стем слова (первые 5 символов — против русской
    // морфологии, см. бэкендовую копию) в имени ×3, в описании ×1;
    // стабильность — по порядку каталога. Ранжируются и групповые совпадения:
    // cap 30 честный (total и droppedByGroup сообщают срез), наполнители
    // группы не вытесняют релевантные тула.
    const stem = w => (w.length > 5 ? w.slice(0, 5) : w);
    const ranked = (list) => list
      .map((t, i) => ({ t, i, s: words.reduce((acc, w) => {
        const st = stem(w);
        return acc + (t.name.toLowerCase().includes(st) ? 3 : 0)
                   + ((t.description || '').toLowerCase().includes(st) ? 1 : 0);
      }, 0) }))
      .sort((a, b) => b.s - a.s || a.i - b.i)
      .map(x => x.t);

    let matched;
    if (matchedGroups.size > 0) {
      // Квота на группу — только при нескольких названных группах: одна группа
      // и так ограничена общим cap, и резать её десяткой значило бы отнимать
      // тула, которые cap и не отрезал бы («организации» — 21 тул orgs).
      // При нескольких — каждая названная группа отдаёт своих лучших, иначе
      // большая группа вытесняет маленькую (документация: docs=50 съедал
      // advisor=4 — стемы кириллические против английских описаний).
      const perGroup = [];
      for (const g of matchedGroups) {
        const groupTools = ranked(allTools.filter(t => available(t) && t.group === g));
        perGroup.push(...(matchedGroups.size > 1 ? groupTools.slice(0, 10) : groupTools));
      }
      const groupSet = new Set(perGroup.map(t => t.name));
      matched = perGroup.concat(ranked(allTools.filter(t =>
        !groupSet.has(t.name) && available(t) && words.every(w => toolText(t).includes(w)))));
    } else {
      // Fallback A: strict AND — all words must appear in name+description+group
      matched = allTools.filter(t => available(t) && words.every(w => toolText(t).includes(w)));

      // Fallback B: ranked OR — when AND finds nothing, require a majority of words
      // and rank by where they hit (name > group > description). Keeps AND precision
      // when it works, adds recall when the query is more verbose than any single
      // tool description (the "nightcall requirements formalize" → 0 results case).
      if (!matched.length && words.length > 1) {
        const minHits = Math.ceil(words.length / 2);
        matched = allTools
          .filter(available)
          .map(t => {
            const name = t.name.toLowerCase();
            const group = (t.group || '').toLowerCase();
            const desc = (t.description || '').toLowerCase();
            let hits = 0, score = 0;
            for (const w of words) {
              const inName = name.includes(w);
              const inGroup = group.includes(w);
              const inDesc = desc.includes(w);
              if (inName || inGroup || inDesc) hits++;
              if (inName) score += 3;
              if (inGroup) score += 2;
              if (inDesc) score += 1;
            }
            return { t, hits, score };
          })
          .filter(x => x.hits >= minHits)
          .sort((a, b) => b.score - a.score || b.hits - a.hits)
          .map(x => x.t);
      }
    }

    // Cap 30 для ЛЮБОГО запроса, включая точное имя группы. Прежнее изъятие
    // («группа по имени активируется целиком») активировало 121 тул workspace —
    // это и есть срыв «<80 имён» (TD-167). Срез честный: total и droppedByGroup
    // сообщают, сколько и кого отрезано.
    const RESULT_CAP = 30;
    const keep = RESULT_CAP;
    const totalMatched = matched.length;
    const droppedByGroup = {};
    if (totalMatched > keep) {
      for (const t of matched.slice(keep)) {
        const g = t.group || '(no group)';
        droppedByGroup[g] = (droppedByGroup[g] || 0) + 1;
      }
    }
    matched = matched.slice(0, keep);

    return { matched, groupExact: matchedGroups.size > 0 ? totalMatched : 0, total: totalMatched, droppedByGroup, knownGroups, words, RESULT_CAP };
  }
}

/**
 * Текст ответа `search_tools` — отдельно от побочных действий, чтобы его можно было
 * проверить, не поднимая сервер.
 *
 * Пустой ответ бывает ДВУХ родов, и раньше они звучали одинаково: «ничего не совпало» и
 * «всё совпавшее уже активно». Второе — не отказ, а сообщение об успехе, сказанное
 * словами отказа: модель читала «not found», переставала верить имени группы и начинала
 * подбирать синонимы, имея все её инструменты на руках. Замер 23.08.2026: третий подряд
 * `search_tools("pm")` отвечал `No tools found matching "pm"` и в той же строке
 * перечислял `pm` среди доступных групп.
 *
 * @param {object} p
 * @param {string} p.query исходный запрос
 * @param {string[]} p.activatedNames что активировано этим вызовом
 * @param {number} p.totalMatched сколько совпало ДО потолка (с учётом предиката)
 * @param {Object<string,number>} p.droppedByGroup срезано потолком, по группам
 * @param {number} p.resultCap сам потолок
 * @param {string[]} p.builtinNames совпавшие встроенные — они и так доступны
 * @param {string[]} p.alreadyActiveNames совпавшие, но активированные РАНЬШЕ
 * @param {string[]} p.knownGroups живой перечень групп каталога
 * @returns {string}
 */
export function buildSearchToolsText(p) {
  const parts = [];
  if (p.activatedNames.length) {
    parts.push(`Activated ${p.activatedNames.length} tools: ${p.activatedNames.join(', ')}.`);
  }
  if (p.totalMatched > p.activatedNames.length) {
    const rest = Object.entries(p.droppedByGroup)
      .sort((a, b) => b[1] - a[1])
      .map(([g, n]) => `${g} +${n}`)
      .join(', ');
    parts.push(
      `NOT activated: ${p.totalMatched - p.activatedNames.length} more matched but were cut at the ${p.resultCap}-tool limit (${rest}). ` +
      `They are NOT available — narrow the query to reach them, e.g. search_tools("${p.query} <what you need>").`
    );
  }
  if (p.builtinNames.length) {
    parts.push(`Already available (built-in): ${p.builtinNames.join(', ')}.`);
  }
  // «Nothing new» обязано выходить и КОГДА встроенные совпали: раньше строка
  // built-in возвращалась раньше ветки alreadyActiveNames, и повторный поиск
  // отвечал только «Already available (built-in)», скрывая, что группа УЖЕ
  // активна (инцидент PM-103, 14.09.2026 — модель так и не узнала, что
  // коннекторы активированы).
  if (!p.activatedNames.length && p.alreadyActiveNames.length) {
    parts.push(`Nothing new: all ${p.alreadyActiveNames.length} tools matching "${p.query}" are already active ` +
               `(${p.alreadyActiveNames.join(', ')}). Use them directly — no further search_tools call is needed.`);
  }
  if (parts.length) return parts.join(' ');

  const groupsMsg = p.knownGroups.length
    ? p.knownGroups.slice().sort().join(', ')
    : '(no tools loaded — select a workspace first)';
  return `No tools found matching "${p.query}". Available groups: ${groupsMsg}`;
}

// ─── PM-164: similar-name guard ──────────────────────────────────────────────

/**
 * Детерминированный поиск похожих имён: общие токены (по '_') или подстрока.
 * Сам запрошенный тул не предлагается. Сортировка: больше общих токенов — выше.
 */
export function findSimilarTools(name, catalog, limit = 3) {
  const tokens = (n) => n.split('_').filter(Boolean);
  const nameToks = new Set(tokens(name));
  const scored = [];
  for (const t of catalog) {
    if (t.name === name) continue;
    let shared = 0;
    for (const tok of tokens(t.name)) {
      if (nameToks.has(tok)) shared += 1;
      else if (t.name.includes(name) || name.includes(t.name)) shared += 1;
    }
    if (shared === 0) continue;
    scored.push({ tool: t, score: shared });
  }
  scored.sort((a, b) => b.score - a.score || a.tool.name.localeCompare(b.tool.name));
  return scored.slice(0, limit).map((s) => s.tool);
}

/**
 * Текст ошибки «тул не активен» с подсказкой похожих: активный похожий тул —
 * с ПРЯМЫМ запретом подмены; неактивный — с подсказкой активировать группу.
 */
export function buildNotActiveText(name, catalog, activeNames) {
  // PM-103: имени нет в каталоге — это не «не активен», а «такого тула нет».
  // Общий текст «is not active» модель читает как «имя неверное, попробую соседнее».
  const known = catalog.some((t) => t.name === name);
  if (!known) {
    return `Error: Unknown tool "${name}" — no such tool in the integram catalog. ` +
      `Do NOT call a different tool instead. Check the name, or use search_tools to discover the right one.`;
  }
  const similar = findSimilarTools(name, catalog);
  if (!similar.length) {
    return `Error: Tool "${name}" is not active. Use search_tools to discover and activate it first. ` +
      `Do NOT call a different tool instead — substitution answers the wrong question.`;
  }
  const activeSet = new Set(activeNames);
  const activeHits = similar.filter((t) => activeSet.has(t.name));
  const inactiveHits = similar.filter((t) => !activeSet.has(t.name));
  const lines = [`Error: Tool "${name}" is not active. Use search_tools to discover and activate it first.`];
  if (activeHits.length) {
    const listed = activeHits.map((t) => `"${t.name}" (group "${t.group}")`).join(', ');
    lines.push(
      `⚠️ Similar tool ${listed} IS ACTIVE but is a DIFFERENT tool. Do NOT call it instead of "${name}".`,
    );
  }
  if (inactiveHits.length) {
    const listed = inactiveHits.map((t) => `"${t.name}" (group "${t.group}")`).join(', ');
    const groups = [...new Set(inactiveHits.map((t) => t.group).filter(Boolean))];
    lines.push(
      `Similar inactive tool(s): ${listed}. If one of these is what you meant, activate its group first: ` +
        groups.map((g) => `search_tools("${g}")`).join(' or ') +
        ` — then call the tool by its exact name.`,
    );
  }
  return lines.join('\n');
}

/**
 * Текст REQUIRES CONFIRMATION: первой строкой имя вызываемого тула
 * (PM-164: пять подтверждений промаха прошло, потому что имя не показывалось),
 * предупреждение о похожих именах и confirmId (PM-241).
 */
export function buildHitlConfirmationText(p) {
  const message = p.message || `Pending: ${p.tool}`;
  const queueNote = p.queued > 1 ? ` (${p.queued} actions queued)` : '';
  const confirmLine = p.confirmId ? `\nconfirm id: ${p.confirmId}\nAsk the user to confirm or reject, then call confirm_action(approved=true/false, confirmId="${p.confirmId}").` : '\nAsk the user to confirm or reject, then call confirm_action(approved=true/false).';
  return (
    `⚠️ REQUIRES CONFIRMATION — tool: ${p.tool}${queueNote}\n` +
    `${message}\n\n` +
    `Before asking the user, verify the tool name above is what you intended — ` +
    `similar names are different tools (e.g. set_grant is access rights, ` +
    `set_portal_config is portal config).` +
    confirmLine
  );
}

async function handleSearchTools(query) {
  try {
    const available = t => !activeTools.has(t.name) && !BUILT_IN_NAMES.has(t.name);
    const { matched, total: totalMatched, droppedByGroup, knownGroups, words, RESULT_CAP } =
      selectTools(query, allTools, available);

    // Search built-in tools (always available, just inform)
    const matchedBuiltins = BUILT_IN_TOOL_DEFS.filter(t => {
      const text = `${t.name} ${t.description || ''}`.toLowerCase();
      return words.some(w => text.includes(w));
    });

    // Activate found backend tools
    for (const t of matched) {
      activeTools.set(t.name, t);
    }
    // Активация принадлежит текущему воркспейсу: запомнить, чтобы
    // switch_workspace её восстановил, а не сбросил (инцидент 05.09.2026).
    rememberActivation();

    if (matched.length) {
      await server.sendToolListChanged();
    }

    // Совпавшие, но активированные РАНЬШЕ. Второй прогон отбора без предиката
    // доступности — единственный способ это узнать: предикат уходит внутрь отбора и
    // делает «нет совпадений» неотличимым от «всё уже активно». Прогон чистый и идёт
    // по памяти, так что второй раз он стоит дёшево, и делается только когда
    // активировать оказалось нечего.
    const alreadyActiveNames = matched.length
      ? []
      : selectTools(query, allTools)
          .matched
          .filter(t => activeTools.has(t.name))
          .map(t => t.name);

    const text = buildSearchToolsText({
      query,
      activatedNames: matched.map(t => t.name),
      totalMatched,
      droppedByGroup,
      resultCap: RESULT_CAP,
      builtinNames: matchedBuiltins.map(t => t.name),
      alreadyActiveNames,
      knownGroups,
    });
    return { content: [{ type: 'text', text }] };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
  }
}

// ─── list_workspaces / switch_workspace handlers ─────────────────────────────

async function handleListWorkspaces() {
  try {
    await ensureAuth();
    const data = await apiFetch('/api/v2/workspaces');
    const list = (data.data || data).map(w => ({ slug: w.slug, name: w.name, role: w.role }));
    const current = workspace || '(none)';
    return {
      content: [{ type: 'text', text: `Server: ${BASE_URL}\nCurrent workspace: ${current}\n\n${list.map(w => `• ${w.slug} — ${w.name} (${w.role})`).join('\n')}` }],
    };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
  }
}

async function handleSwitchWorkspace(input) {
  if (!input) return { content: [{ type: 'text', text: 'Error: slug is required' }], isError: true };
  try {
    await ensureAuth();

    // Resolve input — try slug first, then fuzzy match by name
    const data = await apiFetch('/api/v2/workspaces');
    const list = data.data || data;
    const q = input.toLowerCase();
    let match = list.find(w => w.slug === q);
    if (!match) match = list.find(w => w.name.toLowerCase() === q);
    if (!match) match = list.find(w => w.name.toLowerCase().includes(q) || w.slug.includes(q));
    if (!match) {
      return { content: [{ type: 'text', text: `Workspace "${input}" not found. Available: ${list.map(w => `${w.slug} (${w.name})`).join(', ')}` }], isError: true };
    }

    const slug = match.slug;
    rememberActivation();
    workspace = slug;

    // Загрузить инструменты целевого воркспейса: ядро + восстановленная
    // из памяти активация (инцидент 05.09.2026 — см. блок у activationMemory).
    const { tools, restored } = await loadWorkspaceTools(slug);

    log(`Switched to workspace "${slug}", ${activeTools.size} tools loaded (${restored} restored from memory)`);

    return {
      content: [{ type: 'text', text: `Switched to workspace "${slug}". Loaded ${tools.length} tools (${activeTools.size} active${restored ? `, ${restored} restored from previous activation` : ', core only'}). Use search_tools to activate more.` }],
    };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error switching workspace: ${err.message}` }], isError: true };
  }
}

// ─── Bootstrap ───────────────────────────────────────────────────────────────

// ─── Auto-update from git ────────────────────────────────────────────────────

import { execSync } from 'child_process';
import { realpathSync } from 'fs';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AUTO_UPDATE_INTERVAL = 60 * 60 * 1000; // check every hour

function tryAutoUpdate() {
  try {
    execSync('git rev-parse --git-dir', { cwd: __dirname, stdio: 'ignore' });
    const before = execSync('git rev-parse HEAD', { cwd: __dirname, encoding: 'utf8' }).trim();
    execSync('git pull --ff-only', { cwd: __dirname, stdio: 'ignore', timeout: 15000 });
    const after = execSync('git rev-parse HEAD', { cwd: __dirname, encoding: 'utf8' }).trim();
    if (before !== after) {
      log(`Updated ${before.slice(0, 7)} → ${after.slice(0, 7)}, restarting...`);
      try { execSync('npm install --omit=dev', { cwd: __dirname, stdio: 'ignore', timeout: 30000 }); } catch {}
      // Allow pending responses to drain before exit
      log('Shutting down gracefully...');
      setTimeout(() => process.exit(0), 2000);
    }
  } catch { /* not a git repo or offline — skip */ }
}

async function main() {
  tryAutoUpdate();
  setInterval(tryAutoUpdate, AUTO_UPDATE_INTERVAL);

  // Не ждём: запуск сервера не должен зависеть от доступности реестра npm.
  checkForUpdate();
  setInterval(checkForUpdate, UPDATE_CHECK_INTERVAL_MS).unref();

  log(`integram-mcp ${PKG.version}`);
  log(`Connecting to ${BASE_URL}, workspace "${workspace || '(not set)'}"`);

  // 1. Login
  await login();

  // Сводка непрочитанных — fire-and-forget: старт не должен зависеть от бэкенда.
  checkUnreadNotifications();

  // 2. Fetch tool definitions (if workspace is set)
  if (workspace) {
    const tools = await fetchTools();
    log(`Fetched ${tools.length} tool definitions`);
    for (const t of tools) {
      if (t.group === 'core' && !BUILT_IN_NAMES.has(t.name)) activeTools.set(t.name, t);
    }
    log(`Activated ${activeTools.size} core tools + built-in tools`);
  } else {
    log('No workspace set — use list_workspaces and switch_workspace to select one');
  }

  // 4. Start stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log('MCP server running on stdio');
}

// ─── Orphan self-termination ─────────────────────────────────────────────────
//
// Клиенты (Claude Code, Cursor) не всегда убивают процессы MCP-серверов при
// закрытии сессии — известная проблема экосистемы (anthropics/claude-code#22612):
// пары «npm exec + node» остаются жить сутками с токенами доступа внутри
// (замер от юзер-репорта 01.09.2026: 96 процессов, 2,88 ГБ RSS). Клиентский баг
// нам не подвластен — завершаемся сами; механизмы и их история — в модуле
// orphan-watchdog.js. ВЫХОД ТОЛЬКО ПО СИРОТСТВУ, не по простою: инцидент
// 03.09.2026 — живая сессия не звала integram-инструменты час, сторож тихо
// сделал exit(0), у клиента «MCP error», потребовался ручной reconnect.

// Run only when executed as a program, not when imported. The guard test imports
// `selectTools` from this file; without this check the import would log in, open a
// stdio transport and hang the run. realpathSync is required, not decoration: npm
// installs the bin as a SYMLINK, so process.argv[1] is the link path while
// import.meta.url is the real one, and a naive comparison would make `npx
// integram-mcp` start nothing at all.
const isProgram = (() => {
  try {
    return process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();

if (isProgram) {
  startOrphanWatchdog();
  main().catch(err => {
    process.stderr.write(`[integram-mcp] Fatal: ${err.message}\n`);
    process.exit(1);
  });
}

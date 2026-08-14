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
    throw new Error(`API ${opts.method || 'GET'} ${path} → ${res.status}: ${text}`);
  }
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`API ${opts.method || 'GET'} ${path} → invalid JSON response (${text.length} chars)`);
  }
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
let updateNoticeDelivered = false; // приписка отдаётся один раз за процесс

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

// Приписывает сигнал к результату первого вызова инструмента — один раз.
function withUpdateNotice(result) {
  if (!updateNotice || updateNoticeDelivered) return result;
  if (!result || !Array.isArray(result.content)) return result;
  updateNoticeDelivered = true;
  return { ...result, content: [...result.content, { type: 'text', text: updateNotice }] };
}

// ─── Tool definitions cache ──────────────────────────────────────────────────

let allTools = [];                // full list from backend
const activeTools = new Map();    // name → tool def (currently exposed via MCP)

// Built-in MCP tools handled locally — never load from backend to avoid duplicates
const BUILT_IN_NAMES = new Set([
  'list_workspaces', 'switch_workspace', 'create_workspace',
  'delete_workspace', 'clone_workspace', 'search_tools', 'confirm_action',
]);

// Pending HITL state — stores the threadId for the last pending_confirmation
const pendingHitlQueue = []; // [{ threadId, action, description, createdAt }, ...]
const HITL_QUEUE_MAX_SIZE = 50;
const HITL_QUEUE_TTL_MS = 10 * 60 * 1000; // 10 minutes

async function fetchTools() {
  const data = await apiFetch(`/api/v2/${workspace}/ai/tools`);
  if (!data.ok) throw new Error(`Failed to fetch tools: ${JSON.stringify(data.error)}`);
  allTools = data.data;
  return allTools;
}

// ─── MCP Server (low-level — we pass raw JSON Schema, not Zod) ──────────────

const INSTRUCTIONS = `Integram — workspace-based platform: tables, documents, reports, automations, permissions, forms, webhooks, files, knowledge graph.
Server: ${BASE_URL}

## Getting started
1. list_workspaces → switch_workspace (required before anything else). Or create_workspace to start fresh.
2. Explore: list_tables, list_documents, list_objects for data; semantic_search for fuzzy lookup.
3. Workspace management: clone_workspace to duplicate an existing workspace; delete_workspace to permanently remove one.

## Tool discovery
Only core tools (CRUD, search, graph, comments, bulk, history) are loaded by default. Use search_tools to activate more — it reports how many tools it activated and names them:
- "schema" — create/modify tables and columns, AI/HTTP/script buttons, computed columns (LOOKUP/ROLLUP/FORMULA), validation rules, AI formula generation
- "reports" — create, run, export reports with aggregation, joins and filters
- "docs" — documents, blocks, folders, tags, sharing, versions, templates, PDF generation
- "workspace" — files, import/export, connectors, members, backups, dashboards, view/record sharing, audit log, normalizer, automations, webhooks, forms
- "portal" — portal config, catalog, carts, orders, tickets, KB articles, metrics, customer profiles, Telegram bots, @kit component catalog
- "telegram" — Telegram bot management, messaging, moderation, payments, stories, business API (subset of portal group)
- "grants" — roles, grants, row-level rules, member access (admin only)
- "codespace" — git repositories: branches, commits, files, pull requests, conflict-safe writes
- "teamchat" — rooms, topics, messages, decisions, agent metrics, W-matrix (ONA)
- "graph" — get_related, graph_query, neighborhood, shortest path, health, memory agents
- "meta-kb" — debate-based knowledge curation: start debates, parallel experts, LLM synthesis
- "kag" — knowledge-augmented generation: search, traverse, ask, import, browse, stats, clusters, anomalies
- "memory" — agent long-term memory, recall, procedures, contradictions
- "timeseries" — record, query, and list time-series data sources
- "advisor" — platform expert: docs map/search/read, tool cards, advice on schema design and best practices
- "ai" — text-to-speech synthesis (TTS): speak text, list voices, check TTS service status
- "agents" — list and delegate to external AI agents
- "pm" — project management: issues CRUD + bulk ops, checklists, sprints, board, backlog, comments CRUD, issue links, data-links (issue ↔ table/document/report), watchers, templates, trash/restore, members, CSV export, metrics (velocity, burndown, cycle time, workload), AI helpers (triage, decompose, estimate, plan sprint, detect blockers), org aggregation (portfolio, people, cross-project issues)
- "nightcall" — specification-driven execution: CNM requirements graph, formalization proposals (Extraction IR → governance decisions), artifact specifications, EffectiveSpecification resolver, execution compiler, directed-retry pipeline run, evidence verification, compliance/release decisions, waivers
- "orgs" — organizations: create, list, manage multi-workspace orgs and members
- "bulk" — bulk_create, bulk_update, bulk_delete, autofill_batch
- "comments" — comments, reactions on records
- "history" — object change history, rollback
- "objects" — move, reorder, duplicate records
- "lookups" — get lookup options, ref options
- "automations" — get automation details, webhook delivery log

---

## Column types (colTypeName for add_column / type for plan_schema)

| colTypeName | UI | Use when |
|---|---|---|
| text, string | single-line input | free-form unique values: name, title, URL, address, article code |
| phone | phone input | phone number with click-to-call: mobile, tel, телефон |
| email | email input | email address with mailto link: email, mail, почта |
| memo, multiline | textarea | long text: description, notes, comment, bio, summary |
| number | numeric input | price, cost, amount, qty, score, rating, age, salary, budget |
| date | date picker | birthday, deadline, start date, hire date |
| datetime | date+time picker | event time, created_at, timestamp, log entry |
| bool, checkbox | toggle | flag: active, paid, approved, done, published, verified |
| file | file upload | attachment, photo, image, document, avatar |
| pwd, password | masked input | password, secret, API key (stored hashed) |
| uuid | auto-generated | unique identifier |
| url | URL input | website, link, external resource |
| duration | duration input | time duration: hours, minutes (e.g. task effort) |
| currency | currency input | monetary values with currency symbol |
| percent | percentage input | percentage values (0–100) |
| rating | star rating | ratings, scores (1–5 stars) |
| status | status badge | workflow status with color coding |
| choice | choice/select | single choice from predefined options |
| http_button | clickable button | HTTP request per row (see HTTP Buttons section) |
| script_button | clickable button | JavaScript per row (see Script Buttons section) |
| ai_button | clickable button | AI prompt per row (see AI Buttons section) |
| ai | clickable button | alias for ai_button |

**IMPORTANT — semantic type inference:**
Choose type by the MEANING of the field, not just the word:
- "Phone", "Mobile", "Tel" → phone (type 30, renders with call icon)
- "Email", "Mail" → email (type 41, renders as mailto: link)
- "Website", "URL" → text (NOT number, NOT special type)
- "Price", "Salary", "Budget", "Score", "Age", "Rating" → number
- "Birthday", "Deadline", "Start date" → date
- "Description", "Notes", "Comment", "Bio" → memo
- "Active", "Done", "Published", "Verified" → bool
- "Status", "Priority", "Category", "City", "Department", "Stage", "Type", "Tags" → **NOT text!** → ref to a lookup table (see below)

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
- type — data type: text/memo/number/date/datetime/bool/file/pwd/uuid/url/duration/currency/percent/rating/status/choice/phone/email/http_button/script_button/ai_button (NOT needed if refTable is set)
- refTable — name of another table in the plan for ref/dropdown column
- multi — true for multiselect (REQUIRES refTable)
- required — true for mandatory field
- unique — true for unique constraint (article codes, SKU, email if must be unique)
- size — length limit: "100" (max chars) or "10,2" (precision,scale for numbers e.g. price with 2 decimals)

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

Computed columns auto-calculate values based on other data. Activate via search_tools("schema").

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

Set constraints on column values. Activate via search_tools("schema").
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

Block-based documents (like Notion). Activate via search_tools("documents").

- list_documents(search, folderId) — browse documents
- get_document(docId) / get_document_blocks(docId) — read content and block structure
- create_document(title, parentId) — create new doc (parentId for nesting)
- append_block(docId, text, type) — add block at end. Types: text, heading, code, quote, list, todo.
- update_block(docId, blockId, text) — modify existing block
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
- Sharing: list_doc_sharing, grant_doc_access(docId, userId, level), revoke_doc_access

## Automations

Event-driven rules: when X happens → check condition → do Y. Activate via search_tools("automations").

create_automation({ name, trigger: { type, typeId }, active?, condition, actions: [{ type, config }] })
- active: false — создать выключенной (по умолчанию включена; выключенная не встаёт в расписание и не срабатывает)
- Trigger types: on_create, on_update, on_delete, on_deadline, on_webhook, on_form_submit, schedule, manual, ai_analysis, on_metric_threshold, on_metric_silence, on_document, on_telegram_command, on_telegram_message, on_telegram_pre_checkout, on_telegram_shipping, on_telegram_payment, on_telegram_inline, on_telegram_join_request, on_telegram_business_connection, on_telegram_business_message, on_bot_chat_member
- Actions: send_notification, send_notification_to_group, update_field, create_object, delete_object, fire_webhook, run_ai_agent, run_script, run_server_function, send_telegram, run_connector, send_email, update_related_records, set_requisite, update_related, http_request, if_else, switch, transform, wait_delay, request_approval, delegate_to_agent, invoke_agent, send_invoice, telegram_forward, answer_inline_query, telegram_ban, telegram_unban, telegram_restrict, telegram_promote, telegram_approve_join, telegram_decline_join, telegram_pin, telegram_unpin, telegram_get_chat, telegram_post_story, answer_shipping, telegram_business_reply
  update_related_records: { childTypeId, matchRefReqId, targetTypeId, targetMatchReqId, targetFieldReqId, sourceFieldReqId, operation: 'add'|'subtract'|'set' } — declarative cross-table update (e.g. inventory deduction: order items → match product ref → subtract from stock)
  run_server_function: { repo, fn, args?, resultVar?, idempotencyKey?, idempotencyMinutes? } — call a codespace server function (api/<fn>.js in a workspace git repo) from an automation; this is how repo code gets put on a schedule (trigger.type: 'schedule'), which previously was impossible since server functions were reachable only over HTTP from the portal. Same sandbox, capabilities and limits as the portal path (codespace/server-fn-executor.js); capabilities are declared by a "// capabilities:" comment inside the function file. Replay protection is ON by default: repo+fn+args+record runs once per idempotencyMinutes (default 1) — keep it BELOW the schedule interval or runs are silently skipped; 0 disables it. A failed call releases its claim so the next run retries. Sets {{_server_fn_error}} / {{_server_fn_skipped}}.
  send_notification_to_group: { typeId, usernameReqId, title, body, filter?: { reqId, val } } — notifies all members of a table whose usernameReqId field is a valid Integram username; optional filter restricts to members where reqId==val (e.g. role filter)
- list_automations, get_automation (single), update_automation, delete_automation, trigger_automation (manual run), get_automation_runs (execution log)

## Permissions (admin only)

Role-based access control. Activate via search_tools("permissions").

- list_members — all workspace users with roles
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
- bulk_create(typeId, records) — create many records at once
- bulk_update(updates: [{ objId, fields }]) — update many records
- bulk_delete(objIds) — delete many records (requires confirmation)
- autofill_batch(typeId, reqId, objectIds) — run AI autofill on multiple rows

## Import / Export

Activate via search_tools("workspace").
- import_data(typeId, csv, mapping) — import CSV string into table. Auto-maps columns by header names. mapping override: { columnIndex: "colId" | "__val__" | "__skip__" }
- export_data(typeId, limit, filters) — export table to CSV format
- download_file(fileName, subdir?) — download a file from workspace storage. Returns base64 content (max 10 MB).

## Dashboards

Visual dashboards with widgets. Activate via search_tools("workspace").
- list_dashboards, get_dashboard(id), create_dashboard(name, widgets), update_dashboard, delete_dashboard

## Workspace invitations

Activate via search_tools("workspace").
- list_workspace_invitations — pending invitations (email, role, status)
- cancel_workspace_invitation(invitationId) — cancel an invitation (requires confirmation)

## Sharing

Public links for views and records. Activate via search_tools("workspace").
- share_view(viewId, typeId, expiresInDays, password) → returns share token/URL
- share_record(objId, typeId, expiresInDays) → returns share token/URL
- revoke_view_share, revoke_record_share — disable public links

## Connectors

External data integrations. Activate via search_tools("workspace").
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
- list_comments(objId), create_comment(objId, text), update_comment, delete_comment
- add_reaction(commentId, emoji), remove_reaction

## History & rollback

Activate via search_tools("history").
- get_object_history(objId) — full change log for a record
- rollback_object(objId, auditId) — restore record to state before a specific audit entry (requires confirmation)
- get_object_backlinks(objectId, limit, offset) — find all records that reference this object via ref columns or mentions

## Audit log (admin)

query_audit(type?, actor?, dateFrom?, dateTo?, action?, objectId?, typeId?, reportId?, limit?, offset?) — unified audit log across objects, schema, and reports. type: all|objects|schema|reports (default all). actor filters by username; dateFrom/dateTo are ISO timestamps. objectId narrows type=objects, typeId narrows type=schema, reportId narrows type=reports.

## Notifications

- list_notifications, mark_read(notifId), send_notification(targetUsername, title, body), delete_notification(notifId)
- get_notification_count() — number of unread notifications for current user
- notification_action(notifId, actionKey) — execute action on a notification (e.g. approve/reject a suspended automation). Requires confirmation.

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

Client-facing portal management. Activate via search_tools("portal").

**Configuration:**
- get_portal_config() — current portal config (branding, pages, modules, auth, chat, SEO)
- set_portal_config(config, active, custom_domain, merge?) — create/replace full config. With \`merge: true\` — deep-merge partial config into existing (no need to send entire config; only changed fields). **Requires confirmation.**
- update_portal_module(slug, config, moduleIndex) — update one module without overwriting others
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
- kit_list_components(version?, kind?, search?) — catalog of @kit building blocks: name, kind, one-line summary, module. Generated from the library sources at build time, so it cannot drift from the code. An empty list means an empty filter; a missing catalog comes back as a refusal (KIT_NOT_DEPLOYED / KIT_VERSION_NOT_FOUND / KIT_CATALOG_MISSING / KIT_CATALOG_BROKEN).
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

Bot config schema: { description?: "...", shortDescription?: "...", welcomeMessage?: "...", menuButton?: {type: "commands"|"web_app"|"default"}, employeeTable?: {typeId, chatIdReqId, roleReqId} }.
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

Platform expert for guidance and help. Activate via search_tools("advisor").

- ask_advisor(question, topic?) — ask about schema design, best practices, troubleshooting, feature usage. Grounded in the platform docs corpus + current workspace schema. topic: schema/reports/automations/portal/documents/permissions/import/dashboards/integrations/general
- list_platform_capabilities() — full list of Integram features by category (data, columns, analytics, automations, documents, integrations, security, portal, AI, graph)
- docs_map(area?, module?, query?) — map of the platform docs corpus: what documents exist, what each is about, when it last changed. Start here.
- docs_search(query, area?, limit?) — hybrid search over doc fragments; returns citations (path#section). Empty result means "not in what was retrieved", NOT "not in the platform"
- docs_read(path, section?, offset?, maxChars?) — read a doc or one section in full; paginated via nextOffset
- docs_tool(name? | query? | group?) — card for a platform tool: purpose, params, risk tier. Read live from the tool catalog, so counts and names always match the code

Use advisor when user asks "help", "how to", "what can you do", "best practice", or needs guidance on platform features.
Never state a capability, count, or setting you did not confirm via docs_* — say "not covered in the docs" instead.

## Teamchat (internal messaging)

Internal messaging with rooms, topics, and decisions. Activate via search_tools("teamchat").

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

Create Excel files from raw data. Available via search_tools("workspace").

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
const EN_DESCRIPTIONS = {
  // Lookups
  get_lookup: 'Get dropdown values for a lookup table by ID. Returns an array of records with id and display name.',
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
  patch_file: 'Replace one unique snippet of text in a repository file. Preferred over commit_file for editing existing files: no need to send the whole file, works at any file size, rarely conflicts. oldStr must occur exactly once — lengthen the anchor if it does not. Matching is exact, including indentation.',
  // Notifications
  get_notification_count: 'Get the number of unread notifications for the current user. Returns: { count }.',
  // Workspace
  get_workspace: 'Get current workspace details: name, slug, plan, settings (admin only).',
  get_template: 'Get details of a workspace template by ID (schema, description). Returns: { id, slug, name, description, icon, category, schema }.',
  list_workspace_templates: 'List available templates for creating new workspaces.',
  create_workspace_from_template: 'Create a new workspace from a template. Provide templateId, name, and slug.',
  // Decisions
  create_decision: 'Create a new team decision with optional linked chat room. Returns decision ID and metadata.',
  search_teamchat: 'Search teamchat messages by topic, room, or keyword. Returns matching messages with metadata.',
  search_similar_decisions: 'Find decisions semantically similar to a query or decision ID. Returns ranked results with similarity scores.',
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
  // Meta-KB
  mk_revoke_entity: 'Revoke all knowledge base entities derived from a specified decision. Use when a decision was found to be incorrect. Returns { revoked: number, message: string }.',
  mk_list_debates: 'List recent expert debates in the workspace. Returns { debates: Array, total: number }. Each debate has id, question, consensus, verdict, created_by, created_at.',
  mk_start_debate: 'Start an expert debate on a question. Internal workspace agents evaluate the question in parallel, then cross-examine, then synthesize a consensus. Returns { opinions, crossTurns, consensus }.',
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
  export_type: 'Export a table definition (schema + data) by typeId.',
  bki_import: 'Import BKI format (tables + data from previous export). Provide content as JSON string.',
  list_qa_results: 'List QA test sessions and their results.',
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
  mk_delete_rule: 'Delete a Meta-KB validation rule by ID (requires confirmation).',
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
  if (name === 'confirm_action') return handleConfirmAction(args?.approved === true);

  // Check workspace is set
  if (!workspace) {
    return { content: [{ type: 'text', text: 'No workspace selected. Use list_workspaces to see available workspaces, then switch_workspace to select one.' }], isError: true };
  }

  // Regular tool call → proxy to backend
  if (!activeTools.has(name)) {
    return { content: [{ type: 'text', text: `Error: Tool "${name}" is not active. Use search_tools to discover and activate it first.` }], isError: true };
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
      // Evict expired entries
      const now = Date.now();
      while (pendingHitlQueue.length && pendingHitlQueue[0].createdAt < now - HITL_QUEUE_TTL_MS) {
        pendingHitlQueue.shift();
      }
      // Cap queue size
      if (pendingHitlQueue.length >= HITL_QUEUE_MAX_SIZE) {
        pendingHitlQueue.shift();
      }
      pendingHitlQueue.push({
        threadId: result.threadId,
        action: name,
        description: result.message || `Pending: ${name}`,
        createdAt: now,
      });
      const queueNote = pendingHitlQueue.length > 1 ? ` (${pendingHitlQueue.length} actions queued)` : '';
      return {
        content: [{ type: 'text', text: `⚠️ REQUIRES CONFIRMATION: ${result.message}${queueNote}\n\nAsk the user to confirm or reject, then call confirm_action(approved=true/false).` }],
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
        const resumeData = await apiFetch(`/api/v2/${workspace}/ai/tool`, {
          method: 'POST',
          body: JSON.stringify({
            name,
            args: { ...originalArgs, elicitedAnswer: elicitResult.content },
            threadId: data?.data?.threadId,
            schemaCtx: null,
          }),
          headers: { 'Content-Type': 'application/json' },
        });
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
    return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
  }
}

// ─── confirm_action handler ──────────────────────────────────────────────────

async function handleConfirmAction(approved) {
  if (pendingHitlQueue.length === 0) {
    return { content: [{ type: 'text', text: 'No pending action to confirm.' }], isError: true };
  }

  const pending = pendingHitlQueue.shift();
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
      const data = await apiFetch(`/api/v2/${workspace}/ai/mcp-resume`, {
        method: 'POST',
        body: JSON.stringify({ threadId: pending.threadId, approved }),
      });
      msg = data.data?.message || (approved ? 'Action confirmed and executed.' : 'Action rejected.');
    }

    const remaining = pendingHitlQueue.length > 0 ? ` (${pendingHitlQueue.length} more pending — call confirm_action again)` : '';
    return { content: [{ type: 'text', text: msg + remaining }] };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error confirming action: ${err.message}` }], isError: true };
  }
}

// ─── create_workspace handler ─────────────────────────────────────────────────

async function handleCreateWorkspace({ name, slug, template, templateId }) {
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
    const data = await apiFetch('/api/v2/workspaces', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!data.ok) throw new Error(JSON.stringify(data.error || data));

    const ws = data.data;
    log(`Created workspace "${ws.slug}" (id=${ws.id}, db=${ws.dbName})`);

    // Auto-switch to the new workspace
    workspace = ws.slug;
    const tools = await fetchTools();
    activeTools.clear();
    for (const t of tools) {
      if (t.group === 'core' && !BUILT_IN_NAMES.has(t.name)) activeTools.set(t.name, t);
    }
    await server.sendToolListChanged();

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
    while (pendingHitlQueue.length && pendingHitlQueue[0].createdAt < now - HITL_QUEUE_TTL_MS) {
      pendingHitlQueue.shift();
    }
    if (pendingHitlQueue.length >= HITL_QUEUE_MAX_SIZE) {
      pendingHitlQueue.shift();
    }
    pendingHitlQueue.push({
      threadId: `delete-ws-${slug}`,
      action: 'delete_workspace',
      description: `Permanently delete workspace "${slug}" and ALL its data`,
      createdAt: now,
      onApprove: async () => {
        await ensureAuth();
        const data = await apiFetch(`/api/v2/workspaces/${slug}`, { method: 'DELETE' });
        if (!data.ok) throw new Error(JSON.stringify(data.error || data));
        log(`Deleted workspace "${slug}"`);
        if (workspace === slug) {
          workspace = '';
          activeTools.clear();
          await server.sendToolListChanged();
        }
        _pendingDeleteSlug = null;
        return `Workspace "${slug}" and all its data have been permanently deleted.`;
      },
      onReject: () => { _pendingDeleteSlug = null; },
    });
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

async function handleCloneWorkspace({ sourceSlug, name, slug, includeDocuments, includeMembers }) {
  if (!sourceSlug || !name || !slug) {
    return { content: [{ type: 'text', text: 'Error: sourceSlug, name, and slug are required' }], isError: true };
  }
  try {
    await ensureAuth();
    const body = { name, slug };
    if (includeDocuments !== undefined) body.includeDocuments = includeDocuments;
    if (includeMembers !== undefined) body.includeMembers = includeMembers;
    const data = await apiFetch(`/api/v2/workspaces/${sourceSlug}/clone`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!data.ok) throw new Error(JSON.stringify(data.error || data));

    const ws = data.data;
    log(`Cloned workspace "${sourceSlug}" → "${ws.slug}" (id=${ws.id})`);

    // Auto-switch to the new workspace
    workspace = ws.slug;
    const tools = await fetchTools();
    activeTools.clear();
    for (const t of tools) {
      if (t.group === 'core' && !BUILT_IN_NAMES.has(t.name)) activeTools.set(t.name, t);
    }
    await server.sendToolListChanged();

    return {
      content: [{ type: 'text', text: `Workspace "${sourceSlug}" cloned into "${ws.name}" (slug: ${ws.slug}). Automatically switched to it. ${activeTools.size} core tools loaded.` }],
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
const GROUP_ALIASES = {
  документ: 'docs', документы: 'docs', docs: 'docs', doc: 'docs',
  отчёт: 'reports', отчеты: 'reports', отчёты: 'reports', report: 'reports', reports: 'reports',
  схема: 'schema', таблица: 'schema', колонк: 'schema', schema: 'schema',
  права: 'grants', роли: 'grants', доступ: 'grants', grants: 'grants',
  автоматизац: 'workspace', вебхук: 'workspace', коннектор: 'workspace', форм: 'workspace',
  файл: 'workspace', файлы: 'workspace',
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
  agents: 'agents', агент: 'agents', делегир: 'agents',
  orgs: 'orgs', организаци: 'orgs', org: 'orgs',
  automations: 'automations', automation: 'automations',
  history: 'history', истори: 'history',
  lookups: 'lookups', lookup: 'lookups', справочник: 'lookups',
  'meta-kb': 'meta-kb', metakb: 'meta-kb', дебат: 'meta-kb', дискусси: 'meta-kb',
  pm: 'pm', проект: 'pm', задач: 'pm', спринт: 'pm', канбан: 'pm', бэклог: 'pm', issue: 'pm', sprint: 'pm', backlog: 'pm', board: 'pm',
  найткол: 'nightcall', требован: 'nightcall', спецификац: 'nightcall', верификац: 'nightcall',
  формализ: 'nightcall', formaliz: 'nightcall', governance: 'nightcall', evidence: 'nightcall',
};

async function handleSearchTools(query) {
  try {
    const q = query.toLowerCase();
    const words = q.split(/\s+/).filter(Boolean);
    // Live group catalog — single source of truth, new backend groups appear automatically
    const knownGroups = [...new Set(allTools.map(t => t.group).filter(g => g && g !== 'core'))];

    const available = t => !activeTools.has(t.name) && !BUILT_IN_NAMES.has(t.name);
    const toolText = t => `${t.name} ${t.description || ''} ${t.group || ''}`.toLowerCase();

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
        if (alias.startsWith(w) || w.startsWith(alias)) matchedGroups.add(group);
      }
    }

    let matched;
    if (matchedGroups.size > 0) {
      matched = allTools.filter(t => available(t) && matchedGroups.has(t.group));
      // Also include tools from other groups where ALL words match
      const groupSet = new Set(matched.map(t => t.name));
      const extra = allTools.filter(t =>
        !groupSet.has(t.name) && available(t) && words.every(w => toolText(t).includes(w)));
      matched = matched.concat(extra);
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

    // Cap at 30
    matched = matched.slice(0, 30);

    // Search built-in tools (always available, just inform)
    const matchedBuiltins = BUILT_IN_TOOL_DEFS.filter(t => {
      const text = `${t.name} ${t.description || ''}`.toLowerCase();
      return words.some(w => text.includes(w));
    });

    // Activate found backend tools
    for (const t of matched) {
      activeTools.set(t.name, t);
    }

    if (matched.length) {
      await server.sendToolListChanged();
    }

    const parts = [];
    if (matched.length) parts.push(`Activated ${matched.length} tools: ${matched.map(t => t.name).join(', ')}.`);
    if (matchedBuiltins.length) parts.push(`Already available (built-in): ${matchedBuiltins.map(t => t.name).join(', ')}.`);

    if (!parts.length) {
      const groupsMsg = knownGroups.length
        ? knownGroups.sort().join(', ')
        : '(no tools loaded — select a workspace first)';
      return {
        content: [{ type: 'text', text: `No tools found matching "${query}". Available groups: ${groupsMsg}` }],
      };
    }

    return { content: [{ type: 'text', text: parts.join(' ') }] };
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
    workspace = slug;

    // Reload tools for the new workspace
    const tools = await fetchTools();
    activeTools.clear();
    for (const t of tools) {
      if (t.group === 'core' && !BUILT_IN_NAMES.has(t.name)) activeTools.set(t.name, t);
    }

    await server.sendToolListChanged();
    log(`Switched to workspace "${slug}", ${activeTools.size} core tools loaded`);

    return {
      content: [{ type: 'text', text: `Switched to workspace "${slug}". Loaded ${tools.length} tools (${activeTools.size} core active). Use search_tools to activate more.` }],
    };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error switching workspace: ${err.message}` }], isError: true };
  }
}

// ─── Bootstrap ───────────────────────────────────────────────────────────────

// ─── Auto-update from git ────────────────────────────────────────────────────

import { execSync } from 'child_process';
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

main().catch(err => {
  process.stderr.write(`[integram-mcp] Fatal: ${err.message}\n`);
  process.exit(1);
});

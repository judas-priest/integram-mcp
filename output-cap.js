/**
 * Кэп размера ответа тула в MCP-прокси.
 *
 * Инцидент 19.10.2026: pm_list_issues(limit:100) вернул 242 КБ одним куском —
 * клиент (Claude Code) выгрузил ответ в файл, модель его не видела. Прокси —
 * единственное место, через которое проходят ВСЕ 779 тулов, и единственное,
 * где кэпа не было: встроенный агент режет своё (runner.js
 * _compactToolResultRaw, 16000 символов). Логика здесь — копия runner-версии
 * с двумя отличиями:
 *   1) бюджет 60000 символов (лимит клиента ~100 КБ — оставлен запас);
 *   2) списки режутся ТОЛЬКО при переборе бюджета, а не по счёту (runner режет
 *      items>20 безусловно — для MCP это ломало бы легальные списки вроде
 *      get_lookup с 80 опциями).
 *
 * Контракт усечённого ответа (валидный JSON):
 *   _truncated: true        — это часть, не полный ответ;
 *   _compacted              — человекочитаемо: «Показано K из N», «X КБ из Y КБ»;
 *   _howToContinue          — как дочитать, с настоящими именами аргументов;
 *   _tool, _originalSize    — кто и сколько отдавал;
 *   total/offset/has_more/nextOffset/nextCursor — вынесены наверх ДО усечения,
 *                             иначе тонут в обрезанном хвосте JSON.
 * Синхронизировать с backend/src/api/v2/modules/ai/agent/runner.js при смене
 * контракта (_truncated/_compacted) — там тот же конверт для встроенного агента.
 */
const OUTPUT_MAX_CHARS = 60000;

// Размер ответа pivot/aggregate/group растёт от кардинальности: offset не
// помогает, лечится только сужением фильтра.
const CARDINALITY_RE = /^(pivot|aggregate|group)_/;

// Поля пагинации, которые обязаны пережить усечение.
const PROMOTED_FIELDS = ['total', 'offset', 'limit', 'has_more', 'nextOffset', 'nextCursor'];

const fmtKb = (n) => `${Math.max(1, Math.round(n / 1024))} КБ`;

// Частичный кусок режется ПОСЛЕ эскейпинга, а не фиксированной арифметикой:
// 58 000 кавычек при JSON.stringify превращаются в ~116 000 символов
// (\" \\), фиксированный slice(0, N) бюджет пробивает. Итеративно сжимаем,
// пока сериализованный кусок не влезет.
function fitPartial(raw, budget) {
  let s = raw.slice(0, budget);
  while (s.length > 500 && JSON.stringify(s).length > budget) {
    s = s.slice(0, Math.max(500, Math.floor(s.length * budget / JSON.stringify(s).length) - 64));
  }
  return s;
}

function envelope(toolName, fields, originalSize) {
  return {
    ...fields,
    // Контрактные ключи — ПОСЛЕ спреда данных: результат тула не может
    // подделать пометку «это часть» собственным _truncated/_tool/_compacted.
    _truncated: true,
    _tool: String(toolName ?? '').slice(0, 120),
    _compacted: fields._compacted
      ?? `Показана часть: ${fmtKb(fields.partial?.length ?? 0)} из ${fmtKb(originalSize)}. Это НЕ полный ответ.`,
    _originalSize: originalSize,
  };
}

function howToContinue(toolName, result, keptCount = null) {
  if (CARDINALITY_RE.test(toolName)) {
    return 'Число групп/значений превышает лимит вывода. Сузь запрос фильтром — повторение с offset или большим limit не поможет.';
  }
  if (keptCount === 0) {
    // Ни один item не влез целиком — offset вести в пустоту, честный совет — сузить.
    return 'Записи слишком велики для лимита вывода. Сузь выборку фильтром или запроси меньше полей.';
  }
  if (typeof result?.nextOffset === 'number') {
    return `Текст обрезан. Вызови ${toolName} снова с offset=${result.nextOffset} — продолжение с этого места.`;
  }
  if (result?.truncated === true && typeof result?.path === 'string') {
    // read_blob: continuation-подсказка по его собственному протоколу
    // (baseCommit при частичном чтении приходит null — про правку не упоминаем)
    return `Файл обрезан. Вызови read_blob снова с offset=(прежний offset||0)+длина полученного content, чтобы дочитать.`;
  }
  if (Array.isArray(result?.items) && result.items.length > 0) {
    // keptCount — сколько реально влезло; result.items.length — сколько было.
    const next = (Number(result.offset) || 0) + (keptCount ?? result.items.length);
    return `Повтори ${toolName} с offset=${next} — следующая страница. Вместо большого limit сужай выборку фильтрами/поиском: много адресных запросов лучше одного широкого.`;
  }
  return `Ответ обрезан по размеру. Повтори ${toolName} с более узким фильтром или поиском: много адресных запросов лучше одного широкого.`;
}

export function compactToolResult(toolName, result) {
  // toolName приходит невалидированным из JSON-RPC — зажимаем до любого
  // использования (входит в _tool и в тексты _howToContinue).
  toolName = String(toolName ?? '').slice(0, 120);
  // Строковые ответы: маленькие — как есть, большие — partial-конверт.
  if (typeof result === 'string') {
    if (result.length <= OUTPUT_MAX_CHARS) return result;
    return JSON.stringify(envelope(toolName, { partial: fitPartial(result, OUTPUT_MAX_CHARS - 2000) }, result.length));
  }
  if (result == null || typeof result !== 'object') {
    return JSON.stringify(result ?? null);
  }

  const raw = JSON.stringify(result, null, 2);
  if (raw.length <= OUTPUT_MAX_CHARS) return raw;

  const promoted = {};
  for (const f of PROMOTED_FIELDS) {
    const v = result[f];
    if (v === undefined) continue;
    // Строковые токены (nextCursor) зажимаем: гигантский курсор от сбойного
    // тула не должен пробивать бюджет ни в одной ветке.
    promoted[f] = typeof v === 'string' && v.length > 1000 ? v.slice(0, 1000) : v;
  }

  let fields = null;

  // Текстовые тела (read_file/download_file — как в runner.js): метаданные
  // сохраняем целиком, режем только тело. Сжатие ПОСЛЕ сериализации:
  // newlines/кавычки текста удваиваются в JSON, арифметика по сырым символам
  // бюджет пробивает.
  const textKey = result.extractedText != null ? 'extractedText' : result.base64 != null ? 'base64' : null;
  if (textKey) {
    const meta = { ...result };
    delete meta[textKey];
    delete meta._compacted; // данные тула не перебивают честную пометку конверта
    const fullText = String(result[textKey]);
    const metaJson = JSON.stringify(meta, null, 2);
    const textBudget = Math.max(OUTPUT_MAX_CHARS - metaJson.length - textKey.length - 200, 500);
    if (fullText.length > textBudget) {
      let shown = fullText.slice(0, textBudget);
      const build = (s) => JSON.stringify(envelope(toolName, {
        _compacted: `Текст обрезан: показано ${fmtKb(s.length)} из ${fmtKb(fullText.length)}.`,
        ...meta,
        [textKey]: s,
        _howToContinue: textKey === 'extractedText'
          ? `Текст обрезан. Вызови ${toolName} снова с offset=${(Number(result.offset) || 0) + s.length} — продолжение с этого места.`
          : `Содержимое обрезано (${fmtKb(s.length)} из ${fmtKb(fullText.length)}). Загружай файл по частям меньшего размера.`,
      }, raw.length));
      let out = build(shown);
      while (out.length > OUTPUT_MAX_CHARS && shown.length > 500) {
        shown = shown.slice(0, Math.max(500, Math.floor(shown.length * OUTPUT_MAX_CHARS / out.length) - 64));
        out = build(shown);
      }
      fields = JSON.parse(out); // конверт уже собран — идёт в общий страж ниже
    }
  }

  // Списки: держим префикс items, влезающий в бюджет вместе с прочими полями
  // и конвертом. Режем только при переборе бюджета, не по счёту.
  if (!fields && Array.isArray(result.items) && result.items.length > 0) {
    const kept = [];
    let size = JSON.stringify({ ...result, items: kept, ...promoted }, null, 2).length + 800;
    for (const item of result.items) {
      kept.push(item);
      size += JSON.stringify(item, null, 2).length + 2;
      if (size > OUTPUT_MAX_CHARS) { kept.pop(); break; }
    }
    // result-owned _compacted не перебивает наш (спред результата — после него,
    // поэтому выкидываем ключ из копии до спреда)
    const { _compacted: drop, ...rest } = result;
    fields = {
      _compacted: `Показано ${kept.length} из ${result.items.length} записей (полный ответ ${fmtKb(raw.length)}). Это НЕ полный ответ.`,
      ...promoted,
      ...rest,
      items: kept,
      _howToContinue: howToContinue(toolName, result, kept.length),
    };
  }

  if (!fields) {
    const partial = fitPartial(raw, OUTPUT_MAX_CHARS - 2000);
    fields = {
      _compacted: `Показана часть: ${fmtKb(partial.length)} из ${fmtKb(raw.length)}. Это НЕ полный ответ.`,
      ...promoted,
      partial,
      _howToContinue: howToContinue(toolName, result),
    };
  }

  let out = JSON.stringify(envelope(toolName, fields, raw.length));
  // Единственный честный выход при переборе: конверт с куском сырого JSON;
  // бюджет partial урезается на размер promoted, чтобы и здесь влезть.
  if (out.length > OUTPUT_MAX_CHARS) {
    const promotedJson = JSON.stringify(promoted);
    const partial = fitPartial(raw, Math.max(OUTPUT_MAX_CHARS - 2000 - promotedJson.length, 500));
    out = JSON.stringify(envelope(toolName, {
      _compacted: `Показана часть: ${fmtKb(partial.length)} из ${fmtKb(raw.length)}. Это НЕ полный ответ.`,
      ...promoted,
      partial,
      _howToContinue: howToContinue(toolName, result),
    }, raw.length));
  }
  return out;
}

// ── Кэп details ОШИБКИ ──
// Стратегия «мелкое выживает»: служебные поля (baseCommit, hint, счётчики) —
// это forensic passport ошибки, без которого агент не может продолжить
// (канон Anthropic: усечение рулит текстом). Громоздкие блоки (конфликты
// мержа, дампы) режутся, выброшенные ключи честно перечисляются.
const ERROR_DETAILS_BUDGET = 20000;
const SMALL_VALUE_CHARS = 1000;

export function compactErrorDetails(details, budget = ERROR_DETAILS_BUDGET) {
  if (details == null || typeof details !== 'object') return details;
  if (Array.isArray(details)) {
    // Массив — форма ошибки, не словарь: форму сохраняем, бюджету подчиняем
    // (одиночный срез по соотношению размеров, с доводкой — эскейп-тяжёлые
    // элементы могут надуть сериализацию после среза).
    let arr = details;
    for (let i = 0; i < 20 && arr.length > 1 && JSON.stringify(arr, null, 2).length > budget; i++) {
      arr = arr.slice(0, Math.max(1, Math.floor(arr.length * budget / JSON.stringify(arr, null, 2).length)));
    }
    return arr;
  }
  // 'undefined' вместо падения: JSON.stringify(undefined) === undefined —
  // живой объект (не из JSON.parse) не должен ломать весь error-путь.
  const size = (v) => (JSON.stringify(v, null, 2) ?? 'undefined').length;
  const entries = Object.entries(details);
  const small = entries.filter(([, v]) => size(v) <= SMALL_VALUE_CHARS);
  const big = entries.filter(([, v]) => size(v) > SMALL_VALUE_CHARS);
  const out = {};
  const dropped = [];
  let used = 2;
  // Сначала всё мелкое (пока влезает) — служебные поля важнее громоздких.
  for (const [k, v] of small) {
    const s = size(v);
    if (used + s > budget) { dropped.push(k); continue; }
    out[k] = v;
    used += s + k.length + 6;
  }
  // Потом крупные — по остаточному бюджету.
  for (const [k, v] of big) {
    const s = size(v);
    if (used + s > budget) { dropped.push(k); continue; }
    out[k] = v;
    used += s + k.length + 6;
  }
  if (dropped.length) {
    // Наши ключи — последними: данные details не могут подделать сигнал
    // (собственный _droppedDetails/_hint из details затирается здесь).
    out._droppedDetails = dropped;
    out._hint = `Часть деталей ошибки урезана по размеру: ${dropped.join(', ')}. Мелкие служебные поля (baseCommit и т.п.) сохранены — без них продолжение невозможно.`;
  }
  return out;
}

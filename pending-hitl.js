// pending-hitl.js — очередь ожидающих подтверждения действий MCP-прокси.
//
// Инцидент 08.09.2026 (PM-241, воркспейс nevod-vision): в очереди висело два
// действия, confirm_action исполнял ПЕРВОЕ — старейшее, — хотя подтверждали
// последнее. Ответ «Удалено 5 объектов» уехал от чужого ожидания, запрошенные
// записи остались живы. Отсюда: каждое ожидание несёт короткий id,
// confirm_action подтверждает ПО ИМЕНИ, без имени берёт единственное
// ожидание, а при нескольких — отказывается гадать: исполнение необратимо.

/**
 * Положить ожидание в очередь: сперва выкинуть протухшие, затем держать
 * потолок (при переполнении падает старейший). Мутирует queue.
 *
 * @param {Array} queue  — общий массив очереди
 * @param {object} entry — { id, threadId, action, description, createdAt, onApprove?, onReject? }
 * @param {object} opts  — { now, ttlMs, maxSize }
 * @returns {object} тот же entry
 */
export function enqueuePending(queue, entry, { now, ttlMs, maxSize }) {
  while (queue.length && queue[0].createdAt < now - ttlMs) queue.shift();
  if (queue.length >= maxSize) queue.shift();
  queue.push(entry);
  return entry;
}

/**
 * Взять ожидание к исполнению и УБРАТЬ из очереди — «взял» значит «исполнил»,
 * повторное подтверждение того же id невозможно.
 *
 * confirmId назван  → берётся ровно он; не найден — отказ с перечнем живых id.
 * confirmId опущен  → единственное ожидание берётся (старое поведение для
 * случая «подтверждают сразу»); при нескольких — отказ: угадывать нельзя.
 *
 * @param {Array} queue — общий массив очереди (мутируется)
 * @param {string|undefined} confirmId
 * @param {object} [opts] — { now, ttlMs }
 * @returns {{ entry: object, remaining: number } | { error: string, available: string[] }}
 */
export function takePending(queue, confirmId, { now = Date.now(), ttlMs } = {}) {
  if (ttlMs != null) {
    while (queue.length && queue[0].createdAt < now - ttlMs) queue.shift();
  }
  const available = queue.map((e) => e.id);
  if (!queue.length) return { error: 'EMPTY', available: [] };
  if (confirmId == null) {
    if (queue.length > 1) return { error: 'AMBIGUOUS', available };
    return { entry: queue.shift(), remaining: queue.length };
  }
  const idx = queue.findIndex((e) => e.id === confirmId);
  if (idx === -1) return { error: 'UNKNOWN_CONFIRM_ID', available };
  return { entry: queue.splice(idx, 1)[0], remaining: queue.length };
}

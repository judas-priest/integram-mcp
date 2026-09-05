/**
 * Память активации инструментов по воркспейсу.
 *
 * Инцидент 05.09.2026: switch_workspace субагента делал activeTools.clear()
 * + core-only — сброс был ГЛОБАЛЬНЫМ (activeTools — Map на весь процесс
 * сервера), и неядерная активация пропадала у всех сеансов разом. Фикс:
 * переключение воркспейса запоминает неядерную активацию уходящего воркспейса
 * и восстанавливает активацию целевого. Сброс до ядра остаётся только там,
 * где памяти о воркспейсе нет (первое посещение).
 *
 * Чистые функции без зависимостей от сервера: index.js зовёт их со своим
 * Map (slug → Set имён), списком активных имён и списком выкачанных
 * дефиниций инструментов. Проверяются tests/activation-memory.test.js.
 */

/** Неядерные имена из перечня активных: built-in живут всегда отдельно. */
export function nonCoreNames(activeNames, builtInNames) {
  const builtIn = new Set(builtInNames);
  return activeNames.filter((n) => !builtIn.has(n));
}

/** Запомнить текущую неядерную активацию под слагом. Пустой слаг игнорируется. */
export function rememberActivation(map, slug, activeNames, builtInNames) {
  if (!slug) return;
  map.set(slug, new Set(nonCoreNames(activeNames, builtInNames)));
}

/** Забыть воркспейс (удаление): сохранённая активация мёртвого не нужна. */
export function forgetActivation(map, slug) {
  map.delete(slug);
}

/**
 * Восстановить сохранённую активацию целевого воркспейса: для каждой
 * выкачанной дефиниции, чьё имя сохранено, звать setActive. Возвращает число
 * восстановленных. Имена, которых в выкачке нет (инструмент исчез из
 * воркспейса), молча пропускаются — их всё равно нечем исполнить.
 */
export function applyActivation(map, slug, availableTools, setActive) {
  const saved = map.get(slug);
  if (!saved?.size) return 0;
  let restored = 0;
  for (const t of availableTools) {
    if (saved.has(t.name)) {
      setActive(t);
      restored += 1;
    }
  }
  return restored;
}

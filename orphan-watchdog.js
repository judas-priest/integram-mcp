/**
 * Самозавершение осиротевшего MCP-сервера. См. комментарий в index.js перед
 * вызовом startOrphanWatchdog: клиенты (Claude Code, Cursor) не всегда убивают
 * процессы при закрытии сессии (anthropics/claude-code#22612).
 *
 * Четыре независимых механизма:
 *  1. stdin закрылся — клиент мёртв (для stdio-транспорта это канал жизни);
 *  2. ppid сменился — родитель умер, сироту переусыновил init;
 *  3. ppid РОДИТЕЛЯ сменился («дедушка») — обёртка npm exec осиротела.
 *     Случай юзер-репорта 05.09.2026: клиент запускает `npx integram-mcp`,
 *     пара «npm exec + node» переусыновляется init'ом ЦЕЛИКОМ — у node ppid
 *     не меняется (родитель — npm exec, он жив), stdin не закрывается
 *     (обёртка трубу ребёнку не пробрасывает). Смерть настоящего клиента
 *     видна только на уровень выше: родитель осиротел, его родителем стал
 *     init. Linux-only (читаем /proc), на других платформах проверка
 *     молча пропускается;
 *
 * ВАЖНО: `process.ppid` в Node кэшируется на старте и после смерти родителя
 * НЕ меняется (замер 05.09.2026: дочерний процесс после SIGKILL родителя
 * печатает прежний ppid каждые 200 мс). Прежний механизм 2 в index.js,
 * сравнивавший process.ppid с исходным, был мёртвым кодом. Живой ppid
 * читаем из /proc/<pid>/stat на каждом тике.
 *  4. SIGTERM/SIGINT — явный выход (node с хендлерами SDK глотает сигналы).
 *
 * Живой клиент переносит смерть сервера безболезненно: stdio-сервер
 * перезапускается по требованию при следующем вызове.
 */
import { readFileSync } from 'fs';

/** Поле 4 из /proc/<pid>/stat — ppid. comm в скобках может содержать пробелы,
 *  поэтому режем по последнему ')'. Процесс отсутствует → null. */
export function readPpid(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return Number(stat.slice(stat.lastIndexOf(')') + 2).trim().split(' ')[1]);
  } catch {
    return null;
  }
}

/**
 * @param {object} [opts]
 * @param {boolean} [opts.watchStdin=true] — в тестах stdin бывает уже закрыт;
 *   false отключает механизмы 1 и 4-частично (SIGTERM/SIGINT остаются).
 * @param {number} [opts.intervalMs=30000]
 */
export function startOrphanWatchdog({ watchStdin = true, intervalMs = 30_000 } = {}) {
  const ppid0 = readPpid(process.pid) ?? process.ppid;
  // ppid нашего родителя («дедушка») на старте. null — не Linux или родитель
  // уже исчез; тогда остаётся кэшированный process.ppid и stdin.
  const gp0 = readPpid(ppid0);

  if (watchStdin) {
    process.stdin.on('end', () => process.exit(0));
    process.stdin.on('close', () => process.exit(0));
    process.on('SIGTERM', () => process.exit(0));
    process.on('SIGINT', () => process.exit(0));
  }

  const timer = setInterval(() => {
    const ppid = readPpid(process.pid);
    if (ppid === null) {
      // Не Linux (/proc нет) — остаётся кэшированная копия, хуже не стало.
      if (process.ppid !== ppid0) process.exit(0);
      return;
    }
    if (ppid !== ppid0) process.exit(0);
    // Родитель переусыновлён (его родителем стал init) или исчез между
    // проверками — пара осиротела вместе.
    if (gp0 !== null && readPpid(ppid) !== gp0) process.exit(0);
  }, intervalMs);
  timer.unref();
  return timer;
}

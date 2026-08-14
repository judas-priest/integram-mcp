#!/usr/bin/env node
/**
 * Сторож: всякий номер версии, названный в документации, обязан совпадать
 * с package.json.
 *
 * Зачем устройством, а не памятью. Документация теперь предлагает запускать
 * сервер закреплённой версией (`npx -y integram-mcp@X.Y.Z`) — плавающий
 * `@latest` npx кэширует по строке запуска и годами отдаёт старую сборку.
 * Плата за закрепление одна: номер живёт в четырёх файлах и разъезжается на
 * первом же выпуске, а разъехавшись, зовёт людей на прошлую версию — молча,
 * потому что старый номер в npm существует и запускается.
 *
 * Прогон: npm test (и prepublishOnly — до выкладки, а не после).
 */

import { existsSync, readFileSync } from 'fs';
import { dirname, join, relative } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const pkgDir = join(here, '..');
const repoRoot = join(pkgDir, '..');

const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const expected = pkg.version;

// Скрипт живёт в двух местах: в монорепозитории (где номер назван ещё в двух
// документах) и в публичном зеркале judas-priest/integram-mcp, куда уезжает
// только каталог пакета. Различаем по метке монорепозитория, а не по «файла
// нет — ну и ладно»: иначе переименование тихо выключит сторожа.
const IN_MONOREPO = existsSync(join(repoRoot, 'backend/package.json'));

const DOCS = [
  join(pkgDir, 'README.md'),
  ...(IN_MONOREPO ? [join(repoRoot, 'README.md'), join(repoRoot, 'docs/AI_AGENT_GUIDE.md')] : []),
];

const problems = [];

// Ловим и `integram-mcp@0.7.2`, и `"integram-mcp@0.7.2"` в кусках JSON.
const PIN = new RegExp(`${pkg.name}@(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?)`, 'g');

for (const file of DOCS) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    problems.push(`${relative(repoRoot, file)}: файл не найден — перечень сторожа устарел`);
    continue;
  }
  const found = [...text.matchAll(PIN)];
  if (!found.length) {
    problems.push(`${relative(repoRoot, file)}: не назван ни один номер ${pkg.name}@X.Y.Z`);
    continue;
  }
  for (const m of found) {
    if (m[1] !== expected) {
      const line = text.slice(0, m.index).split('\n').length;
      problems.push(`${relative(repoRoot, file)}:${line}: ${m[0]} — в package.json ${expected}`);
    }
  }
}

// Версия, которую сервер сообщает клиенту, обязана читаться из package.json.
// Захардкоженная копия уже отставала: сидела на 0.5.0 сквозь выпуски 0.6.0 и 0.7.0.
const index = readFileSync(join(pkgDir, 'index.js'), 'utf8');
const serverInfo = /new Server\(\s*\{[^}]*version:\s*([^,}]+)/.exec(index);
if (!serverInfo) {
  problems.push('index.js: не нашёл version в serverInfo — сторож ослеп, поправь образец');
} else if (!/PKG\.version/.test(serverInfo[1])) {
  problems.push(`index.js: serverInfo.version = ${serverInfo[1].trim()} — должно быть PKG.version`);
}

if (problems.length) {
  console.error(`Версии разъехались (package.json: ${expected}):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}

console.log(`Версии согласованы: ${pkg.name}@${expected} в ${DOCS.length} документах и serverInfo${IN_MONOREPO ? '' : ' (зеркало)'}.`);

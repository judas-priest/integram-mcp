#!/usr/bin/env bash
# Правка того, что уходит в пакет integram-mcp, обязана поднимать номер версии
# в том же коммите. Скрипт поднимает его сам и добавляет в коммит.
#
# Что считается «уходит в пакет». Перечень читается из поля `files` в
# package.json — ЕДИНСТВЕННОЕ объявление, плюс `package.json` и `README.md`,
# которые npm кладёт в архив всегда. Захардкоженный перечень («ровно три
# файла: index.js») стал ложным молча, когда в `files` добавился второй файл:
# 0.7.36 вышла без activation-memory.js, потому что сторож за ней не следил.
# Теперь следит за тем, что объявлено. Полноту `files` относительно импортов
# index.js стережёт scripts/check-versions.mjs (npm test / prepublishOnly).
#
# Чего в пакете НЕТ, вопреки ожиданию: определения инструментов. `TOOL_DEFS`
# живут в бэкенде, а сервер забирает их по сети при запуске
# (`fetchTools()` → `GET /api/v2/:db/ai/tools`, index.js:228). Значит новый
# инструмент сам по себе выкладки пакета НЕ требует — требует её правка
# подсказки в `mcp-server/index.js`, то есть шаг 6 перечня в
# `.claude/rules/ai-tools.md`. Отсюда и образец: следим за файлами пакета,
# а не за `agent/index.js`.
#
# Почему поднимаем сами, а не отказываем в коммите (как это ПЫТАЕТСЯ делать
# `portal-kit/scripts/require-version-bump.sh` — он в lefthook.yml не
# зарегистрирован и не исполнялся ни разу; у @kit работает только прогон
# `test/version-bump.test.js`). У @kit цена ошибки
# необратима: адрес версии неизменяем и раздаётся год. Здесь цена обратима —
# npm просто не даст выложить занятый номер, — а забытый бамп стоил суток
# расхождения выложенного с репозиторием (0.7.0 отставала от кода на три
# коммита и никто не заметил). Поэтому номер поднимается без участия человека.
#
# Уже поднятый вручную номер скрипт не трогает: minor и major остаются
# решением человека. Обход на один коммит: SKIP_MCP_BUMP=1 git commit ...
set -euo pipefail

[ "${SKIP_MCP_BUMP:-}" = "1" ] && exit 0

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

PKG=mcp-server/package.json
LOCK=mcp-server/package-lock.json

FILED=$(node -e '
  const p = JSON.parse(require("fs").readFileSync("mcp-server/package.json", "utf8"));
  for (const f of p.files || []) console.log(f);
' | sed 's|^|mcp-server/|')
if [ -z "$FILED" ]; then
  echo "integram-mcp: поле files в mcp-server/package.json пусто или отсутствует — сторож ослеп" >&2
  exit 1
fi

# Файлы, попадающие в архив npm. package-lock.json и scripts/ в архив не идут:
# их правка выкладки не меняет и бампа не требует.
STAGED=$(git diff --cached --name-only --diff-filter=ACMR \
  -- $FILED mcp-server/README.md "$PKG" || true)
[ -n "$STAGED" ] || exit 0

read_version() { node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).version" 2>/dev/null || echo ''; }

NEW=$(git show ":$PKG" 2>/dev/null | read_version)
OLD=$(git show "HEAD:$PKG" 2>/dev/null | read_version)

if [ -z "$NEW" ] || [ -z "$OLD" ]; then
  echo "integram-mcp: не удалось прочитать версию из $PKG (индекс: «$NEW», HEAD: «$OLD»)" >&2
  exit 1
fi

# Человек уже поднял номер — не вмешиваемся.
if [ "$NEW" != "$OLD" ]; then
  echo "integram-mcp: версия поднята вручную, $OLD → $NEW"
  exit 0
fi

# Хук правит рабочее дерево и добавляет правку в индекс — значит он обязан
# отказаться, если в тех же файлах уже лежит незастейдженное. Иначе `git add`
# заметает в коммит то, чего человек туда не клал: проверено 14.08.2026 —
# черновая строка из неподготовленного README.md уехала в коммит целиком.
# Тот же случай накрывает частичный набор (`git add -p`): файл со
# застейдженным и незастейдженным куском виден в этом же перечне.
DIRTY=$(git diff --name-only -- "$PKG" "$LOCK" mcp-server/README.md README.md docs/AI_AGENT_GUIDE.md || true)
if [ -n "$DIRTY" ]; then
  echo "" >&2
  echo "integram-mcp: правится содержимое пакета, номер надо поднять — но в файлах," >&2
  echo "которые для этого правятся, есть незастейдженные изменения:" >&2
  echo "" >&2
  echo "$DIRTY" | sed 's/^/  /' >&2
  echo "" >&2
  echo "Подхватить их в коммит хук не вправе. Подготовьте их (git add) либо" >&2
  echo "уберите (git stash) и повторите коммит." >&2
  exit 1
fi

BUMPED=$(node -e '
  const v = process.argv[1].match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!v) { console.error("не разобрал версию: " + process.argv[1]); process.exit(1); }
  console.log(`${v[1]}.${v[2]}.${+v[3] + 1}`);
' "$OLD")

# package.json
node -e '
  const fs = require("fs");
  const [file, version] = process.argv.slice(1);
  const p = JSON.parse(fs.readFileSync(file, "utf8"));
  p.version = version;
  fs.writeFileSync(file, JSON.stringify(p, null, 2) + "\n");
' "$PKG" "$BUMPED"

# package-lock.json — правим два поля напрямую. `npm install --package-lock-only`
# здесь не годится: хук не должен зависеть от доступности сети.
node -e '
  const fs = require("fs");
  const [file, version] = process.argv.slice(1);
  const l = JSON.parse(fs.readFileSync(file, "utf8"));
  l.version = version;
  if (l.packages && l.packages[""]) l.packages[""].version = version;
  fs.writeFileSync(file, JSON.stringify(l, null, 2) + "\n");
' "$LOCK" "$BUMPED"

# Закреплённые номера в документации. Их согласованность стережёт
# scripts/check-versions.mjs — здесь перечень обязан совпадать с тамошним.
DOCS="mcp-server/README.md README.md docs/AI_AGENT_GUIDE.md"
for f in $DOCS; do
  [ -f "$f" ] || { echo "integram-mcp: нет файла $f — перечень закреплённых номеров устарел" >&2; exit 1; }
  sed -i "s/integram-mcp@${OLD//./\\.}/integram-mcp@$BUMPED/g" "$f"
done

# Только свои файлы поимённо: в репозитории одновременно работают несколько
# сессий, `git add -A` увёл бы в коммит чужое.
git add "$PKG" "$LOCK" $DOCS

node mcp-server/scripts/check-versions.mjs >/dev/null

echo "integram-mcp: $OLD → $BUMPED (правится содержимое пакета)"
echo "$STAGED" | sed 's/^/  /'
echo "  Выложится само после пуша в master: зеркало → judas-priest/integram-mcp → npm."

#!/bin/bash
# Integram MCP — быстрая установка для Claude Code
# Запусти: bash setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Integram MCP Setup ==="
echo ""

# URL
echo "Куда подключаемся?"
echo "  1) ai2o.online (облако)"
echo "  2) localhost:8081 (локальный сервер)"
echo "  3) Свой URL"
read -p "Выбор [1]: " url_choice
url_choice=${url_choice:-1}

case $url_choice in
  1) URL="https://ai2o.online" ;;
  2) URL="http://localhost:8081" ;;
  3) read -p "URL: " URL ;;
  *) URL="https://ai2o.online" ;;
esac

# Credentials
read -p "Email: " EMAIL
read -sp "Пароль: " PASSWORD
echo ""

# Workspace (optional)
read -p "Воркспейс (slug, Enter чтобы пропустить): " WORKSPACE

# Client
echo ""
echo "Для какого клиента настраиваем?"
echo "  1) Claude Code"
echo "  2) Claude Desktop"
echo "  3) Cursor"
read -p "Выбор [1]: " client_choice
client_choice=${client_choice:-1}

case $client_choice in
  1)
    # Claude Code
    CMD="claude mcp add integram -e INTEGRAM_URL=$URL -e INTEGRAM_EMAIL=$EMAIL -e INTEGRAM_PASSWORD=$PASSWORD"
    if [ -n "$WORKSPACE" ]; then
      CMD="$CMD -e INTEGRAM_WORKSPACE=$WORKSPACE"
    fi
    CMD="$CMD -- node $SCRIPT_DIR/index.js"

    echo ""
    echo "Выполняю: claude mcp add integram ..."
    eval "$CMD"
    echo ""
    echo "Готово! Перезапусти разговор в Claude Code."
    ;;

  2)
    # Claude Desktop
    CONFIG_DIR="$HOME/.config/claude-desktop"
    CONFIG_FILE="$CONFIG_DIR/claude_desktop_config.json"
    mkdir -p "$CONFIG_DIR"

    ENV_JSON="{\"INTEGRAM_URL\": \"$URL\", \"INTEGRAM_EMAIL\": \"$EMAIL\", \"INTEGRAM_PASSWORD\": \"$PASSWORD\""
    if [ -n "$WORKSPACE" ]; then
      ENV_JSON="$ENV_JSON, \"INTEGRAM_WORKSPACE\": \"$WORKSPACE\""
    fi
    ENV_JSON="$ENV_JSON}"

    MCP_ENTRY="{\"command\": \"node\", \"args\": [\"$SCRIPT_DIR/index.js\"], \"env\": $ENV_JSON}"

    if [ -f "$CONFIG_FILE" ]; then
      echo ""
      echo "Добавь в $CONFIG_FILE в секцию mcpServers:"
      echo "  \"integram\": $MCP_ENTRY"
    else
      cat > "$CONFIG_FILE" << CONF
{
  "mcpServers": {
    "integram": $MCP_ENTRY
  }
}
CONF
      echo ""
      echo "Создан $CONFIG_FILE"
    fi
    echo "Перезапусти Claude Desktop."
    ;;

  3)
    # Cursor
    echo ""
    echo "Добавь в .cursor/mcp.json:"
    echo ""
    ENV_JSON="{\"INTEGRAM_URL\": \"$URL\", \"INTEGRAM_EMAIL\": \"$EMAIL\", \"INTEGRAM_PASSWORD\": \"$PASSWORD\""
    if [ -n "$WORKSPACE" ]; then
      ENV_JSON="$ENV_JSON, \"INTEGRAM_WORKSPACE\": \"$WORKSPACE\""
    fi
    ENV_JSON="$ENV_JSON}"
    echo "{
  \"mcpServers\": {
    \"integram\": {
      \"command\": \"node\",
      \"args\": [\"$SCRIPT_DIR/index.js\"],
      \"env\": $ENV_JSON
    }
  }
}"
    ;;
esac

#!/bin/zsh

# このファイルをダブルクリックすると、
# このプロジェクトの説明ボードを既定ブラウザで開きます。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
open "${SCRIPT_DIR}/presentation-board.html"

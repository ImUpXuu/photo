#!/bin/bash
# photo 仓库自动更新 + 加密相册同步（systemd timer 每小时调用）
# 代码以 GitHub photo 仓库为准，本地一律 reset --hard（服务器的 data/media/.env 都是 gitignore 文件，不受影响）
set -euo pipefail
cd /root/photo

BEFORE=$(git rev-parse HEAD 2>/dev/null || echo none)
git fetch origin main --quiet
git reset --hard origin/main --quiet
AFTER=$(git rev-parse HEAD)

# 若有私有照片仓库（可选，未来接私有 repo 时把 /root/gallery-src 变成 git clone 即可）
if [ -d /root/gallery-src/.git ]; then
  git -C /root/gallery-src pull --ff-only --quiet || true
fi

node /root/photo/gallery-api/sync-secure.mjs

if [ "$BEFORE" != "$AFTER" ]; then
  echo "[update] photo repo ${BEFORE:0:7} -> ${AFTER:0:7}, restart gallery-api"
  systemctl restart gallery-api
fi

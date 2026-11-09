#!/usr/bin/env bash
# Сборка Debian-пакета: dist/sign-everything_<version>_all.deb
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(grep -m1 '^APP_VERSION = ' Sign-everything.py | cut -d'"' -f2)"
if [ -z "$VERSION" ]; then
    echo "Не удалось определить APP_VERSION" >&2
    exit 1
fi

DIST="$ROOT/dist"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 0755 "$STAGE"
mkdir -p "$DIST"

install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/share/sign-everything"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/icons/hicolor/256x256/apps"
install -d "$STAGE/usr/share/doc/sign-everything"

install -m 0755 Sign-everything.py "$STAGE/usr/share/sign-everything/Sign-everything.py"
install -m 0755 packaging/sign-everything-launcher "$STAGE/usr/bin/sign-everything"
install -m 0644 packaging/sign-everything.desktop "$STAGE/usr/share/applications/sign-everything.desktop"
install -m 0644 packaging/sign-everything.png "$STAGE/usr/share/icons/hicolor/256x256/apps/sign-everything.png"

install -m 0644 README.md "$STAGE/usr/share/doc/sign-everything/README.md"
install -m 0644 THIRD_PARTY_NOTICES.md "$STAGE/usr/share/doc/sign-everything/THIRD_PARTY_NOTICES.md"
install -m 0644 LICENSE "$STAGE/usr/share/doc/sign-everything/LICENSE"
gzip -9n -c packaging/deb/changelog > "$STAGE/usr/share/doc/sign-everything/changelog.gz"

cat > "$STAGE/usr/share/doc/sign-everything/copyright" <<'EOF'
Sign Everything
Copyright (C) 2026 Tripswarlock

License: GPL-3.0-only
This package is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3.

On Debian systems the complete text of the GPL-3.0 is available in
/usr/share/common-licenses/GPL-3.
EOF

SIZE="$(du -sk "$STAGE" | cut -f1)"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@SIZE@/$SIZE/g" \
    packaging/deb/control.in > "$STAGE/DEBIAN/control"
install -m 0755 packaging/deb/postinst "$STAGE/DEBIAN/postinst"
install -m 0755 packaging/deb/postrm "$STAGE/DEBIAN/postrm"

(
    cd "$STAGE"
    find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums
)
chmod 0644 "$STAGE/DEBIAN/control" "$STAGE/DEBIAN/md5sums"

OUT="$DIST/sign-everything_${VERSION}_all.deb"
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$OUT" >/dev/null
echo "DEB: $OUT"
dpkg-deb --info "$OUT" | sed -n '1,18p'

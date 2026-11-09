#!/usr/bin/env bash
# Сборка RPM-пакета: dist/sign-everything-<version>-1.noarch.rpm
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(grep -m1 '^APP_VERSION = ' Sign-everything.py | cut -d'"' -f2)"
if [ -z "$VERSION" ]; then
    echo "Не удалось определить APP_VERSION" >&2
    exit 1
fi
SPEC_VERSION="$(grep -m1 '^Version:' packaging/rpm/sign-everything.spec | awk '{print $2}')"
if [ "$VERSION" != "$SPEC_VERSION" ]; then
    echo "Версия приложения ($VERSION) не совпадает с версией в spec ($SPEC_VERSION)" >&2
    exit 1
fi
if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "rpmbuild не найден. Установите пакет rpm/rpm-build." >&2
    exit 1
fi

DIST="$ROOT/dist"
STAGE="$(mktemp -d)"
TOP="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$TOP"' EXIT
mkdir -p "$DIST" "$DIST/rpm"

SRC="$STAGE/sign-everything-$VERSION"
mkdir -p "$SRC"
cp Sign-everything.py README.md LICENSE THIRD_PARTY_NOTICES.md "$SRC/"
cp -a packaging "$SRC/packaging"
tar -czf "$DIST/sign-everything-$VERSION.tar.gz" -C "$STAGE" "sign-everything-$VERSION"

rpmbuild -bb packaging/rpm/sign-everything.spec \
    --define "_topdir $TOP" \
    --define "_sourcedir $DIST" \
    --define "_rpmdir $DIST/rpm" \
    --define "_builddir $TOP/build" \
    --define "debug_package %{nil}" \
    --define "_build_id_links none"

RPM_FILE="$(find "$DIST/rpm" -name '*.rpm' -type f | head -n 1)"
if [ -z "$RPM_FILE" ]; then
    echo "RPM не собран" >&2
    exit 1
fi
cp "$RPM_FILE" "$DIST/sign-everything-${VERSION}-1.noarch.rpm"
echo "RPM: $DIST/sign-everything-${VERSION}-1.noarch.rpm"
rpm -qip "$DIST/sign-everything-${VERSION}-1.noarch.rpm" | sed -n '1,18p'

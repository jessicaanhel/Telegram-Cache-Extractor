#!/bin/bash
# Собирает TelegramCacheExtractor.app (PyInstaller) и упаковывает его в .dmg с ярлыком на /Applications.
# Запуск: ./build_macos.sh (из корня репозитория, с активным venv, где стоит pip install -r requirements.txt)
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="TelegramCacheExtractor"
VOL_NAME="Telegram Cache Extractor"

if ! command -v pyinstaller >/dev/null 2>&1; then
    echo "PyInstaller не найден, устанавливаю..."
    pip install pyinstaller
fi

if [ ! -f icon.icns ]; then
    echo "icon.icns не найден - генерирую временную иконку из icons/telegram_icon.png"
    rm -rf icon.iconset
    mkdir icon.iconset
    for size in 16 32 128 256 512; do
        sips -z "$size" "$size" icons/telegram_icon.png --out "icon.iconset/icon_${size}x${size}.png" >/dev/null
        sips -z "$((size * 2))" "$((size * 2))" icons/telegram_icon.png --out "icon.iconset/icon_${size}x${size}@2x.png" >/dev/null
    done
    iconutil -c icns icon.iconset -o icon.icns
    rm -rf icon.iconset
fi

echo "Собираю $APP_NAME.app..."
rm -rf build dist "${APP_NAME}.spec"
pyinstaller --onedir --windowed --icon=icon.icns \
    --add-data "icons:icons" --add-data "icon.icns:." \
    --name "$APP_NAME" app.py

echo "Собираю .dmg..."
rm -rf dmg_staging "${APP_NAME}.dmg"
mkdir dmg_staging
cp -R "dist/${APP_NAME}.app" dmg_staging/
ln -s /Applications dmg_staging/Applications

hdiutil create -volname "$VOL_NAME" -srcfolder dmg_staging -ov -format UDZO "${APP_NAME}.dmg"
rm -rf dmg_staging

echo ""
echo "Готово: ${APP_NAME}.dmg"

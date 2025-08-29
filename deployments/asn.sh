#!/bin/bash

# Создаем временную директорию
TMP_DIR=$(mktemp -d)
OUTPUT_FILE="combined_asn_list.txt"

# URLs файлов (используем raw.githubusercontent.com для прямого доступа к содержимому)
URLS=(
    "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/Malicious/ASN.txt"
    "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/VPN%20Providers/ASN.txt"
    "https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/main/VPS%20Providers/ASN.txt"
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt"
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ASN.txt"
)

echo "Скачивание и обработка ASN списков..."

# Инициализируем файл
> "$TMP_DIR/all_asn.txt"

# Скачиваем и обрабатываем каждый файл
for url in "${URLS[@]}"; do
    echo "Обработка: $url"
    
    # Скачиваем файл с проверкой на ошибки
    if curl -s --fail "$url" > "$TMP_DIR/temp_file.txt"; then
        # Извлекаем ASN номера (только цифры после AS)
        grep -Eo 'AS[0-9]+' "$TMP_DIR/temp_file.txt" | sed 's/AS//' >> "$TMP_DIR/all_asn.txt"
    else
        echo "Ошибка при скачивании: $url"
    fi
done

# Проверяем, есть ли данные
if [ ! -s "$TMP_DIR/all_asn.txt" ]; then
    echo "Ошибка: Не удалось получить данные ни из одного источника"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Удаляем дубликаты и сортируем
sort -u "$TMP_DIR/all_asn.txt" > "$TMP_DIR/unique_asn.txt"

# Сохраняем количество ASN перед очисткой временной директории
ASN_COUNT=$(wc -l < "$TMP_DIR/unique_asn.txt" | tr -d ' ')

# Преобразуем в строку с запятыми (только цифры)
ASN_LIST=$(tr '\n' ',' < "$TMP_DIR/unique_asn.txt" | sed 's/,$//')

# Сохраняем результат
echo "$ASN_LIST" > "$OUTPUT_FILE"

# Очищаем временные файлы
rm -rf "$TMP_DIR"

echo "Готово! Результат сохранен в $OUTPUT_FILE"
echo "Найдено уникальных ASN: $ASN_COUNT"
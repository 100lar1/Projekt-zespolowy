#!/bin/bash

# Skrypt do inicjalizacji bazy danych dla systemu wyborczego
# Uruchom w katalogu głównym projektu

echo "🚀 Inicjalizacja bazy danych systemu wyborczego..."

# Sprawdź czy kontenery są uruchomione
if ! docker ps | grep -q "mysql-db"; then
    echo "❌ Kontener MySQL nie jest uruchomiony!"
    echo "Uruchom najpierw: docker-compose up -d"
    exit 1
fi

# Czekaj aż MySQL będzie gotowy
echo "⏳ Oczekiwanie na gotowość MySQL..."
sleep 10

# Sprawdź połączenie z bazą danych
echo "🔍 Sprawdzanie połączenia z bazą danych..."
docker exec mysql-db mysql -u user -ppassword -e "SELECT 1;" > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "❌ Nie można połączyć się z bazą danych!"
    echo "Sprawdź czy kontener MySQL działa poprawnie."
    exit 1
fi

# Importuj strukturę bazy danych
echo "📦 Importowanie struktury bazy danych..."
docker exec -i mysql-db mysql -u user -ppassword moja_baza < wybory_portal.sql

if [ $? -eq 0 ]; then
    echo "✅ Struktura bazy danych została zaimportowana pomyślnie!"
else
    echo "❌ Błąd podczas importowania struktury bazy danych!"
    exit 1
fi

# Sprawdź czy tabele zostały utworzone
echo "🔍 Weryfikacja utworzonych tabel..."
TABLES=$(docker exec mysql-db mysql -u user -ppassword moja_baza -e "SHOW TABLES;" | grep -v "Tables_in")

echo "📋 Utworzone tabele:"
echo "$TABLES"

# Sprawdź czy wszystkie wymagane tabele istnieją
REQUIRED_TABLES=("users" "elections" "candidates" "vote_tokens")
MISSING_TABLES=()

for table in "${REQUIRED_TABLES[@]}"; do
    if ! echo "$TABLES" | grep -q "^$table$"; then
        MISSING_TABLES+=("$table")
    fi
done

if [ ${#MISSING_TABLES[@]} -eq 0 ]; then
    echo "✅ Wszystkie wymagane tabele zostały utworzone!"
    echo ""
    echo "🌐 System jest gotowy! Możesz teraz odwiedzić:"
    echo "   http://localhost:8080"
    echo ""
    echo "👤 Domyślne konto administratora:"
    echo "   PESEL: admin"
    echo "   Hasło: admin"
    echo ""
else
    echo "❌ Brakujące tabele: ${MISSING_TABLES[*]}"
    echo "Sprawdź plik wybory_portal.sql"
    exit 1
fi

echo ""
echo "🔧 Dodatkowe polecenia:"
echo "   Restart kontenerów: docker-compose restart"
echo "   Logi PHP: docker-compose logs php"
echo "   Logi MySQL: docker-compose logs mysql"
echo "   Zatrzymaj: docker-compose down"
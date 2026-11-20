# Zmiana API — Render

Ten katalog zawiera serwer API do wdrożenia w Render. W GitHubie utwórz puste repozytorium, wybierz **Add file → Upload files**, dodaj wszystkie cztery pliki z tego katalogu do głównego katalogu repozytorium i zatwierdź (**Commit changes**). Następnie w Render wybierz **New → Blueprint**, połącz repozytorium i uruchom Blueprint.

Blueprint tworzy bezpłatny serwer API oraz bezpłatną bazę PostgreSQL do testów. Po wdrożeniu adres usługi będzie w formacie `https://...onrender.com`. W aplikacji wpisz go w **Ustawienia serwera**.

Kod pierwszego konta zatrudniającego Render wygeneruje jako zmienną `ZM_EMPLOYER_CODE` usługi `zmiana-api`. Odczytaj go w ustawieniach Environment tej usługi i wpisz przy rejestracji zatrudniającego. Dopiero to konto może tworzyć konta pracowników.

Plan testowy Render usypia serwer po bezczynności, a bezpłatna baza wygasa po 30 dniach. Nie używaj tej bazy dla prawdziwych danych pracowników ani wypłat.

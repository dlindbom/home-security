# Plan: Tabbed HTML-rapport med AI-analys

## Mål
Bygga om HTML-rapporten till EN sida med flikar (tabs) istället för två separata sidor.
Lägg till en AI-analys som sammanfattar och tolkar alla resultat inklusive trafikanalysen.

## Struktur – 4 flikar

### Flik 1: 🛡️ Översikt (startsida)
- Sammanlagd riskpoäng (SVG-cirkel)
- Spårbarhet / uniqueness bits
- Resultatsammanfattning (gröna/gula/röda)
- **AI-analys** – en sammanfattande text som tolkar alla resultat:
  - Övergripande säkerhetsläge
  - Viktigaste observationerna från trafikanalysen (kodsignaturer, IP-klassificering, VPN, baseline)
  - Viktigaste observationerna från nätverkskontrollerna
  - Viktigaste observationerna från fingerprint-analysen
  - Konkreta rekommendationer prioriterade efter allvarlighetsgrad
- Verdict-meddelande

### Flik 2: 🔒 Nätverkssäkerhet
- Alla nuvarande nätverkssektioner: Brandvägg, WiFi, DNS, Öppna portar, Aktiva anslutningar, Processanalys
- Samma kollapsibla kort-design som idag

### Flik 3: 📡 Trafikanalys
- Kodsignaturer
- IP-klassificering
- VPN-status
- Baseline-diff
- Samma kort-design

### Flik 4: 🔍 Fingeravtryck
- Alla webbläsar-fingerprint-analyser (User Agent, Canvas, WebGL, WebRTC, etc.)
- Migrerad från fingerprint.html in i rapporten (körs live i webbläsaren)

## Tekniska ändringar

### 1. scanner/report.py – `export_html()`
- Ny tab-navigation med CSS (inga extra dependencies)
- Tab-switching via vanilla JS (`data-tab` attribut, class toggle)
- Flytta fingerprint-JS till flik 4 istället för att blanda med nätverksresultat
- Generera AI-analystext i Python baserat på findings-data
- Ny funktion `_generate_ai_summary(findings)` som bygger sammanfattningen

### 2. scanner/report.py – `_generate_ai_summary()`
- Tar in alla findings
- Analyserar per kategori och severity
- Bygger en strukturerad text med:
  - Övergripande betyg
  - Trafikanalys-tolkning (VPN, signaturer, okända IP:er)
  - Nätverkssäkerhet-tolkning
  - Fingerprint-tolkning (spårbarhet)
  - Prioriterad åtgärdslista

### 3. scanner/__main__.py
- Ta bort öppning av fingerprint.html (allt i en sida nu)
- Behåll `--no-browser` flaggan

### 4. Filer som INTE ändras
- scanner/checks.py – orörd
- scanner/utils.py – orörd
- scanner/fingerprint.html – behålls som backup men öppnas inte längre
- tests/test_checks.py – orörd

## CSS-design för tabs
- Tab-bar med horisontella flikar längst upp
- Aktiv flik markerad med accent-färg
- Smooth fade-transition mellan flikar
- Samma mörka tema (#0c0e14)
- Responsiv – funkar på mobil också

## AI-analys design
- Kort i översikten med rubrik "🤖 Analys"
- Strukturerad text med ikoner per avsnitt
- Färgkodade nyckelord (grönt/gult/rött)
- Inte AI-genererad i realtid – deterministisk analys baserad på findings-data

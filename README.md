# HTTP2TCP Local Agent

`hrnco/http2tcp-local-agent` je ľahký lokálny HTTP server bežiaci v Dockeri, ktorý umožňuje webovým alebo cloudovým aplikáciám bezpečne komunikovať so zariadeniami v LAN cez TCP – bez potreby otvárať porty, nastavovať VPN alebo exponovať LAN smerom do internetu.

Hlavná idea:

> Cloud / Web → Browser → http://localhost:<port> → HTTP2TCP Local Agent → TCP → LAN zariadenie

Cloud tak nikdy nepotrebuje priamy prístup do vnútornej siete zákazníka.

---

## Prehľad

HTTP2TCP Local Agent funguje ako:

- **HTTP server na localhoste** – prijíma požiadavky z prehliadača alebo lokálneho klienta
- **TCP klient do LAN** – nadväzuje výstupné TCP spojenia na zariadenia v lokálnej sieti (tlačiarne, pokladnice, terminály, IoT…)
- **kryptograficky párovaný agent** – pri inicializácii prijme verejný kľúč webovej aplikácie a následne komunikuje výhradne šifrovane a autorizovane s touto aplikáciou

Typické LAN zariadenia:

- ESC/POS LAN tlačiarne (port 9100)
- ZPL etikety (Zebra, port 9100)
- fiskálne pokladnice (napr. FiskalPRO API na porte 3000)
- špecializované TCP zariadenia (skenery, IoT gatewaye…)

---

## Typické scenáre použitia

- Cloudový fakturačný/POS systém, ktorý potrebuje tlačiť účtenky na lokálnej tlačiarni
- Webová aplikácia, ktorá musí komunikovať s LAN pokladnicou cez proprietárny TCP protokol
- Centrálne webové UI (na vzdialenom serveri), ktoré riadi lokálne TCP zariadenia bez VPN
- Situácie, kde IT oddelenie nedovolí otvárať porty ani nastavovať port-forwarding, ale povoľuje bežný výstupný HTTP/HTTPS

---

## Architektúra (high-level)

Tok komunikácie:

1. **Cloud / Web aplikácia** – beží na vzdialenom serveri, komunikuje cez HTTPS s prehliadačom
2. **Prehliadač (používateľ)** – vykonáva JavaScript, ktorý posiela požiadavky na `http://localhost:<port>`
3. **HTTP2TCP Local Agent** – prijíma HTTP požiadavky a podľa konfigurácie nadväzuje TCP spojenia do LAN
4. **LAN zariadenia** – tlačiarne, pokladnice, terminály a iné TCP zariadenia

Schematicky:

```
Cloud / Web App
        |
        |  HTTPS
        v
   Web Browser
        |
        |  HTTP (localhost)
        v
HTTP2TCP Local Agent
        |
        |  TCP
        v
    LAN Device
```

---

## Bezpečnostný model

### Sieťový model

HTTP2TCP Local Agent je navrhnutý tak, aby:

- bežal typicky na `127.0.0.1:<port>` (nie je dostupný zo siete)
- používal len **výstupné** TCP spojenia smerom do LAN
- nikdy neotváral priamy prístup do LAN pre internet
- fungoval aj za „striktnejším firewallom“, ktorý povoľuje len:
    - výstupný HTTPS pre prehliadač
    - lokálnu komunikáciu na `localhost`
    - internú komunikáciu v LAN

Nie je potrebný:

- port-forwarding
- verejná IP adresa
- vstupné pravidlá vo firewalle
- VPN prístup do siete zákazníka

### Kryptografická inicializácia

Bezpečnosť je postavená na dvojfázovom procese:

#### 1. Inicializačná (bootstrap) fáza

Po prvom spustení:

1. Agent čaká na **jednorazovú inicializačnú požiadavku**
2. Webová aplikácia poskytne:
    - IP adresu zariadenia v LAN
    - TCP port zariadenia
    - svoj **verejný kľúč**
3. Agent:
    - vygeneruje vlastný **súkromný kľúč** (zostáva len lokálne) a poskytne webovej časti verejný kľúč
    - vytvorí alebo odvodí **session key**
    - uloží konfiguráciu a párovanie lokálne
    - prepne sa do „encrypted-only“ režimu

Keďže verejný kľúč nie je citlivý, úvodná inicializácia môže prebiehať bez šifrovania.

#### 2. Prevádzková (encrypted-only) fáza

Po úspešnej inicializácii:

- agent prestane akceptovať nešifrované alebo „nepárované“ požiadavky
- komunikuje iba s webovou aplikáciou, ktorá dokáže používať dohodnutý kryptografický mechanizmus
- všetky payloady sú šifrované (E2E medzi webom a agentom)
- do LAN odchádzajú len RAW TCP dáta (agent ich neinterpretuje)

Re-párovanie agenta je možné len manuálnym zásahom (napr. vymazaním lokálnej konfigurácie).

---

## Rýchly štart (Docker)

Odporúčaný spôsob spustenia:

```bash
docker run -d   --restart=unless-stopped   --name http2tcp-agent   -p 127.0.0.1:34279:80   hrnco/http2tcp-local-agent
```

Po spustení je agent dostupný na:

```
http://localhost:34279
```

V produkčnom prostredí sa odporúča:

- viazať sa len na `127.0.0.1`
- používať fixný port (napr. 34279)
- neinzerovať endpoint do LAN

---

## Základný princíp API

Bude doplnené.

---

## Čo tento projekt nie je

HTTP2TCP Local Agent nie je:

- VPN server ani sieťový tunel
- univerzálny port-forwarder z internetu do LAN
- SSH náhrada
- nástroj na vzdialenú správu PC

Je to **špecializovaný, lokálny, kryptograficky párovaný agent** na bezpečné TCP operácie, riadené webovou aplikáciou.

---

## Poďakovanie

Tento projekt vznikol ako reakcia na konkrétnu potrebu zákazníka v oblasti komunikácie s LAN zariadeniami.

Ďakujeme spoločnostiam:

Cykloon — https://www.cykloon.com/

Trialexa — https://trialexa.com/

za podporu a umožnenie otvorenia projektu ako open-source.

## Licencia

Bude doplnené.

# HTTP2TCP Local Agent

`hrnco/http2tcp-local-agent` je ľahký lokálny HTTP server bežiaci v Dockeri, ktorý umožňuje webovým alebo cloudovým aplikáciám bezpečne komunikovať so zariadeniami v LAN cez TCP – bez potreby otvárať porty, nastavovať VPN alebo exposeovať LAN smerom do internetu.

Hlavná idea:

> Cloud / Web → Browser → http://localhost:<port> → HTTP2TCP Local Agent → TCP → LAN zariadenie

Cloud tak nikdy nepotrebuje priamy prístup do vnútornej siete zákazníka.

---

## Prehľad

HTTP2TCP Local Agent funguje ako:

- **HTTP server na localhoste** – prijíma požiadavky z browsera alebo lokálneho klienta
- **TCP klient do LAN** – nadväzuje outbound TCP spojenia na zariadenia v lokálnej sieti (tlačiarne, pokladnice, terminály, IoT…)
- **kryptograficky párovaný agent** – po inicializácii komunikuje so svojou webovou aplikáciou výhradne šifrovane a autorizovane

Typické LAN zariadenia:

- ESC/POS LAN tlačiarne (port 9100)
- ZPL etikety (Zebra, port 9100)
- fiskálne pokladnice (napr. FiskalPRO API na porte 3000)
- špecializované TCP zariadenia (scannery, IoT gatewaye…)

---

## Typické scenáre použitia

- Cloudový fakturačný/POS systém, ktorý potrebuje tlačiť účtenky na lokálnej tlačiarni
- Webová aplikácia, ktorá musí komunikovať s LAN pokladnicou cez proprietárny TCP protokol
- Centrálne webové UI (na vzdialenom serveri), ktoré riadi lokálne TCP zariadenia bez VPN
- Situácie, kde IT oddelenie nedovolí otvárať porty ani nastavovať port-forwarding, ale povoľuje bežný outbound HTTP/HTTPS

---

## Architektúra (high-level)

Tok komunikácie:

1. **Cloud / Web aplikácia** – beží na vzdialenom serveri, komunikuje cez HTTPS s browserom
2. **Browser (používateľ)** – vykonáva JavaScript, ktorý posiela požiadavky na `http://localhost:<port>`
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
- používal len **outbound** TCP spojenia smerom do LAN
- nikdy neotváral priamy prístup do LAN pre internet
- fungoval aj za „striktnejším firewallom“, ktorý povoľuje len:
  - outbound HTTPS pre prehliadač
  - lokálnu komunikáciu na `localhost`
  - internú komunikáciu v LAN

Nie je potrebný:

- port-forwarding
- verejná IP adresa
- inbound pravidlá vo firewalle
- VPN prístup do siete zákazníka

### Kryptografická inicializácia

Bezpečnosť je postavená na dvojfázovom procese:

#### 1. Inicializačná (bootstrap) fáza

Po prvom spustení:

1. Agent čaká na **jednorazovú inicializačnú požiadavku**
2. Webová aplikácia poskytne:
   - IP adresu zariadenia v LAN
   - TCP port zariadenia
   - svoj **public key**
3. Agent:
   - vygeneruje vlastný **private key** (zostáva len lokálne)
   - vytvorí alebo odvodí **session key**
   - uloží konfiguráciu a párovanie lokálne
   - prepne sa do „encrypted-only“ režimu

Public key nie je citlivý, preto bootstrap môže prebiehať bez šifrovania.

#### 2. Prevádzková (encrypted-only) fáza

Po úspešnej inicializácii:

- agent prestane akceptovať nešifrované alebo „nepárované“ požiadavky
- komunikuje iba s webovou aplikáciou, ktorá dokáže používať dohodnutý kryptografický mechanizmus
- všetky payloady sú šifrované (E2E medzi webom a agentom)
- do LAN odchádzajú len RAW TCP dáta (agent ich neinterpretuje)

Re-párovanie agenta je možné len manuálnym zásahom (napr. vymazaním lokálnej konfigurácie).

---

## Rýchly štарт (Docker)

Odporúčaný spôsob spustenia:

```bash
docker run -d \
  --restart=unless-stopped \
  --name http2tcp-agent \
  -p 127.0.0.1:34279:80 \
  hrnco/http2tcp-local-agent
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

Presná špecifikácia API môže byť predmetom ďalšej dokumentácie, ale základný princíp je:

- **Inicializačné volanie** – párovanie agenta s webovou aplikáciou (konfigurácia IP/port a public key)
- **Prevádzkové volania** – odosielanie šifrovaných požiadaviek, ktoré agent rozbalí a prevedie na TCP komunikáciu

Príklad konceptu prevádzkovej požiadavky (ilustratívne):

```
POST /tcp/send HTTP/1.1
Host: localhost:34279
Content-Type: application/json

{
  "ip": "192.168.1.50",
  "port": 9100,
  "payload_base64": "SGVsbG8gV29ybGQK..."
}
```

Agent:

1. dekóduje/overí šifrovanie a podpis podľa dohodnutého protokolu
2. otvorí TCP spojenie na `ip:port`
3. odošle binárny payload
4. vráti odpoveď v Base64

---

## Čo tento projekt nie je

HTTP2TCP Local Agent nie je:

- VPN server ani sieťový tunel
- univerzálny port-forwarder z internetu do LAN
- SSH náhrada
- nástroj na vzdialenú správu PC

Je to **špecializovaný, lokálny, kryptograficky párovaný agent** na bezpečné TCP operácie, riadené webovou aplikáciou.

---

## Licencia

Bude doplnené.


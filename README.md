# HTTP2TCP Local Agent

`hrnco/http2tcp-local-agent` je ľahký lokálny HTTP server bežiaci v Dockeri, ktorý umožňuje webovým alebo cloudovým aplikáciám bezpečne komunikovať so zariadeniami v LAN cez TCP – bez potreby otvárať porty, nastavovať VPN alebo exponovať LAN smerom do internetu.

Hlavná idea:

> Cloud / Web App → http2tcp-server (crypto/signing) → Browser → http://localhost:<port> → HTTP2TCP Local Agent → TCP → LAN zariadenie

Cloud nikdy nepotrebuje priamy prístup do vnútornej siete zákazníka.

---

## Prehľad

HTTP2TCP Local Agent funguje ako:

- **HTTP server na localhoste** – prijíma požiadavky z prehliadača alebo lokálneho klienta
- **TCP klient do LAN** – nadväzuje výstupné TCP spojenia na zariadenia v lokálnej sieti (tlačiarne, pokladnice, terminály, IoT…)
- **kryptograficky overujúci agent** – akceptuje iba serverom podpísané (a voliteľne šifrované) požiadavky

Doplnková serverová časť (`http2tcp-server`) slúži ako:

- držiteľ private key
- podpisový / šifrovací modul
- prekladač aplikačných požiadaviek do kryptograficky autorizovanej podoby

Server **nekomunikuje priamo s agentom** – agent komunikuje iba s browserom na localhoste.

Typické LAN zariadenia:

- ESC/POS LAN tlačiarne (port 9100)
- ZPL etikety (Zebra, port 9100)
- fiskálne pokladnice (napr. FiskalPRO API na porte 3000)
- špecializované TCP zariadenia (skenery, IoT gatewaye…)

---

## Typické scenáre použitia

- Cloudový fakturačný/POS systém, ktorý potrebuje tlačiť účtenky na lokálnej tlačiarni
- Webová aplikácia, ktorá musí komunikovať s LAN pokladnicou cez proprietárny TCP protokol
- Centrálne webové UI, ktoré riadi lokálne TCP zariadenia bez VPN
- Prostredia, kde IT oddelenie nedovolí otvárať porty ani nastavovať port-forwarding

---

## Architektúra (high-level)

Tok komunikácie:

1. **Cloud / Web aplikácia** požiada server o podpísanú/šifrovanú požiadavku
2. **http2tcp-server** vytvorí kryptografickú obálku (signature/encryption)
3. **Browser (JS)** pošle túto obálku na `http://localhost:<port>`
4. **HTTP2TCP Local Agent** overí podpis a vykoná TCP operáciu
5. **LAN zariadenie** spracuje TCP komunikáciu

Schematicky:

```
Cloud / Web App
        |
        |  HTTPS
        v
 http2tcp-server
 (signing/encryption)
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

### Digitálny podpis

Každá požiadavka je podpísaná private key servera.

Agent overuje podpis pomocou uloženého server public key.

Podpis je povinný vždy – aj pri nešifrovanom payload-e.

---

### Trust On First Use (TOFU)

Pri prvom spojení:

1. Server pošle svoj public key
2. Agent si ho uloží (pinning)
3. Od tej chvíle dôveruje iba tomuto kľúču

Ak sa kľúč zmení, agent požiadavky odmietne.

---

### Ochrana proti replay útokom

Každá požiadavka obsahuje timestamp. 

Agent odmietne staré požiadavky.

---

### Payload

- payload nie je šifrovaný
- je podpísaný
- zaručuje integritu a autentickosť

---

## Key management

### Server keyring

Server môže mať viac private key (`key_id`):

- per zákazník
- per tenant
- per zariadenie

To umožňuje izoláciu a rotáciu.

---

### Uloženie kľúčov

Private keys nie sú súčasťou Docker image.

Odporúčané možnosti:

- Docker volume
- databáza + šifrovanie at-rest
- Vault / KMS

Kľúče prežijú recreate kontajnera.

---

### Rotácia kľúčov

Agent môže akceptovať viac public key naraz.

Postup:

1. odstrániť starý private key zo servera
2. odparovat agenta zo starym klucom
3. server autoamticky vytvori novy private key a agent, kedze nie je sparovany sa automaticky sparuje

---

## Rýchly štart (Docker)

Odporúčaný spôsob spustenia:

```bash
docker run -d --restart=unless-stopped --name http2tcp-agent -p 127.0.0.1:34279:80 hrnco/http2tcp-local-agent
```

Po spustení je agent dostupný na:

```
http://localhost:34279
```

---

## Základný princíp API

Server vracia kryptograficky autorizovanú obálku, ktorú browser pošle agentovi.  
Špecifikácia formátu bude doplnená.

---

## Čo tento projekt nie je

HTTP2TCP Local Agent nie je:

- VPN server ani sieťový tunel
- univerzálny port-forwarder z internetu do LAN
- SSH náhrada
- nástroj na vzdialenú správu PC

Je to **špecializovaný, lokálny, kryptograficky overujúci agent** na bezpečné TCP operácie.

---

## Poďakovanie

Tento projekt vznikol ako reakcia na konkrétnu potrebu zákazníka v oblasti komunikácie s LAN zariadeniami.

Ďakujeme spoločnostiam:

Cykloon — https://www.cykloon.com/

Trialexa — https://trialexa.com/

za konzultácie, podporu a umožnenie otvorenia projektu ako open-source.

---

## Licencia

Bude doplnené.

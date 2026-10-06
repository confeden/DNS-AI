# DNS-AI — клиент шифрованного DNS для Windows 7+

Один исполняемый файл `DNS-AI.exe`: окно с настройками в трее, локальный DoH-резолвер и
необязательная служба LocalSystem. Программа поднимает свой резолвер на `127.0.0.1:53` (и `[::1]:53`),
говорит с `dns.dns-ai.ru` по DoH (RFC 8484) и переводит DNS сетевых адаптеров на себя, а при
выключении возвращает их ровно в то состояние, в котором нашла.

На Windows 11 доступен и второй режим — прописать адреса резолвера прямо в адаптеры и отдать
шифрование встроенному в Windows DoH-клиенту.

## Быстрая настройка одной командой

Скрипт сам определяет систему, берёт актуальные адреса из [`endpoints.json`](endpoints.json) и
прописывает шифрованный DNS. Обычный DNS на 53-м порту сервис не отдаёт, поэтому скрипты настраивают
только шифрованные варианты.

**Windows 10 и 11** — в PowerShell:

```powershell
irm https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.ps1 | iex
```

* Windows 11 — адреса и встроенный DoH (`https://dns.dns-ai.ru/dns-query`, без возврата к открытому
  тексту) на каждом подключённом физическом адаптере, IPv4 и IPv6;
* Windows 7, 8 и 10 — встроенного шифрованного DNS у них нет, поэтому скачивается и ставится
  программа `DNS-AI.exe` из последнего релиза.

Отмена: `& ([scriptblock]::Create((irm https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.ps1))) -Undo`

**Linux** (Debian, Ubuntu, Fedora, RHEL, openSUSE, Arch, Alpine, Void…):

```bash
curl -fsSL https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.sh | sudo sh
```

Где есть systemd 247+ — DNS-over-TLS через `systemd-resolved` (ставится, если его нет); иначе —
`stubby`. Отмена: `curl -fsSL https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.sh | sudo sh -s -- --undo`

**iPhone, iPad, Mac** — профиль: <https://dns-ai.ru/dns-ai.mobileconfig> (открыть в Safari).

## Актуальные адреса

Программа не зависит от вшитых адресов. Служба раз в 10 минут спрашивает у резолвера, где он сейчас
находится; если ни один известный адрес не отвечает, она узнаёт адреса через публичный DoH, а затем
из [`endpoints.json`](endpoints.json) в этом репозитории (и его копии на dns-ai.ru), и — в режиме
встроенного DoH Windows 11 — сама переписывает адреса в адаптерах. Имя, по которому проверяется
сертификат (`dns.dns-ai.ru`), вшито в программу, поэтому подменённый список адресов не может
перенаправить запросы на чужой сервер.

## Состав

| Каталог | Что внутри |
|---|---|
| `core/` | перечисление адаптеров, состояние DNS, резервная копия и восстановление, DoH-заглушка, типы IPC |
| `client/` | всё, у чего есть `main`: окно и трей, служба, установка, команды командной строки (`probe`, `test-doh`, …) |

Собирается один бинарник `DNS-AI.exe`; какую роль он играет, решает argv (`service`, `--tray`,
`install`, `probe`, …).

## Сборка

Нужны:

* **Rust nightly** с компонентом `rust-src` — цель `x86_64-win7-windows-msvc` относится к Tier 3
  и готовой стандартной библиотеки для неё не публикуют, она собирается из исходников (`-Zbuild-std`);
* **MSVC-тулчейн** — Visual Studio Build Tools с Windows SDK (оттуда берётся компилятор ресурсов
  для иконки и блока версии).

```bash
rustup toolchain install nightly --profile minimal --component rust-src
rustup override set nightly          # один раз, в этом каталоге
cargo build --release
```

Цель и `-Zbuild-std` заданы в `.cargo/config.toml`, поэтому команда сборки обычная. Результат:

```
target/x86_64-win7-windows-msvc/release/DNS-AI.exe
```

Отдельной «современной» сборки нет: цель под Windows 7 — строгое подмножество, её бинарник подходит
для всех версий от 7 до 11. Обычная сборка на Windows 7 не запустилась бы вовсе — начиная с Rust 1.78
стандартная библиотека импортирует `WaitOnAddress` и `ProcessPrng`, которых там нет, и загрузчик
отказывает ещё до `main`. C-рантайм линкуется статически (там же, в `.cargo/config.toml`), чтобы не
тянуть за собой распространяемый пакет Visual C++.

Тесты:

```bash
cargo test --workspace
```

## Лицензия

GNU General Public License v3.0 или новее — см. [LICENSE](LICENSE).

---

# Создано с ❤️

🙋 **Группа в Телеграм:** [@nova_txt](https://t.me/nova_txt) — вопросы, новости,
поддержка.

☕ **[Отблагодарить](https://nova-app.eu/donate)** — если DNS-AI оказался полезным.
Это необязательный способ сказать "спасибо".

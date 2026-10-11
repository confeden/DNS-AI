# DNS-AI: undo the one-line setup.
#   irm https://dns-ai.ru/undo.ps1 | iex
# Only a wrapper: fetches setup.ps1 and runs it with -Undo, so the undo logic lives in one place.
# ASCII only and saved without a BOM (G114).
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
& ([scriptblock]::Create((irm https://dns-ai.ru/setup.ps1))) -Undo

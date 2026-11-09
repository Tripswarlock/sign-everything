# Third-party notices

Sign Everything распространяется по **GNU General Public License v3.0**
(`GPL-3.0-only`). Полный текст — в файле `LICENSE`.

## PyQt5

Приложение использует PyQt5 (GUI). PyQt5 распространяется по GNU GPL v3.0
или по коммерческой лицензии Riverbank Computing. В состав этого репозитория
PyQt5 не входит и устанавливается отдельно средствами дистрибутива.

- https://www.riverbankcomputing.com/software/pyqt/
- https://www.gnu.org/licenses/gpl-3.0.html

## cryptography

Модуль `cryptography` используется для шифрования локального хранилища PIN.
Распространяется по Apache License 2.0 или BSD 3-Clause; в состав репозитория
не входит.

- https://cryptography.io/
- https://github.com/pyca/cryptography/blob/main/LICENSE

## Python

Python распространяется по Python Software Foundation License. В состав
репозитория не входит.

- https://docs.python.org/3/license.html

## КриптоПро CSP

`cryptcp` и `certmgr` — компоненты проприетарного КриптоПро CSP. Они не входят
в пакет Sign Everything и должны быть установлены и лицензированы отдельно.

- https://www.cryptopro.ru/

## Токены и смарт-карты

Для доступа к аппаратным носителям используется PC/SC (`pcscd`) и драйверы
производителя токена. Они также не входят в состав пакета.

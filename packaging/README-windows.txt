SocketTrail for Windows
=======================

A network connection monitor tied to processes: which program talks to where
and how much, plus recording the traffic of a selected process into .pcapng.

Running
-------
1. Extract the archive to any folder and run sockettrail.exe.
2. A Microsoft Edge (or Chrome) window with the interface opens. The black
   console window is the program log: closing either window exits the program.
3. Windows may show "Windows protected your PC": the exe is not signed yet.
   Click "More info" -> "Run anyway".

Without installation and without administrator rights the process and
connection list works, and domains come from the Windows DNS cache (Chrome and
Edge will not have them: browsers use their own DNS client). Domains appear
gradually, within a few seconds.

Administrator rights
--------------------
The "Restart as administrator" button in the window (or starting the exe with
"Run as administrator") enables packet capture via PktMon, a driver built into
Windows. This gives browser domains (SNI), per-connection traffic volume and
.pcapng dumps. Wireshark and Npcap are not needed.
Requires Windows 10 version 2004 or newer, or Windows 11.

Dumps
-----
"Record dump" with "process only" checked records the traffic of the selected
game and stops by itself 15 seconds after the game exits. Every packet in the
file is labeled with its process and domain: in Wireshark this is the
frame.comment field, filter frame.comment contains "game.exe". A .json file
with the connection map is saved next to it.

If Wireshark with Npcap is already installed, SocketTrail uses its dumpcap
without administrator rights.

Language
--------
English by default. The EN | RU switch in the window header changes the
language, and the choice is saved. Command line: sockettrail.exe --lang ru

Where data is stored
--------------------
Dumps:              %USERPROFILE%\SocketTrail
Cache and profile:  %LOCALAPPDATA%\SocketTrail

Command line options: sockettrail.exe --help
Source code and bug reports: https://github.com/mazixs/SocketTrail


SocketTrail для Windows
=======================

Монитор сетевых соединений с привязкой к процессу: какая программа, куда и
сколько передает, плюс запись трафика выбранного процесса в .pcapng.

Запуск
------
1. Распакуйте архив в любую папку и запустите sockettrail.exe.
2. Откроется окно Microsoft Edge (или Chrome) с интерфейсом. Черное окно
   консоли - это журнал программы: закрытие любого из окон завершает работу.
3. Windows может показать "Система Windows защитила ваш компьютер": exe пока
   не подписан. Нажмите "Подробнее" -> "Выполнить в любом случае".

Без установки и без прав администратора работают список процессов и соединений,
а домены берутся из DNS-кеша Windows (у Chrome и Edge их не будет: у браузеров
свой DNS-клиент). Домены появляются постепенно, в течение нескольких секунд.

Права администратора
--------------------
Кнопка "Перезапустить от администратора" в окне (или запуск exe через
"Запуск от имени администратора") включает захват пакетов встроенным в Windows
драйвером PktMon. Это дает домены браузеров (SNI), объем трафика по соединениям
и запись дампов .pcapng. Ставить Wireshark и Npcap не нужно.
Нужна Windows 10 версии 2004 или новее либо Windows 11.

Дампы
-----
"Собрать дамп" с галочкой "только процесс" пишет трафик выбранной игры и
останавливается сам через 15 секунд после ее выхода. Каждый пакет в файле
подписан процессом и доменом: в Wireshark это поле frame.comment, фильтр
frame.comment contains "game.exe". Рядом лежит .json с картой соединений.

Если Wireshark с Npcap уже установлен, без прав администратора SocketTrail
использует его dumpcap.

Язык
----
По умолчанию английский. Переключатель EN | RU в шапке окна меняет язык,
выбор сохраняется. Из командной строки: sockettrail.exe --lang ru

Где лежат данные
----------------
Дампы:           %USERPROFILE%\SocketTrail
Кеш и профиль:   %LOCALAPPDATA%\SocketTrail

Ключи командной строки: sockettrail.exe --help
Исходный код и сообщения об ошибках: https://github.com/mazixs/SocketTrail

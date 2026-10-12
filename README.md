# PasswordManager

Piccolo password manager da terminale scritto in C#/.NET. Il progetto è pensato per studio e uso personale; non è stato sottoposto a un audit di sicurezza indipendente.

## Schermata

Anteprima grafica del comando `help`:

![Anteprima dei comandi di PasswordManager in un terminale](docs/terminal-help.svg)

## Requisiti

- .NET 10 SDK

## Avvio

Apri un terminale nella cartella del progetto ed esegui:

```sh
dotnet run -- setup
dotnet run -- add example.com alice
dotnet run -- get example.com
dotnet run -- list
```

`setup` crea `vault.dat` e chiede due volte una password master di almeno 12 caratteri. Gli altri comandi la chiedono nel terminale senza mostrarla. Con `add`, premi Invio al prompt della password per generarne una casuale.

Il programma salva l'archivio nella cartella di lavoro corrente. Esegui i comandi sempre dalla stessa cartella. Fai copie di backup sicure di `vault.dat`: se lo perdi o dimentichi la password master, non c'è una procedura di recupero. Non condividere il file del vault.

## Protezione dei dati

Il vault usa AES-GCM con nonce e tag di autenticazione, una salt casuale per archivio e PBKDF2-HMAC-SHA-256 con 600.000 iterazioni per derivare la chiave dalla password master. Su sistemi Unix il file viene impostato con permessi di lettura e scrittura per il solo utente. La password master non viene salvata separatamente né passata come argomento dei comandi.

Queste misure non sostituiscono un audit indipendente. La sicurezza dipende anche dalla robustezza della password master, dal dispositivo e dai backup. La password recuperata con `get` viene mostrata nel terminale.

## Formato e compatibilità

Il formato dell'archivio è versionato. Le versioni precedenti del progetto usavano un formato differente e non vengono migrate automaticamente: crea un nuovo archivio e trasferisci manualmente solo i dati che vuoi conservare.

## Licenza

Questo progetto è distribuito con licenza MIT. Vedi [LICENSE](LICENSE).

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class Program
{
    private const string VaultPath = "vault.dat";
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int KdfIterations = 600_000;
    private const int MinimumKdfIterations = 100_000;
    private const int MaximumKdfIterations = 2_000_000;
    private const int HeaderSize = 4 + 1 + 4 + SaltSize + NonceSize;
    private const byte FormatVersion = 1;
    private const int MinimumMasterPasswordLength = 12;
    private static readonly byte[] Magic = "PMGR"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0].Equals("help", StringComparison.OrdinalIgnoreCase))
            {
                ShowHelp();
                return 0;
            }

            switch (args[0].ToLowerInvariant())
            {
                case "setup" when args.Length == 1:
                    Setup();
                    return 0;
                case "add" when args.Length == 3:
                    Add(args[1], args[2]);
                    return 0;
                case "get" when args.Length == 2:
                    Get(args[1]);
                    return 0;
                case "list" when args.Length == 1:
                    ListAll();
                    return 0;
                default:
                    Console.Error.WriteLine("Comando o numero di argomenti non valido. Usa 'help' per l'uso.");
                    return 2;
            }
        }
        catch (CryptographicException)
        {
            Console.Error.WriteLine("Password master errata oppure archivio danneggiato o manomesso.");
            return 1;
        }
        catch (InvalidDataException ex)
        {
            Console.Error.WriteLine($"Archivio non valido: {ex.Message}");
            return 1;
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"Errore di accesso ai file: {ex.Message}");
            return 1;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"Accesso negato: {ex.Message}");
            return 1;
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static void Setup()
    {
        if (File.Exists(VaultPath))
        {
            Console.WriteLine("L'archivio esiste già. Non è stato modificato.");
            return;
        }

        string masterPassword = ReadSecret("Crea password master: ");
        if (masterPassword.Length < MinimumMasterPasswordLength)
        {
            Console.Error.WriteLine($"La password master deve contenere almeno {MinimumMasterPasswordLength} caratteri.");
            return;
        }

        string confirmation = ReadSecret("Ripeti password master: ");
        byte[] masterBytes = Encoding.UTF8.GetBytes(masterPassword);
        byte[] confirmationBytes = Encoding.UTF8.GetBytes(confirmation);
        bool passwordsMatch;
        try
        {
            passwordsMatch = CryptographicOperations.FixedTimeEquals(masterBytes, confirmationBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterBytes);
            CryptographicOperations.ZeroMemory(confirmationBytes);
        }

        if (!passwordsMatch)
        {
            Console.Error.WriteLine("Le password non coincidono. Archivio non creato.");
            return;
        }

        SaveVault(new Dictionary<string, PasswordEntry>(StringComparer.OrdinalIgnoreCase), masterPassword);
        Console.WriteLine($"Archivio creato in {Path.GetFullPath(VaultPath)}");
        Console.WriteLine("Conserva una copia di backup di vault.dat: la password master non è recuperabile.");
    }

    private static void Add(string siteInput, string username)
    {
        if (!EnsureVaultExists())
            return;

        string site = NormalizeSite(siteInput);
        if (site.Length == 0 || string.IsNullOrWhiteSpace(username))
        {
            Console.Error.WriteLine("Sito e utente non possono essere vuoti.");
            return;
        }

        string masterPassword = ReadSecret("Password master: ");
        Dictionary<string, PasswordEntry> vault = LoadVault(masterPassword);

        string password = ReadSecret("Password da salvare (INVIO per generarne una): ", allowEmpty: true);
        if (string.IsNullOrWhiteSpace(password))
            password = GeneratePassword();

        vault[site] = new PasswordEntry
        {
            Username = username,
            Password = password,
            CreatedUtc = DateTimeOffset.UtcNow
        };
        SaveVault(vault, masterPassword);
        Console.WriteLine($"Credenziale salvata per {site}.");
    }

    private static void Get(string siteInput)
    {
        if (!EnsureVaultExists())
            return;

        string site = NormalizeSite(siteInput);
        string masterPassword = ReadSecret("Password master: ");
        Dictionary<string, PasswordEntry> vault = LoadVault(masterPassword);

        if (!vault.TryGetValue(site, out PasswordEntry? entry))
        {
            Console.WriteLine("Voce non trovata.");
            return;
        }

        Console.WriteLine($"Sito: {site}");
        Console.WriteLine($"Utente: {entry.Username}");
        Console.WriteLine($"Password: {entry.Password}");
    }

    private static void ListAll()
    {
        if (!EnsureVaultExists())
            return;

        string masterPassword = ReadSecret("Password master: ");
        Dictionary<string, PasswordEntry> vault = LoadVault(masterPassword);

        if (vault.Count == 0)
        {
            Console.WriteLine("Archivio vuoto.");
            return;
        }

        foreach (KeyValuePair<string, PasswordEntry> item in vault.OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase))
            Console.WriteLine($"{item.Key} | {item.Value.Username}");
    }

    private static bool EnsureVaultExists()
    {
        if (File.Exists(VaultPath))
            return true;

        Console.Error.WriteLine("Archivio non trovato nella cartella corrente. Esegui 'setup' prima.");
        return false;
    }

    private static Dictionary<string, PasswordEntry> LoadVault(string masterPassword)
    {
        byte[] file = File.ReadAllBytes(VaultPath);
        if (file.Length < HeaderSize + TagSize + 1)
            throw new InvalidDataException("file incompleto.");

        ReadOnlySpan<byte> header = file.AsSpan(0, HeaderSize);
        if (!header[..Magic.Length].SequenceEqual(Magic))
            throw new InvalidDataException("intestazione sconosciuta.");
        if (header[4] != FormatVersion)
            throw new InvalidDataException("versione del formato non supportata.");

        int iterations = BinaryPrimitives.ReadInt32BigEndian(header.Slice(5, 4));
        if (iterations < MinimumKdfIterations || iterations > MaximumKdfIterations)
            throw new InvalidDataException("parametri di derivazione della chiave non validi.");

        ReadOnlySpan<byte> salt = header.Slice(9, SaltSize);
        ReadOnlySpan<byte> nonce = header.Slice(9 + SaltSize, NonceSize);
        ReadOnlySpan<byte> tag = file.AsSpan(HeaderSize, TagSize);
        ReadOnlySpan<byte> ciphertext = file.AsSpan(HeaderSize + TagSize);
        byte[] key = DeriveKey(masterPassword, salt, iterations);
        byte[] plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, header);

            Dictionary<string, PasswordEntry>? loaded;
            try
            {
                loaded = JsonSerializer.Deserialize<Dictionary<string, PasswordEntry>>(plaintext);
            }
            catch (JsonException)
            {
                throw new InvalidDataException("contenuto non leggibile.");
            }
            if (loaded is null)
                throw new InvalidDataException("contenuto vuoto.");

            var vault = new Dictionary<string, PasswordEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, PasswordEntry> item in loaded)
            {
                if (string.IsNullOrWhiteSpace(item.Key) || item.Value is null ||
                    item.Value.Username is null || item.Value.Password is null)
                    throw new InvalidDataException("una voce dell'archivio non è valida.");

                vault[item.Key] = item.Value;
            }

            return vault;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(file);
        }
    }

    private static void SaveVault(Dictionary<string, PasswordEntry> vault, string masterPassword)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] header = new byte[HeaderSize];
        Magic.CopyTo(header, 0);
        header[4] = FormatVersion;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5, 4), KdfIterations);
        salt.CopyTo(header, 9);
        nonce.CopyTo(header, 9 + SaltSize);

        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(vault, JsonOptions);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];
        byte[] key = DeriveKey(masterPassword, salt, KdfIterations);
        string temporaryPath = Path.GetFullPath(VaultPath) + ".tmp";

        try
        {
            using (var aes = new AesGcm(key, TagSize))
                aes.Encrypt(nonce, plaintext, ciphertext, tag, header);

            using (var output = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                output.Write(header);
                output.Write(tag);
                output.Write(ciphertext);
                output.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(temporaryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            File.Move(temporaryPath, Path.GetFullPath(VaultPath), overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static byte[] DeriveKey(string masterPassword, ReadOnlySpan<byte> salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(masterPassword, salt, iterations, HashAlgorithmName.SHA256, KeySize);

    private static string GeneratePassword()
    {
        const string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        var result = new StringBuilder(20);
        for (int i = 0; i < 20; i++)
            result.Append(characters[RandomNumberGenerator.GetInt32(characters.Length)]);
        return result.ToString();
    }

    private static string ReadSecret(string prompt, bool allowEmpty = false)
    {
        if (Console.IsInputRedirected)
            throw new InvalidOperationException("Inserisci le password da un terminale interattivo, non da input reindirizzato.");

        Console.Write(prompt);
        var value = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;

            if (key.Key == ConsoleKey.Backspace)
            {
                if (value.Length > 0)
                {
                    value.Length--;
                    Console.Write("\b \b");
                }
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                value.Append(key.KeyChar);
                Console.Write('*');
            }
        }

        Console.WriteLine();
        string result = value.ToString();
        return allowEmpty && string.IsNullOrWhiteSpace(result) ? string.Empty : result;
    }

    private static string NormalizeSite(string site) => site.Trim().ToLowerInvariant();

    private static void ShowHelp()
    {
        Console.WriteLine("""
        PasswordManager

        Comandi:
          dotnet run -- setup
          dotnet run -- add <sito> <utente>
          dotnet run -- get <sito>
          dotnet run -- list
          dotnet run -- help

        La password master e le password dei servizi vengono richieste nel terminale
        e non vanno inserite negli argomenti dei comandi.
        """);
    }

}

internal sealed class PasswordEntry
{
    public PasswordEntry() { }

    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
}

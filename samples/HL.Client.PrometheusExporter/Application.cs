using System.Buffers.Text;
using System.Net;
using System.Security;
using Prometheus;

namespace HL.Client.PrometheusExporter
{
    public class Application
    {
        private static readonly SecureString Username = new();
        private static readonly SecureString Password = new();
        private static readonly SecureString DateOfBirth = new();
        private static readonly SecureString SecretCode = new();

        private static Gauge _accountInstrumentValue;
        private static Gauge _accountCashValue;

        private static Gauge _instrumentCost;
        private static Gauge _instrumentValue;
        private static Gauge _instrumentQuantity;

        private static Client _client;

        private static void SetValue(SecureString secureString, string value)
        {
            secureString.Clear();
            foreach (var c in value)
            {
                secureString.AppendChar(c);
            }
        }

        private static void Log(string line)
        {
            Console.WriteLine($"[{DateTime.UtcNow.ToString("O")}] {line}");
        }

        private static void CollectInput(
            string envVar, string prompt, SecureString destination, Func<int, char, bool> predicate
        )
        {
            var value = Environment.GetEnvironmentVariable(envVar);
            if (value != null)
            {
                Environment.SetEnvironmentVariable(envVar, null);
                SetValue(destination, value);
                return;
            }

            while (destination.Length == 0)
            {
                Console.Write(prompt + ": ");
                ConsoleKeyInfo key;
                do
                {
                    key = Console.ReadKey(true);

                    // Ignore any key out of range.
                    if (predicate(destination.Length, key.KeyChar))
                    {
                        // Append the character to the password.
                        destination.AppendChar(key.KeyChar);
                        Console.Write("*");
                    }

                    if (key.Key == ConsoleKey.Backspace && destination.Length > 0)
                    {
                        destination.RemoveAt(destination.Length - 1);
                        Console.Write("\b \b");
                    }
                    // Exit if Enter key is pressed.
                } while (key.Key != ConsoleKey.Enter);

                Console.Write("\n");
            }
        }

        private static void GenerateEncryptedSecret()
        {
            Console.WriteLine("This mode will generate an encrypted credentials that can later be used for decryption on startup.");
            CollectInput("HL_USERNAME", "Enter username", Username, (_, c) => char.IsLetterOrDigit(c));
            CollectInput("HL_PASSWORD", "Enter password", Password, (_, c) => !char.IsControl(c));
            CollectInput(
                "HL_BIRTHDAY", "Enter date of birth (YYYY-MM-DD)", DateOfBirth,
                (i, c) => i < 10 && (i == 4 || i == 7 ? c == '-' : char.IsDigit(c))
            );
            CollectInput("HL_SECURITY_CODE", "Enter secret code", SecretCode, (i, c) => i < 6 && char.IsDigit(c));

            var decryptionKey = new SecureString();
            CollectInput("HL_DECRYPTION_KEY", "Encryption/decryption key", decryptionKey, (_, c) => !char.IsControl(c));

            var key = EncryptionHelper.CreateKey(ToPlainString(decryptionKey));
            var credentialString =
                $"{ToPlainString(Username)}:{ToPlainString(Password)}:{ToPlainString(DateOfBirth)}:{ToPlainString(SecretCode)}";
            var encryptedCredentialString = EncryptionHelper.Encrypt(credentialString, key);
            Console.WriteLine($"Encrypted credential string: {encryptedCredentialString}");
        }

        public static async Task Main(string[] args)
        {
            if (args != null && args.Length != 0 && args[0].ToLower() == "generate")
            {
                GenerateEncryptedSecret();
                return;
            }

            var encryptedCredentials = Environment.GetEnvironmentVariable("HL_ENCRYPTED_CREDENTIALS");
            if (!string.IsNullOrWhiteSpace(encryptedCredentials))
            {
                CollectInput("HL_DECRYPTION_KEY", "Enter decryption key", Password, (_, c) => !char.IsControl(c));
                var key = EncryptionHelper.CreateKey(ToPlainString(Password));
                var decryptedCredentials = EncryptionHelper.Decrypt(encryptedCredentials, key);
                var parts = decryptedCredentials.Split(':');
                if (parts.Length != 4)
                {
                    Console.WriteLine("Wrong number of parts in encrypted credentials");
                    return;
                }

                SetValue(Username, parts[0]);
                SetValue(Password, parts[1]);
                SetValue(DateOfBirth, parts[2]);
                SetValue(SecretCode, parts[3]);
            }
            else
            {
                CollectInput("HL_USERNAME", "Enter username", Username, (_, c) => char.IsLetterOrDigit(c));
                CollectInput("HL_PASSWORD", "Enter password", Password, (_, c) => !char.IsControl(c));
                CollectInput(
                    "HL_BIRTHDAY", "Enter date of birth (YYYY-MM-DD)", DateOfBirth,
                    (i, c) => i < 10 && (i == 4 || i == 7 ? c == '-' : char.IsDigit(c))
                );
                CollectInput("HL_SECURITY_CODE", "Enter secret code", SecretCode, (i, c) => i < 6 && char.IsDigit(c));
            }

            _client = new Client();

            if (!await _client.AuthenticateAsync(
                    ToPlainString(Username),
                    ToPlainString(Password),
                    DateTime.Parse(ToPlainString(DateOfBirth)),
                    ToPlainString(SecretCode)
                ))
            {
                Log("Failed to log in, exiting");
                return;
            }

            Log("Credentials worked");

            _accountInstrumentValue = Metrics.CreateGauge(
                "hl_account_instrument_value", "", "client_account", "account"
            );
            _accountCashValue = Metrics.CreateGauge("hl_account_cash_value", "", "client_account", "account");
            _instrumentCost = Metrics.CreateGauge("hl_instrument_cost", "", "instrument", "client_account", "account");
            _instrumentValue = Metrics.CreateGauge(
                "hl_instrument_value", "", "instrument", "client_account", "account"
            );
            _instrumentQuantity = Metrics.CreateGauge(
                "hl_instrument_quantity", "", "instrument", "client_account", "account"
            );

            var port = int.Parse(Environment.GetEnvironmentVariable("HL_PORT") ?? "9797");
            Log($"Will listen on port: {port}");

            var metricsServer = new KestrelMetricServer(port);
            metricsServer.Start();

            while (true)
            {
                try
                {
                    await TrackMetrics();
                }
                catch (Exception e)
                {
                    Log($"Failed to fetch metrics: {e}");
                }

                await Task.Delay(TimeSpan.FromMinutes(1));
            }
        }

        private static async Task TrackMetrics()
        {
            if (!await _client.IsAuthenticated())
            {
                if (!await _client.AuthenticateAsync(
                        ToPlainString(Username),
                        ToPlainString(Password),
                        DateTime.Parse(ToPlainString(DateOfBirth)),
                        ToPlainString(SecretCode)
                    ))
                {
                    Log("Failed to login, skipping");
                    return;
                }
            }

            foreach (var linkedAccount in await _client.LinkedAccountOperations.ListAsync())
            {
                if (!await _client.LinkedAccountOperations.Switch(linkedAccount.ClientNumber))
                {
                    Log($"Failed to switch to account {linkedAccount.Name}");
                    continue;
                }

                foreach (var account in await _client.AccountOperations.ListAsync())
                {
                    _accountCashValue.WithLabels(linkedAccount.Name, account.Name)
                        .Set(Convert.ToDouble(account.CashValue));
                    _accountInstrumentValue.WithLabels(linkedAccount.Name, account.Name)
                        .Set(Convert.ToDouble(account.StockValue));

                    foreach (var stock in await _client.AccountOperations.ListStocksAsync(account.Id))
                    {
                        _instrumentCost.WithLabels(stock.Name, linkedAccount.Name, account.Name)
                            .Set(Convert.ToDouble(stock.Cost));
                        _instrumentValue.WithLabels(stock.Name, linkedAccount.Name, account.Name)
                            .Set(Convert.ToDouble(stock.Value));
                        _instrumentQuantity.WithLabels(stock.Name, linkedAccount.Name, account.Name)
                            .Set(Convert.ToDouble(stock.UnitsHeld));
                    }
                }
            }
        }

        // convert a secure string into a normal plain text string
        private static String ToPlainString(SecureString secureStr)
        {
            return new NetworkCredential(string.Empty, secureStr).Password;
        }
    }
}

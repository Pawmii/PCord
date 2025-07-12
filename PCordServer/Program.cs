using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;

namespace PCordServer;

public class Program
{
    private const string EncryptionKey = "kB56emXyBTgGi5929Lt2J6k25cXGbS2v";
    
    private static readonly Dictionary<WebSocket, string> Tokens = new();
    private static readonly List<WebSocket> Sockets = new();
    private static string _password = "NOPASSWORD";
    
    private static readonly Dictionary<string, string> FileHashes = new(); // hash => file name

    public static void Main(string[] args)
    {
        int port = 5000;
        bool logChat = false;

        if (args.Length >= 1 && int.TryParse(args[0], out int argPort))
        {
            if (argPort >= 1024)
                port = argPort;
            else
                Console.WriteLine("ПРЕДУПРЕЖДЕНИЕ: Порт должен быть >= 1024. Установлен порт 5000.");
        }

        if (args.Length >= 2)
        {
            _password = args[1];
            Console.WriteLine($"Установлен пароль: {new string('*', _password.Length)}");
        }

        if (args.Length >= 3 && bool.TryParse(args[2], out logChat))
        {
            Console.WriteLine("Логирование чата включено, внимание, это нарушает политику о анонимности сообщений");
        }

        string logFileName = $"chatlogs/chatlog-{Guid.NewGuid().ToString("N")[..8]}.log";
        
        const string ActualVersion = "RELEASE1.1.0";
        string uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
        Directory.CreateDirectory(uploadsPath);

        var builder = WebApplication.CreateBuilder(args);
        builder.WebHost.ConfigureKestrel(options => options.ListenAnyIP(port));
        var app = builder.Build();

        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = new PhysicalFileProvider(uploadsPath),
            RequestPath = ""
        });

        app.UseWebSockets();

        app.MapPost("/upload", async context =>
        {
            var form = await context.Request.ReadFormAsync();
            var file = form.Files["file"];
            if (file == null)
            {
                context.Response.StatusCode = 400;
                return;
            }

            await using var ms = new MemoryStream();
            await file.CopyToAsync(ms);
            byte[] fileBytes = ms.ToArray();

            string hash;
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                hash = Convert.ToHexString(sha256.ComputeHash(fileBytes));
            }

            if (FileHashes.TryGetValue(hash, out var existingFileName))
            {
                Console.WriteLine($"[UPLOAD] Файл уже существует: {existingFileName}");
                await context.Response.WriteAsync(existingFileName);
                return;
            }

            string uniqueFileName = Path.GetFileNameWithoutExtension(file.FileName) + "_" + Guid.NewGuid() + Path.GetExtension(file.FileName);
            string fullPath = Path.Combine(uploadsPath, uniqueFileName);

            await File.WriteAllBytesAsync(fullPath, fileBytes);

            FileHashes[hash] = uniqueFileName;

            Console.WriteLine($"[UPLOAD] Загружен новый файл: {uniqueFileName}");
            await context.Response.WriteAsync(uniqueFileName);
        });

        app.Map("/ws", async context =>
        {
            if (!context.WebSockets.IsWebSocketRequest)
            {
                context.Response.StatusCode = 400;
                return;
            }

            var ws = await context.WebSockets.AcceptWebSocketAsync();
            Sockets.Add(ws);
            Console.WriteLine("Новое подключение");

            var buffer = new byte[4096];

            try
            {
                while (ws.State == WebSocketState.Open)
                {
                    var result = await ws.ReceiveAsync(buffer, CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Закрыто", CancellationToken.None);
                        Tokens.Remove(ws);
                        Sockets.Remove(ws);
                        Console.WriteLine("Отключено");
                        break;
                    }

                    var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    Console.WriteLine("RAW: " + message);
                    
                    string[] parts = message.Split("<br>");
                    if (parts.Length == 4)
                    {
                        string crypted = parts[0];
                        string signature = parts[1];
                        string publicKey = parts[2];
                        string password = parts[3];
                        
                        if (password != _password)
                            password = CryptoUtils.DecryptString(password, EncryptionKey);

                        if (!RsaUtils.VerifyMessage(crypted, signature, publicKey))
                        {
                            await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Невалидный токен", CancellationToken.None);
                            Sockets.Remove(ws);
                            return;
                        }

                        if (password != _password)
                        {
                            await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Неправильный пароль", CancellationToken.None);
                            Sockets.Remove(ws);
                            return;
                        }

                        Tokens[ws] = crypted;
                        
                        var msgObj = new { type = "text", data = $"Пользователь с айпи {context.Connection.RemoteIpAddress?.ToString()} подключился к чату!" };
                        string jsonMessage = JsonSerializer.Serialize(msgObj);
                        jsonMessage = CryptoUtils.EncryptString(jsonMessage, EncryptionKey);

                        var payload = Encoding.UTF8.GetBytes(jsonMessage);
                        
                        foreach (var socket in Sockets.ToList())
                        {
                            if (socket.State == WebSocketState.Open)
                                await socket.SendAsync(payload, WebSocketMessageType.Text, true, CancellationToken.None);
                        }

                        if (logChat)
                        {
                            string alert =
                                CryptoUtils.EncryptString("Внимание, в данном чате включено логирование сообщений!",
                                    EncryptionKey);

                            var alertPayload = Encoding.UTF8.GetBytes(alert);

                            if (ws.State == WebSocketState.Open)
                                await ws.SendAsync(alertPayload, WebSocketMessageType.Text, true,
                                    CancellationToken.None);
                        }
                        
                        continue;
                    }

                    if (!Tokens.TryGetValue(ws, out string token))
                        continue;
                
                    if (!message.Contains(ActualVersion) || !message.EndsWith($"<token:{token}>", StringComparison.Ordinal))
                        continue;

                    string json = message.Replace(ActualVersion, "").Replace($"<token:{token}>", "");
                    
                    string decrypted = CryptoUtils.DecryptString(json, EncryptionKey);
                    
                    if (decrypted.StartsWith('{') && decrypted.TrimEnd().EndsWith('}'))
                    {
                        var root = JsonDocument.Parse(decrypted).RootElement;

                        if (root.TryGetProperty("type", out var typeProp) && typeProp.GetString() == "file")
                        {
                            string fileName = root.GetProperty("fileName").GetString();
                            string fileType = root.GetProperty("fileType").GetString();
                            string? path = root.TryGetProperty("path", out var pathProp) ? pathProp.GetString() : null;

                            var fileBroadcast = new
                            {
                                type = "file",
                                fileName = fileName,
                                fileType = fileType,
                                path = path
                            };

                            string fileJson = JsonSerializer.Serialize(fileBroadcast);

                            string encryptedFileJson = CryptoUtils.EncryptString(fileJson, EncryptionKey);
                            var payload = Encoding.UTF8.GetBytes(encryptedFileJson);

                            foreach (var socket in Sockets.ToList())
                            {
                                if (socket.State == WebSocketState.Open)
                                    await socket.SendAsync(payload, WebSocketMessageType.Text, true, CancellationToken.None);
                            }

                            continue;
                        }

                        if (logChat)
                        {
                            try
                            {
                                string text = root.GetProperty("data").GetString();
                                
                                string? dir = Path.GetDirectoryName(logFileName);

                                if (!string.IsNullOrEmpty(dir))
                                    Directory.CreateDirectory(dir);

                                bool exists = File.Exists(logFileName);
                                
                                await File.AppendAllTextAsync(logFileName,
                                    exists ? $"\n{text}" : text,
                                    Encoding.UTF8);
                            }
                            catch { /* Ignore */ }
                        }
                        
                        continue;
                    }

                    var data = Encoding.UTF8.GetBytes(json);
                    foreach (var socket in Sockets.ToList())
                    {
                        if (socket.State == WebSocketState.Open)
                            await socket.SendAsync(data, WebSocketMessageType.Text, true, CancellationToken.None);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка в сокете: {ex.Message}");
                Sockets.Remove(ws);
            }
        });

        app.Run();
    }
}

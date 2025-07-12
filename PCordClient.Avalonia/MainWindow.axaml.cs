using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using System;
using System.IO;
using System.Net.Http;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using Avalonia;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;

namespace PCordClient.Avalonia;

public partial class MainWindow : Window
{
    private ClientWebSocket _socket = new();
    private CancellationTokenSource _cts = new();
    private static string _token = string.Empty;
    private bool _connected;

    private const string EncryptionKey = "kB56emXyBTgGi5929Lt2J6k25cXGbS2v";
    private const string MyVersion = "RELEASE1.1.0";

    public MainWindow()
    {
        if (!RsaUtils.LoadKeysFromFiles())
            RsaUtils.GenerateKeys();

        InitializeComponent();
        Opened += MainWindow_OnLoaded;
    }

    private async void ConnectButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_connected)
        {
            await Disconnect();
            ConnectButton.Content = "Подключиться";
            _connected = false;
            AddMessage("Отключено от сервера.");
            return;
        }

        string serverIp = ServerIpBox.Text.Trim();

        if (string.IsNullOrWhiteSpace(serverIp))
        {
            ShowMessage("Ошибка", "Введите IP сервера.");
            return;
        }

        _socket = new ClientWebSocket();
        _cts = new CancellationTokenSource();

        try
        {
            await _socket.ConnectAsync(new Uri($"ws://{serverIp}/ws"), _cts.Token);

            string tokenRaw = GenerateToken();
            _token = CryptoUtils.EncryptString(tokenRaw, EncryptionKey);

            string password = ServerPasswordBox.Text?.Trim() ?? "NOPASSWORD";

            if (string.IsNullOrEmpty(password))
            {
                password = "NOPASSWORD";
            }
            else
            {
                password = CryptoUtils.EncryptString(password, EncryptionKey);
            }
            
            string payload = $"{_token}<br>{RsaUtils.SignMessage(_token)}<br>{RsaUtils.GetPublicKey()}<br>{password}";
            var bytes = Encoding.UTF8.GetBytes(payload);
            await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, _cts.Token);

            _ = Task.Run(ReceiveLoop);
            
            ConnectButton.Content = "Отключиться";
            _connected = true;
            AddMessage($"Подключено к серверу {serverIp}");
        }
        catch (Exception ex)
        {
            ShowMessage("Ошибка подключения", ex.Message);
        }
    }
    
    private async Task SendFile(string filePath)
    {
        if (!_connected || _socket.State != WebSocketState.Open)
        {
            ShowMessage("Ошибка", "Соединение не установлено.");
            return;
        }

        try
        {
            string fileName = Path.GetFileName(filePath);
            string fileType = GetMimeType(filePath);

            using var form = new MultipartFormDataContent();
            form.Add(new StreamContent(File.OpenRead(filePath)), "file", fileName);

            string serverIp = ServerIpBox.Text.Trim();
            using var client = new HttpClient();
            var response = await client.PostAsync($"http://{serverIp}/upload", form);

            if (!response.IsSuccessStatusCode)
            {
                ShowMessage("Ошибка", "Ошибка загрузки файла на сервер.");
                return;
            }

            string relativePath = await response.Content.ReadAsStringAsync();

            var fileMessageObj = new
            {
                type = "file",
                fileName = fileName,
                fileType = fileType,
                path = relativePath
            };

            string jsonMessage = JsonSerializer.Serialize(fileMessageObj);
            jsonMessage = CryptoUtils.EncryptString(jsonMessage, EncryptionKey);
            jsonMessage += MyVersion + $"<token:{_token}>";

            var bytes = Encoding.UTF8.GetBytes(jsonMessage);
            await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, _cts.Token);
        }
        catch (Exception ex)
        {
            ShowMessage("Ошибка", "Ошибка отправки файла: " + ex.Message);
        }
    }
    
    private async void SendFileButton_Click(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Выберите файл",
            AllowMultiple = false
        });

        if (files.Count > 0)
        {
            var file = files[0];
            string originalFileName = file.Name;
            var tempFilePath = Path.Combine(Path.GetTempPath(), originalFileName);

            await using (var stream = await file.OpenReadAsync())
            await using (var fs = File.Create(tempFilePath))
            {
                await stream.CopyToAsync(fs);
            }

            try
            {
                await SendFile(tempFilePath);
            }
            finally
            {
                try { File.Delete(tempFilePath); } catch { /* игнорируем */ }
            }
        }
    }

    private async Task Disconnect()
    {
        try
        {
            await _cts.CancelAsync();

            if (_socket.State == WebSocketState.Open || _socket.State == WebSocketState.CloseReceived)
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
        }
        catch { }
        finally
        {
            _socket.Dispose();
        }
    }

    private async Task ReceiveLoop()
    {
        var buffer = new byte[4096];
        try
        {
            while (_socket.State == WebSocketState.Open)
            {
                var result = await _socket.ReceiveAsync(buffer, _cts.Token);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await _socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Closing",
                        CancellationToken.None);
                    ConnectButton.Content = "Подключиться";
                    _connected = false;
                    AddMessage("Отключено от сервера.");
                    return;
                }

                if (result.MessageType == WebSocketMessageType.Text)
                {
                    string encryptedMessage = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    string decryptedMessage = CryptoUtils.DecryptString(encryptedMessage, EncryptionKey);

                    try
                    {
                        Console.WriteLine($"[DECRYPTED]: {decryptedMessage}");
                        using var jsonDoc = JsonDocument.Parse(decryptedMessage);
                        var root = jsonDoc.RootElement;

                        if (root.TryGetProperty("type", out var typeProp))
                        {
                            Console.WriteLine("[DEBUG] Property type found");

                            string type = typeProp.GetString()?.Trim().Trim('\0') ?? string.Empty;

                            Console.WriteLine($"[DEBUG] File type (cleaned): '{type}'");

                            byte[] typeBytes = Encoding.UTF8.GetBytes(type);

                            Console.WriteLine("[HEX] " + BitConverter.ToString(typeBytes));

                            if (type == "file")
                            {
                                string fileName = root.GetProperty("fileName").GetString();
                                string fileType = root.GetProperty("fileType").GetString();
                                string path = root.GetProperty("path").GetString();

                                string serverIp = "";
                                await Dispatcher.UIThread.InvokeAsync(() => { serverIp = ServerIpBox.Text.Trim(); });

                                string fileUrl = $"http://{serverIp}/" + path.Replace("\\", "/");

                                Console.WriteLine(
                                    $"[DEBUG]\nFile Name: {fileName}\nFile Type:{fileType}\nPath: {path}\nFile Url: {fileUrl}");

                                Dispatcher.UIThread.Invoke(() => AddFileMessage(fileName, fileType, fileUrl));
                                continue;
                            }

                            if (type == "text")
                            {
                                string textData = root.GetProperty("data").GetString();

                                Console.WriteLine($"[DEBUG]\nText Data: {textData}");

                                Dispatcher.UIThread.Invoke(() => AddMessage(textData));
                                continue;
                            }
                        }

                        Dispatcher.UIThread.Invoke(() => AddMessage(decryptedMessage));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Receive Loop error: {e.ToString()}");

                        Dispatcher.UIThread.Invoke(() => AddMessage(decryptedMessage));
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Invoke(() => AddMessage($"[Ошибка]: {ex.Message}"));
            
            await _socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "Closing",
                CancellationToken.None);
            ConnectButton.Content = "Подключиться";
            _connected = false;
            AddMessage("Отключено от сервера.");
        }
    }

    private async void AddFileMessage(string fileName, string fileType, string filePath)
    {
        MessagesPanel.Children.Add(new TextBlock
        {
            Text = $"Файл: {fileName}",
            Foreground = Brushes.LightGray,
            Margin = new Thickness(0, 0, 0, 2)
        });

        if (fileType.StartsWith("image/"))
        {
            try
            {
                using var httpClient = new HttpClient();
                var bytes = await httpClient.GetByteArrayAsync(filePath);
                using var ms = new MemoryStream(bytes);
                var bitmap = new Bitmap(ms);

                var image = new Image
                {
                    Source = bitmap,
                    Width = 300,
                    Height = 300,
                    Stretch = Stretch.Uniform,
                    Margin = new Thickness(0, 0, 0, 10)
                };

                MessagesPanel.Children.Add(image);
            }
            catch (Exception ex)
            {
                AddMessage("[Ошибка загрузки изображения]: " + ex.Message);
            }
        }

        var download = new Button
        {
            Content = "Открыть файл",
            Tag = filePath,
            Margin = new Thickness(0, 0, 0, 10)
        };
        download.Click += (_, _) => Process.Start(new ProcessStartInfo(filePath) { UseShellExecute = true });
        MessagesPanel.Children.Add(download);
    }

    private void AddMessage(string fullMessage)
    {
        var textBlock = new TextBlock
        {
            Text = fullMessage,
            Foreground = Brushes.White,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 5)
        };
        MessagesPanel.Children.Add(textBlock);
    }

    private async Task SendMessage()
    {
        if (!_connected || _socket.State != WebSocketState.Open)
        {
            ShowMessage("Ошибка", "Соединение не установлено.");
            return;
        }

        string nickname = NicknameBox.Text?.Trim() ?? string.Empty;
        string message = MessageBox.Text?.Trim() ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(message))
        {
            var msgObj = new { type = "text", data = $"{nickname}: {message}" };
            string jsonMessage = JsonSerializer.Serialize(msgObj);
            jsonMessage = CryptoUtils.EncryptString(jsonMessage, EncryptionKey);
            jsonMessage += MyVersion + $"<token:{_token}>";

            var bytes = Encoding.UTF8.GetBytes(jsonMessage);

            try
            {
                await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, _cts.Token);
                Dispatcher.UIThread.Invoke(() =>
                {
                    AddMessage($"{nickname}: {message}");
                    MessageBox.Text = string.Empty;
                });
            }
            catch (Exception ex)
            {
                ShowMessage("Ошибка отправки", ex.Message);
            }
        }
    }

    private async void SendButton_Click(object? sender, RoutedEventArgs e) => await SendMessage();

    private async void MessageBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            await SendMessage();
            e.Handled = true;
        }
    }

    protected override async void OnClosing(WindowClosingEventArgs e)
    {
        base.OnClosing(e);
        await Disconnect();
    }

    private void ClearMessages_Click(object? sender, RoutedEventArgs e)
    {
        MessagesPanel.Children.Clear();
    }

    private void MainWindow_OnLoaded(object? sender, EventArgs e)
    {
        AddMessage("Введите IP и нажмите 'Подключиться'.");
    }

    private static string GetMimeType(string filePath)
    {
        return Path.GetExtension(filePath).ToLowerInvariant() switch
        {
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".bmp" => "image/bmp",
            ".gif" => "image/gif",
            _ => "application/octet-stream",
        };
    }

    private static string GenerateToken(int byteLength = 32)
    {
        byte[] tokenBytes = RandomNumberGenerator.GetBytes(byteLength);
        return Convert.ToBase64String(tokenBytes);
    }

    private void ShowMessage(string title, string message)
    {
        AddMessage($"[{title}] {message}");
    }
}
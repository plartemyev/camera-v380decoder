using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace V380Decoder.src
{
    public class DispatchRelayServer
    {
        private readonly static string dispatchUrl = "http://dispa1.av380.net:8001/api/v1/get_stream_server";
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            TypeInfoResolver = AppJsonSerializerContext.Default,
            PropertyNameCaseInsensitive = true
        };
        public static async Task<string> GetServerIPAsync(int deviceId)
        {
            var ips = await GetServerIPsAsync(deviceId);
            return ips.FirstOrDefault(string.Empty);
        }

        /// All dispatch relays (ordered), reachable on :8800. The camera is attached
        /// only to some of them - a relay without the camera returns "offline" codes
        /// (resp463 result=2002), so callers rotate through the list.
        public static async Task<List<string>> GetServerIPsAsync(int deviceId)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            int platform = 10001; // 20001 pano device
            string baseString = $"dev_id={deviceId}&platform={platform}&timestamp={timestamp}hsdata2022";
            string sign = ComputeSha1Hash(baseString);

            DispatchRequest request = new()
            {
                dev_id = deviceId,
                platform = platform,
                timestamp = timestamp,
                sign = sign
            };

            string json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var ips = new List<string>();
            using var client = new HttpClient();
            var response = await client.PostAsync(dispatchUrl, content);
            if (!response.IsSuccessStatusCode)
                return ips;

            string responseBody = await response.Content.ReadAsStringAsync();
            DispatchResult result = JsonSerializer.Deserialize<DispatchResult>(responseBody, _jsonOptions);
            if (result.code != 2000)
                return ips;

            foreach (var item in result.data)
            {
                if (await IsServerReachableAsync(item.ip, 8800))
                {
                    ips.Add(item.ip);
                }
            }
            return ips;
        }

        private static string ComputeSha1Hash(string input)
        {
            using SHA1 sha1 = SHA1.Create();
            byte[] hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }


        private static async Task<bool> IsServerReachableAsync(string ip, int port, int timeoutMs = 3000)
        {
            using var client = new TcpClient();
            try
            {
                var connectTask = client.ConnectAsync(ip, port);
                var timeoutTask = Task.Delay(timeoutMs);
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                if (completedTask == connectTask && client.Connected)
                {
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}

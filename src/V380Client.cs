using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace V380Decoder.src
{
    public class V380Client : IDisposable
    {
        public SnapshotManager snapshotManager { get; private set; }
        public int Channel { get; set; } = 0;
        public ushort lastStreamToken { get; private set; } = 0x3001;
        public int lastRelayStatus { get; private set; } = -1;
        private TcpClient authClient, streamClient;
        private NetworkStream authStream, streamStream;
        // modern (v31+) cloud session: control connection (cmd361) + live video connection (cmd363)
        private TcpClient? controlClient, liveClient;
        private NetworkStream? controlStream, liveStream;
        private uint recordSize = 2040;   // resp463[0x4c]
        private uint serverEpoch;         // resp463[8]
        private volatile bool controlPingPending;
        private CancellationTokenSource? controlKaCts;
        private readonly string ip;
        private readonly int port;
        private readonly uint deviceId;
        private readonly string username, password;
        private readonly SourceStream source;
        private readonly OutputMode mode;
        private readonly int streamQuality;
        private uint authTicket, sessionId;
        private ushort deviceVersion, communicationVersion;
        private int frameWidth = 1280;
        private int frameheight = 720;
        private byte[] aesKey = new byte[16];
        private StreamWriter? frameDump;
        private bool frameDumpEnabled = false;
        private bool needReconnect = false;

        public V380Client(string ip, int port, uint deviceId, string username, string password, SourceStream source, OutputMode mode, int streamQuality)
        {
            this.ip = ip;
            this.port = port;
            this.deviceId = deviceId;
            this.username = username;
            this.password = password;
            this.source = source;
            this.mode = mode;
            this.streamQuality = streamQuality;
            if (mode == OutputMode.Rtsp)
                snapshotManager = new SnapshotManager();
        }

        public void Run(RtspServer rtsp, CancellationToken ct)
        {
         try
         {
          frameDumpEnabled = File.Exists("/home/favour/camera/frame_dump.bin");
          if (frameDumpEnabled)
          {
           frameDump = new StreamWriter(new FileStream("/home/favour/camera/frame_dump.log", FileMode.Append, FileAccess.Write, FileShare.Read));
           frameDump.AutoFlush = true;
           LogUtils.debug("[DUMP] frame dump ENABLED - writing to /home/favour/camera/frame_dump.bin and .log");
          }
         }
         catch { }

         while (!ct.IsCancellationRequested)
            {
                try
                {
                    int auth = GetAuthTicket();
                    if (auth == 0) continue;
                    if (auth == -1) break;

                    if (source == SourceStream.Cloud && deviceVersion > 30)
                    {
                        RunModernCloudSession(rtsp, ct);
                        continue;
                    }

                    if (!StreamLogin())
                    {
                        Console.Error.WriteLine("[STREAM] Retrying...");
                        streamStream?.Close(); streamClient?.Close();
                        continue;
                    }

                    if (!StartStream())
                    {
                        Console.Error.WriteLine("[STREAM] Retrying...");
                        continue;
                    }

                    ReceiveFrames(mode, rtsp, ct);
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine("[STREAM] Operation cancelled");
                    break;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[ERROR] Fatal error: {ex.Message}");
                    Console.Error.WriteLine($"[ERROR] Stack trace: {ex.StackTrace}");
                    Thread.Sleep(3000);
                }
                finally
                {
                    Console.Error.WriteLine("[STREAM] Closing connection...");
                    streamStream?.Close(); streamClient?.Close();
                }
            }
        }

        public int GetAuthTicket()
        {
            try
            {
                authClient = new TcpClient();
                var r = authClient.BeginConnect(ip, port, null, null);
                if (!r.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
                {
                    Console.Error.WriteLine("[AUTH] failed connecting to socket. retrying...");
                    return 0;
                }
                authClient.EndConnect(r);
                authStream = authClient.GetStream();

                var encryptedPassword = GeneratePassword(password);
                var userBytes = Encoding.ASCII.GetBytes(username);
                var cmd1167 = new byte[520];
                WriteUInt32LE(cmd1167, 0, 1167); // command
                if (source == SourceStream.Lan)
                {
                    WriteUInt32LE(cmd1167, 4, 120); // unknown1
                    cmd1167[8] = 31; // unknown2 (version?)
                    WriteUInt32LE(cmd1167, 9, 1); // unknown3            
                    WriteUInt32LE(cmd1167, 13, deviceId); // deviceId
                    Array.Copy(userBytes, 0, cmd1167, 49, Math.Min(userBytes.Length, 32)); //username
                    Array.Copy(encryptedPassword, 0, cmd1167, 81, Math.Min(encryptedPassword.Length, 64)); //password
                }
                else
                {
                    WriteUInt32LE(cmd1167, 4, 1022); // unknown1
                    cmd1167[8] = 31; // unknown2 (version?)
                    WriteUInt32LE(cmd1167, 9, 1); // unknown3 
                    WriteUInt32LE(cmd1167, 13, deviceId); // deviceId
                    var hostnameBytes = Encoding.ASCII.GetBytes($"{deviceId}.nvdvr.net");
                    Array.Copy(hostnameBytes, 0, cmd1167, 17, Math.Min(hostnameBytes.Length, 50)); //hostname
                    WriteUInt32LE(cmd1167, 67, (uint)port); //port
                    Array.Copy(userBytes, 0, cmd1167, 71, Math.Min(userBytes.Length, 32)); //username
                    Array.Copy(encryptedPassword, 0, cmd1167, 103, Math.Min(encryptedPassword.Length, 64)); //password
                }
                if (!SendData(authStream, cmd1167))
                {
                    Console.Error.WriteLine("[AUTH] failed send request. retrying...");
                    return 0;
                }

                var resp = ReceiveData(authStream, 256);
                if (resp == null || resp.Length < 256)
                {
                    Console.Error.WriteLine("[AUTH] failed receive response. retrying...");
                    return 0;
                }

                uint respCmd = ReadUInt32LE(resp, 0);
                if (respCmd != 1168)
                {
                    Console.Error.WriteLine($"[AUTH] invalid response cmd: {respCmd} (expected 1168). retrying...");
                    return 0;
                }
                uint loginResult = ReadUInt32LE(resp, 4);
                if (loginResult != 1001 && loginResult != 1002)
                {
                    if (loginResult == 1011)
                        Console.Error.WriteLine($"[AUTH] invalid username. exiting...");
                    else if (loginResult == 1012)
                        Console.Error.WriteLine($"[AUTH] invalid password. exiting...");
                    else if (loginResult == 1018)
                        Console.Error.WriteLine($"[AUTH] invalid device id. exiting...");
                    else
                        Console.Error.WriteLine($"[AUTH] login failed result: {loginResult} (expected 1001). exiting...");

                    return -1;
                }

                uint resultValue = ReadUInt32LE(resp, 8);
                byte version = resp[12];
                uint ticket = ReadUInt32LE(resp, 13);
                uint session = ReadUInt32LE(resp, 17);
                byte deviceType = resp[21];
                byte camType = resp[22];
                uint vendorId = ReadUInt16LE(resp, 23);
                uint isDomainExists = resp[25];
                byte[] domainBytes = new byte[32];
                Array.Copy(resp, 26, domainBytes, 0, 32);
                string domain = Encoding.ASCII.GetString(domainBytes).TrimEnd('\0');

                LogUtils.debug($"[AUTH] response success");
                LogUtils.debug($"[AUTH] cmd: {respCmd}");
                LogUtils.debug($"[AUTH] result: {loginResult}");
                LogUtils.debug($"[AUTH] authTicket: {ticket} (0x{ticket:X})");
                LogUtils.debug($"[AUTH] resultValue: {resultValue}");
                LogUtils.debug($"[AUTH] version: {version}");
                LogUtils.debug($"[AUTH] session: {session}");
                LogUtils.debug($"[AUTH] deviceType: {deviceType}");
                LogUtils.debug($"[AUTH] camType: {camType}");
                LogUtils.debug($"[AUTH] vendorId: {vendorId}");
                LogUtils.debug($"[AUTH] isDomainExists: {isDomainExists}");
                LogUtils.debug($"[AUTH] domain: {domain}");

                deviceVersion = version;
                sessionId = session;
                authTicket = ticket;

                Console.Error.WriteLine($"[AUTH] success ticket={authTicket} deviceVersion={deviceVersion}");
                authStream.Close(); authClient.Close();
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[AUTH] Error: {ex.Message}");
                return 0;
            }
            finally
            {
                authStream?.Close(); authClient?.Close();
            }
        }


        // ---------------------------------------------------------------------
        // Modern cloud session (v31 firmware, observed on Android app 2026-10-14)
        //
        //   conn A (control): cmd361 [4]=1012 -> resp2000; server pings cmd2000,
        //                     client answers cmd362 (16B)
        //   conn B (live):    cmd363 [4]=1002, [74]=date, [78]=time -> resp463
        //                     (64B: [4]=1000, [8]=epoch, [0x14w]=31, [0x4c]=recordSize)
        //                     -> cmd364 sub1 -> server cmd111 (8B) -> cmd364 sub2
        //                     -> records: 7f [type] [seq] [flag] [len:LE32] payload
        //                     -> cmd364 every ~2.5s; close = cmd1008
        // ---------------------------------------------------------------------

        void BuildCloudLogin(byte[] cmd, uint cmdId, uint subcode, bool withDateTime)
        {
            WriteUInt32LE(cmd, 0, cmdId);
            WriteUInt32LE(cmd, 4, subcode);
            var hostnameBytes = Encoding.ASCII.GetBytes($"{deviceId}.nvdvr.net");
            Array.Copy(hostnameBytes, 0, cmd, 8, Math.Min(hostnameBytes.Length, 50));
            WriteUInt32LE(cmd, 58, (uint)port);
            WriteUInt32LE(cmd, 62, deviceId);
            WriteUInt32LE(cmd, 66, authTicket);
            WriteUInt32LE(cmd, 70, sessionId != 0 ? sessionId : authTicket);
            if (withDateTime)
            {
                var now = DateTime.Now;
                WriteUInt16LE(cmd, 74, (ushort)now.Year);
                cmd[76] = (byte)now.Month;
                cmd[77] = (byte)now.Day;
                cmd[78] = (byte)now.Hour;
                cmd[79] = (byte)now.Minute;
                cmd[80] = (byte)now.Second;
            }
        }

        void RunModernCloudSession(RtspServer rtsp, CancellationToken ct)
        {
            Console.Error.WriteLine("[MODERN] starting v31 cloud session (control 361 + live 363)");
            try
            {
                if (!SessionConnect())
                {
                    Console.Error.WriteLine("[MODERN] control connection failed");
                    Thread.Sleep(3000);
                    return;
                }
                if (!LiveLogin())
                {
                    Console.Error.WriteLine("[MODERN] live login failed");
                    CloseModern();
                    Thread.Sleep(3000);
                    return;
                }
                ReceiveLiveFrames(rtsp, ct);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[MODERN] error: {ex.Message}");
            }
            finally
            {
                CloseModern();
            }
        }

        bool SessionConnect()
        {
            controlClient = new TcpClient { NoDelay = true, ReceiveBufferSize = 0x8000 };
            var r = controlClient.BeginConnect(ip, port, null, null);
            if (!r.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
            {
                Console.Error.WriteLine("[CTRL] connect timeout");
                controlClient.Close(); controlClient = null;
                return false;
            }
            controlClient.EndConnect(r);
            controlStream = controlClient.GetStream();

            var cmd361 = new byte[256];
            BuildCloudLogin(cmd361, 361, 1012, withDateTime: false);
            if (!SendData(controlStream, cmd361)) return false;

            var resp = ReceiveExact(controlStream, 256, 10);
            if (resp == null || ReadUInt32LE(resp, 0) != 2000)
            {
                Console.Error.WriteLine($"[CTRL] unexpected response: {(resp == null ? "null" : ReadUInt32LE(resp, 0).ToString())} (expected 2000)");
                return false;
            }
            Console.Error.WriteLine("[CTRL] session established (resp2000)");

            // background thread: answer every server cmd2000 ping with cmd362
            controlKaCts = new CancellationTokenSource();
            var kaCt = controlKaCts.Token;
            var kaStream = controlStream;
            var kaThread = new Thread(() =>
            {
                var pingBuf = new byte[16];
                while (!kaCt.IsCancellationRequested)
                {
                    try
                    {
                        if (!kaStream.DataAvailable) { Thread.Sleep(100); continue; }
                        int n = kaStream.Read(pingBuf, 0, 16);
                        if (n <= 0) break;
                        uint c = ReadUInt32LE(pingBuf, 0);
                        if (c == 2000)
                        {
                            var cmd362 = new byte[16];
                            WriteUInt32LE(cmd362, 0, 362);
                            kaStream.Write(cmd362, 0, 16);
                        }
                        else
                        {
                            Console.Error.WriteLine($"[CTRL] unexpected server cmd {c}");
                        }
                    }
                    catch { break; }
                }
            });
            kaThread.IsBackground = true;
            kaThread.Start();
            return true;
        }

        bool LiveLogin()
        {
            liveClient = new TcpClient { NoDelay = true, ReceiveBufferSize = 0x8000 };
            var r = liveClient.BeginConnect(ip, port, null, null);
            if (!r.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
            {
                Console.Error.WriteLine("[LIVE] connect timeout");
                liveClient.Close(); liveClient = null;
                return false;
            }
            liveClient.EndConnect(r);
            liveStream = liveClient.GetStream();

            var cmd363 = new byte[256];
            BuildCloudLogin(cmd363, 363, 1002, withDateTime: true);
            if (!SendData(liveStream, cmd363)) return false;

            var resp463 = ReceiveExact(liveStream, 64, 10);
            if (resp463 == null || ReadUInt32LE(resp463, 0) != 463)
            {
                Console.Error.WriteLine($"[LIVE] unexpected response: {(resp463 == null ? "null" : (resp463.Length >= 4 ? ReadUInt32LE(resp463, 0).ToString() : "short"))} (expected 463)");
                return false;
            }
            uint result = ReadUInt32LE(resp463, 4);
            serverEpoch = ReadUInt32LE(resp463, 8);
            recordSize = resp463.Length >= 0x50 ? ReadUInt32LE(resp463, 0x4c) : 2040;
            if (recordSize == 0 || recordSize > 65536) recordSize = 2040;
            Console.Error.WriteLine($"[LIVE] resp463 result={result} epoch={serverEpoch} recordSize={recordSize} ver={ReadUInt16LE(resp463, 0x14)}");

            // handshake: cmd364 sub1 -> (server cmd111) -> cmd364 sub2
            SendCmd364(1);
            var srv = ReceiveExact(liveStream, 8, 5);
            if (srv != null)
                Console.Error.WriteLine($"[LIVE] server ack: cmd={ReadUInt32LE(srv, 0)} [{BitConverter.ToString(srv)}]");
            SendCmd364(2);
            Console.Error.WriteLine("[LIVE] login complete, expecting records");
            return true;
        }

        void SendCmd364(uint sub)
        {
            var cmd364 = new byte[32];
            WriteUInt32LE(cmd364, 0, 364);
            WriteUInt16LE(cmd364, 4, (ushort)sub);
            WriteUInt16LE(cmd364, 6, 200);
            WriteUInt32LE(cmd364, 12, serverEpoch);
            if (liveStream != null) SendData(liveStream, cmd364);
        }

        void ReceiveLiveFrames(RtspServer rtsp, CancellationToken ct)
        {
            var s = liveStream!;
            var dumpPath = Environment.GetEnvironmentVariable("V380_LIVE_DUMP");
            FileStream? dump = null;
            if (!string.IsNullOrEmpty(dumpPath))
            {
                dump = new FileStream(dumpPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                Console.Error.WriteLine($"[LIVE] dumping records to {dumpPath}");
            }

            // frame assembly state per sub-stream (flag byte)
            var chains = new Dictionary<uint, List<byte>>();
            var lastSeq = new Dictionary<uint, ushort>();
            long recCount = 0, videoDispatched = 0;
            var kaDeadline = DateTime.Now.AddSeconds(2.5);

            Console.Error.WriteLine("[RECV-LIVE] record loop started");
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    // periodic cmd364 keepalive (~2.5s), like the app
                    if (DateTime.Now > kaDeadline)
                    {
                        SendCmd364(2);
                        kaDeadline = DateTime.Now.AddSeconds(2.5);
                    }

                    int hdr = SyncAndReadHeader(s, out uint type, out ushort seq, out uint flag, out uint len);
                    if (hdr == 0) { needReconnect = true; break; }
                    if (len == 0 || len > 100000)
                    {
                        Console.Error.WriteLine($"[RECV-LIVE] bogus len={len}, resyncing");
                        continue;
                    }

                    var payload = new byte[len];
                    if (ReadExact(s, payload, 0, (int)len) < (int)len)
                    {
                        Console.Error.WriteLine("[RECV-LIVE] payload read failed");
                        needReconnect = true;
                        break;
                    }
                    recCount++;
                    dump?.Write(payload, 0, payload.Length);
                    if (recCount <= 12 || recCount % 200 == 0)
                        Console.Error.WriteLine($"[RECV-LIVE] rec#{recCount} type={type} seq={seq} flag={flag} len={len} head={BitConverter.ToString(payload, 0, Math.Min(16, payload.Length))}");

                    if (type == 0x16 || type == 0x1A)
                    {
                        // audio record - dump only for now
                        continue;
                    }
                    if (type > 1)
                    {
                        Console.Error.WriteLine($"[RECV-LIVE] unhandled record type={type}");
                        continue;
                    }

                    // video: chain records per sub-stream; a new frame starts when
                    // seq restarts (<= last seq) or the record is short (len < recordSize)
                    uint key = flag;
                    bool startNew = !chains.TryGetValue(key, out var chain) || chain.Count == 0
                                    || (lastSeq.TryGetValue(key, out var ls) && seq <= ls)
                                    || len < recordSize;
                    if (startNew && chain != null && chain.Count > 0)
                    {
                        DispatchLiveVideo(chain, type, mode, rtsp);
                        videoDispatched++;
                        chain = new List<byte>();
                    }
                    if (chain == null) { chain = new List<byte>(); chains[key] = chain; }
                    chain.AddRange(payload);
                    lastSeq[key] = seq;
                }
            }
            finally
            {
                dump?.Dispose();
                Console.Error.WriteLine($"[RECV-LIVE] loop ended: recs={recCount} videoFrames={videoDispatched}");
            }
        }

        void DispatchLiveVideo(List<byte> chain, uint type, OutputMode mode, RtspServer rtsp)
        {
            var full = chain.ToArray();
            LogUtils.debug($"[LIVE-FRAME] type={type} len={full.Length} head={BitConverter.ToString(full, 0, Math.Min(24, full.Length))}");
            if (!HandleAsMediaFrame((byte)type, full, needDecrypt: deviceVersion > 30, mode, rtsp, null))
            {
                Console.Error.WriteLine($"[LIVE-FRAME] unroutable type={type} len={full.Length} head={BitConverter.ToString(full, 0, Math.Min(16, full.Length))}");
            }
        }

        /// Reads a V380 record header (7f type seq flag len32), byte-syncing on 0x7f.
        /// Returns total header bytes consumed (always 8), 0 on stream end/timeout.
        int SyncAndReadHeader(NetworkStream s, out uint type, out ushort seq, out uint flag, out uint len)
        {
            type = 0; seq = 0; flag = 0; len = 0;
            var buf = new byte[8];
            // byte-wise sync on 0x7f (records start 7f XX XX XX len32)
            if (!ReadByteOrTimeout(s, out byte b0)) return 0;
            while (b0 != 0x7f)
            {
                Console.Error.WriteLine($"[RECV-LIVE] sync skip byte {b0:X2}");
                if (!ReadByteOrTimeout(s, out b0)) return 0;
            }
            buf[0] = b0;
            for (int i = 1; i < 8; i++)
            {
                if (!ReadByteOrTimeout(s, out buf[i])) return 0;
            }
            type = buf[1];
            seq = buf[2];
            flag = buf[3];
            len = ReadUInt32LE(buf, 4);
            return 8;
        }

        bool ReadByteOrTimeout(NetworkStream s, out byte b)
        {
            b = 0;
            var deadline = DateTime.Now.AddSeconds(15);
            while (DateTime.Now < deadline)
            {
                if (s.DataAvailable)
                {
                    int n = s.Read(m_singleByte, 0, 1);
                    if (n == 1) { b = m_singleByte[0]; return true; }
                    return false;
                }
                Thread.Sleep(5);
            }
            needReconnect = true;
            return false;
        }
        private readonly byte[] m_singleByte = new byte[1];

        byte[]? ReceiveExact(NetworkStream s, int cnt, int timeoutSec)
        {
            var buf = new byte[cnt];
            int tot = 0;
            var deadline = DateTime.Now.AddSeconds(timeoutSec);
            while (tot < cnt && DateTime.Now < deadline)
            {
                if (!s.DataAvailable) { Thread.Sleep(10); continue; }
                int n = s.Read(buf, tot, cnt - tot);
                if (n <= 0) break;
                tot += n;
            }
            if (tot == 0) return null;
            if (tot < cnt)
            {
                var r = new byte[tot]; Array.Copy(buf, r, tot); return r;
            }
            return buf;
        }

        void CloseModern()
        {
            try
            {
                if (liveStream != null)
                {
                    var bye = new byte[16];
                    WriteUInt32LE(bye, 0, 1008);
                    liveStream.Write(bye, 0, 16);
                }
            }
            catch { }
            try { controlKaCts?.Cancel(); } catch { }
            try { liveStream?.Close(); liveClient?.Close(); } catch { }
            try { controlStream?.Close(); controlClient?.Close(); } catch { }
            liveStream = null; liveClient = null; controlStream = null; controlClient = null;
        }


        public bool StreamLogin()
        {
            streamClient = new TcpClient
            {
                NoDelay = true,
                ReceiveBufferSize = 0x8000
            };
            var r = streamClient.BeginConnect(ip, port, null, null);
            if (!r.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
            {
                Console.Error.WriteLine("[STREAM] failed connecting to socket. retrying...");
                return false;
            }
            ;
            streamClient.EndConnect(r);
            streamStream = streamClient.GetStream();

            var cmd301 = new byte[256];
            WriteUInt32LE(cmd301, 0, 301);
            if (source == SourceStream.Lan)
            {
                WriteUInt32LE(cmd301, 4, deviceId); //device id
                WriteUInt32LE(cmd301, 8, 0); //unknown1 
                WriteUInt16LE(cmd301, 12, 20); //unknown2 
                WriteUInt32LE(cmd301, 14, authTicket); //auth ticket
                WriteUInt32LE(cmd301, 22, 4097); //audio 4096=off, 4097=on
                WriteUInt32LE(cmd301, 26, (uint)streamQuality);    //quality  0=SD, 1=HD
            }
            else
            {
                // GetImageMR layout, matching the Android app byte-for-byte
                // (capture 2026-10-14: [4]=1002, [74]=1, [78]=20, [80]=0x10, [82]=1, [87..89]=1)
                WriteUInt32LE(cmd301, 4, 1002); // subcode
                var hostnameBytes = Encoding.ASCII.GetBytes($"{deviceId}.nvdvr.net");
                Array.Copy(hostnameBytes, 0, cmd301, 8, Math.Min(hostnameBytes.Length, 50)); //hostname
                WriteUInt32LE(cmd301, 58, (uint)port); //port
                WriteUInt32LE(cmd301, 62, deviceId); //device id
                WriteUInt32LE(cmd301, 66, authTicket); // auth ticket
                uint activeSession = sessionId != 0 ? sessionId : authTicket;
                WriteUInt32LE(cmd301, 70, activeSession); // session id (fallback to authTicket if 0)
                WriteUInt32LE(cmd301, 74, 1); // flag: audio requested
                cmd301[78] = 20; // fps / version byte
                cmd301[80] = 0x10;
                cmd301[82] = 1;
                cmd301[87] = 1; cmd301[88] = 1; cmd301[89] = 1;
            }

            if (!SendData(streamStream, cmd301))
            {
                Console.Error.WriteLine("[STREAM] login failed send request");
                return false;
            }

            // App reads resp401 as exactly 32 bytes (16 header + 16 zero pad),
            // then a 12-byte "go" message before frames start. The old 412-byte
            // read swallowed the stream start into the header buffer.
            var resp401 = ReceiveExact(streamStream, 32, 10);

            if (resp401 == null || resp401.Length < 8)
            {
                Console.Error.WriteLine("[STREAM] login failed receive response");
                return false;
            }
            var respCmd = ReadUInt32LE(resp401, 0);
            if (respCmd != 401)
            {
                Console.Error.WriteLine($"[STREAM] login invalid response cmd: {respCmd} (expected 401)");
                return false;
            }

            int relayStatus = (int)ReadUInt32LE(resp401, 4);
            int deviceStatus = resp401.Length >= 12 ? (int)ReadUInt32LE(resp401, 8) : 0;
            int reasonCode = resp401.Length >= 16 ? (int)ReadUInt32LE(resp401, 12) : 0;

            // 12-byte stream-start message: 1f 00 05 d0 02 14 00 10 01 00 00 00
            var go = ReceiveExact(streamStream, 12, 10);
            Console.Error.WriteLine($"[STREAM] go message: {(go == null ? "none" : BitConverter.ToString(go))}");

            LogUtils.debug($"[STREAM] login raw hex: {BitConverter.ToString(resp401, 0, Math.Min(resp401.Length, 32))}");
            LogUtils.debug($"[STREAM] login relayStatus={relayStatus} (0x{relayStatus:X8}), deviceStatus={deviceStatus} (0x{deviceStatus:X8}), reasonCode={reasonCode}");

            if (source == SourceStream.Cloud)
            {
                // GetImageNew: resp401[8]=-12 ("unsupported as asked") is NOT fatal -
                // the Windows app proceeds (only resp401[4]==-11/-12 relay errors abort)
                if (relayStatus == -11 || relayStatus == -12)
                {
                    Console.Error.WriteLine($"[STREAM] login failed relayStatus={relayStatus}");
                    return false;
                }
                lastStreamToken = (ushort)(deviceStatus > 0 ? (ushort)deviceStatus : 0x3001);
                lastRelayStatus = relayStatus;
            }
            else
            {
                if (relayStatus == -11 || relayStatus == -12)
                {
                    Console.Error.WriteLine($"[STREAM] login failed result={relayStatus}");
                    return false;
                }
                lastStreamToken = (ushort)(relayStatus > 0 ? (ushort)relayStatus : 0x3001);
            }

            LogUtils.debug($"[STREAM] login response success");
            LogUtils.debug($"[STREAM] login cmd: {respCmd}");
            if (source == SourceStream.Lan)
            {
                ushort version = ReadUInt16LE(resp401, 8);
                uint width = ReadUInt32LE(resp401, 10);
                uint height = ReadUInt32LE(resp401, 14);
                uint maxPackSize = ReadUInt32LE(resp401, 18);
                byte audioFreq = resp401[22];
                byte audioBits = resp401[23];
                byte audioChannels = resp401[24];
                communicationVersion = version;
                frameWidth = (int)width;
                frameheight = (int)height;
                LogUtils.debug($"[STREAM] login result: {relayStatus}");
                LogUtils.debug($"[STREAM] login version: {version}");
                LogUtils.debug($"[STREAM] login width: {width}");
                LogUtils.debug($"[STREAM] login height: {height}");
                LogUtils.debug($"[STREAM] login maxPackSize: {maxPackSize}");
                LogUtils.debug($"[STREAM] login audioFreq: {audioFreq}");
                LogUtils.debug($"[STREAM] login audioBits: {audioBits}");
                LogUtils.debug($"[STREAM] login audioChannels: {audioChannels}");
            }

            if (deviceVersion > 30) GenerateMediaKey(authTicket);
            Console.Error.WriteLine($"[STREAM] login OK quality={(streamQuality == 0 ? "SD" : "HD")} channel={Channel}");
            return true;
        }

        public bool StartStream()
        {
            Console.Error.WriteLine($"[STREAM] starting stream (token=0x{lastStreamToken:X4}, echoRelayStatus={lastRelayStatus})...");
            var cmd303 = new byte[16];
            WriteUInt32LE(cmd303, 0, 303);
            if (source == SourceStream.Cloud)
            {
                // App sends a 16-byte cmd303 with token 0x3001 (capture 2026-10-14),
                // not an echo of resp401[4]
                WriteUInt32LE(cmd303, 4, 0x3001);
            }
            else
            {
                WriteUInt16LE(cmd303, 4, lastStreamToken);
            }
            return SendData(streamStream, cmd303);
        }

        public void ReceiveFrames(OutputMode mode, RtspServer rtsp, CancellationToken ct)
        {
            bool needDecrypt = deviceVersion > 30;

            var frameFrags = new List<byte>();
            ushort frameTotal = 0;
            ushort nextFragment = 0;
            byte frameStartType = 0;
            bool assemblingFrame = false;

            var header12 = new byte[12];
            var payloadBuf = new byte[65536];

            // stdout is used only for Video or Audio output modes
            Stream stdout = (mode == OutputMode.Video || mode == OutputMode.Audio)
                ? Console.OpenStandardOutput()
                : null;

            Console.Error.WriteLine($"[RECV] mode={mode} decrypt={needDecrypt} communicationVersion={communicationVersion}");

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    if (needReconnect)
                    {
                        Console.Error.WriteLine($"[STREAM] lost, reconnecting... ");
                        try { streamStream?.Close(); streamClient?.Close(); } catch { }
                        if (!StreamLogin()) break;
                        if (!StartStream()) break;
                        needReconnect = false;
                    }

                    // 12-byte fragment header (LAN dialect). Cloud+v31: raw-dump first
                    if (deviceVersion > 30 && source == SourceStream.Cloud)
                    {
                        // phased empirical probe: 30s passive, then 16B zero keepalives
                        var sw = System.Diagnostics.Stopwatch.StartNew();
                        var buf = new byte[4096];
                        var zeros = new byte[16];
                        while (!ct.IsCancellationRequested && sw.ElapsedMilliseconds < 60000)
                        {
                            int n = 0;
                            try { streamStream.ReadTimeout = 400; n = streamStream.Read(buf, 0, buf.Length); }
                            catch { n = 0; }
                            if (n > 0)
                                Console.Error.WriteLine($"[RAW t={sw.ElapsedMilliseconds}ms] n={n}: {Convert.ToHexString(buf, 0, Math.Min(n, 48))}");
                            if (sw.ElapsedMilliseconds > 30000)
                            {
                                try { streamStream.Write(zeros, 0, 16); Console.Error.WriteLine($"[KA t={sw.ElapsedMilliseconds}ms] sent 16 zero bytes"); } catch { }
                            }
                        }
                        needReconnect = true;
                        continue;
                    }
                    if (ReadExact(streamStream, header12, 0, 12) < 12) continue;

                    if (header12[0] != 0x7F)
                    {
                        continue;
                    }

                    byte type = header12[1];
                    ushort totalFrame = ReadUInt16LE(header12, 3);
                    ushort curFrame = ReadUInt16LE(header12, 5);
                    ushort payLen = ReadUInt16LE(header12, 7);

                    if (payLen == 0 || payLen > 20000 || totalFrame == 0 || curFrame >= totalFrame)
                    {
                        Console.Error.WriteLine($"[SKIP] invalid header type=0x{type:X2} total={totalFrame} cur={curFrame} len={payLen}");
                        continue;
                    }

                    if (payloadBuf.Length < payLen) payloadBuf = new byte[payLen];
                    if (ReadExact(streamStream, payloadBuf, 0, payLen) < payLen) continue;

                    if (type == 0x5B)
                    {
                        continue;
                    }

                    if (curFrame == 0 || !assemblingFrame || totalFrame != frameTotal || curFrame != nextFragment)
                    {
                        if (assemblingFrame && curFrame != 0)
                        {
                            LogUtils.debug($"[FRAME] resync from type=0x{frameStartType:X2} expected={nextFragment} got={curFrame} total={totalFrame}");
                        }

                        frameFrags.Clear();
                        frameTotal = totalFrame;
                        nextFragment = 0;
                        frameStartType = type;
                        assemblingFrame = true;
                    }

                    for (int i = 0; i < payLen; i++) frameFrags.Add(payloadBuf[i]);
                    nextFragment = (ushort)(curFrame + 1);

                    if (curFrame != totalFrame - 1) continue;
                    if (frameFrags.Count < 16)
                    {
                        frameFrags.Clear();
                        assemblingFrame = false;
                        continue;
                    }

                    byte[] full = frameFrags.ToArray();
                    frameFrags.Clear();
                    assemblingFrame = false;

                    if (!HandleAsMediaFrame(frameStartType, full, needDecrypt, mode, rtsp, stdout))
                    {
                        Console.Error.WriteLine($"[FRAME] unknown type=0x{frameStartType:X2} len={full.Length} head={BitConverter.ToString(full, 0, Math.Min(32, full.Length))}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
             Console.Error.WriteLine("[RECV] Operation cancelled");
             frameDump?.WriteLine($"[{DateTime.Now:HH:mm:ss}] Operation cancelled");
             frameDump?.Flush();
            }
            catch (Exception ex)
            {
             Console.Error.WriteLine($"[RECV] {ex.Message}");
             Console.Error.WriteLine($"[RECV] {ex.StackTrace}");
             frameDump?.WriteLine($"[{DateTime.Now:HH:mm:ss}] ERROR: {ex.Message}");
             frameDump?.Flush();
            }
            finally
            {
             // Don't dispose frameDump here - it's reused across reconnects
             // frameDump?.Dispose();
            }
            }

        private bool HandleAsMediaFrame(byte rawType, byte[] full, bool needDecrypt, OutputMode mode, RtspServer rtsp, Stream stdout)
        {
            ushort outerFrameType = full.Length >= 6 ? ReadUInt16LE(full, 4) : (ushort)0;
            uint outerFrameId = full.Length >= 4 ? ReadUInt32LE(full, 0) : 0;
            ushort outerFrameRate = full.Length >= 8 ? ReadUInt16LE(full, 6) : (ushort)0;
            ulong outerTimestamp = full.Length >= 16 ? ReadUInt64LE(full, 8) : 0;

            if (rawType == 0x1A)
            {
                if (full.Length < 16) return false;

                uint frameId = ReadUInt32LE(full, 0);
                ushort frameType = ReadUInt16LE(full, 4);
                ushort frameRate = ReadUInt16LE(full, 6);
                ulong timestamp = ReadUInt64LE(full, 8);

                byte[] payload = new byte[full.Length - 16];
                Array.Copy(full, 16, payload, 0, payload.Length);

                if (needDecrypt)
                {
                    if (communicationVersion == 21)
                        DecryptMediaPre2k(payload, payload.Length, 1);
                    else
                        DecryptAudioFrame(payload, payload.Length);
                }

                var audioFrame = new FrameData
                {
                    RawType = rawType,
                    FrameId = frameId,
                    FrameType = frameType,
                    FrameRate = frameRate,
                    Timestamp = timestamp,
                    Payload = payload
                };

                if (mode == OutputMode.Audio)
                {
                    stdout.Write(payload, 0, payload.Length);
                    stdout.Flush();
                }
                else if (mode == OutputMode.Rtsp)
                {
                    rtsp?.PushAudio(audioFrame);
                }

                return true;
            }

            if (rawType == 0x16)
            {
                byte[] audioPayload = ExtractAudioPayload(full, needDecrypt);
                if (audioPayload.Length == 0) return false;

                if (mode == OutputMode.Audio)
                {
                    stdout.Write(audioPayload, 0, audioPayload.Length);
                    stdout.Flush();
                }
                else if (mode == OutputMode.Rtsp)
                {
                    rtsp?.PushAudio(new FrameData
                    {
                        RawType = rawType,
                        FrameId = 0,
                        FrameType = 0,
                        FrameRate = 0,
                        Timestamp = 0,
                        Payload = audioPayload
                    });
                }

                return true;
            }

            if (rawType == 0x18 || rawType == 0x28 || rawType == 0x29 || rawType == 0x5C)
                        {
                         const int headerSize = 16;
                         if (full.Length <= headerSize) return false;
                         byte[] payload = new byte[full.Length - headerSize];
                         Array.Copy(full, headerSize, payload, 0, payload.Length);

                         // dump raw frame before decryption
                         if (frameDumpEnabled)
                         {
                          frameDump?.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] V rawType=0x{rawType:X2} len={full.Length} raw_head={BitConverter.ToString(full, 0, Math.Min(32, full.Length))}");
                          frameDump?.Flush();
                          var binPath = "/home/favour/camera/frame_dump.bin";
                          using var bfs = new FileStream(binPath, FileMode.Append, FileAccess.Write, FileShare.Read);
                          bfs.Write(full, 0, full.Length);
                         }

                         if (needDecrypt && payload.Length >= 16)
                         {
                          DecryptVideoFrame(payload, payload.Length);
                         }

                         // dump payload after decryption
                         if (frameDumpEnabled)
                         {
                          frameDump?.WriteLine($"  -> decrypted len={payload.Length} head={BitConverter.ToString(payload, 0, Math.Min(64, payload.Length))}");
                          frameDump?.Flush();
                          var binPath = "/home/favour/camera/frame_dump.bin";
                          using var bfs = new FileStream(binPath, FileMode.Append, FileAccess.Write, FileShare.Read);
                          bfs.Write(payload, 0, payload.Length);
                         }

                         bool keyFrame = IsKeyVideoFrame(rawType, outerFrameType, payload);
                         if (mode == OutputMode.Rtsp)
                         {
                          snapshotManager.UpdateFrame(payload, frameWidth, frameheight, keyFrame, outerTimestamp);
                         }
                         var vFrame = new FrameData
                         {
                          RawType = rawType,
                          FrameId = outerFrameId,
                          FrameType = outerFrameType,
                          FrameRate = outerFrameRate,
                          Timestamp = outerTimestamp,
                          Codec = VideoCodec.H265,
                          Payload = payload
                         };
                         if (mode == OutputMode.Video)
                         {
                          stdout?.Write(payload, 0, payload.Length);
                          stdout?.Flush();
                         }
                         else if (mode == OutputMode.Rtsp)
                         {
                          rtsp?.PushVideo(vFrame);
                         }
                         return true;
                        }
            if (!TryExtractVideoPayload(full, needDecrypt, out var normalizedPayload))
            {
                LogUtils.debug($"[FRAME] unclassified type=0x{rawType:X2} len={full.Length} head={BitConverter.ToString(full, 0, Math.Min(16, full.Length))}");
                return false;
            }

            bool isKeyFrame = IsKeyVideoFrame(rawType, outerFrameType, normalizedPayload);

            if (mode == OutputMode.Rtsp)
            {
                snapshotManager.UpdateFrame(normalizedPayload, frameWidth, frameheight, isKeyFrame, outerTimestamp);
            }

            var videoFrame = new FrameData
            {
                RawType = rawType,
                FrameId = outerFrameId,
                FrameType = outerFrameType,
                FrameRate = outerFrameRate,
                Timestamp = outerTimestamp,
                Codec = DetectVideoCodec(normalizedPayload),
                Payload = normalizedPayload
            };

            if (mode == OutputMode.Video)
            {
                stdout.Write(normalizedPayload, 0, normalizedPayload.Length);
                stdout.Flush();
            }
            else if (mode == OutputMode.Rtsp)
            {
                rtsp?.PushVideo(videoFrame);
            }

            return true;
        }

        private byte[] ExtractAudioPayload(byte[] full, bool needDecrypt)
        {
            byte[] payload;

            if (full.Length > 20)
            {
                payload = new byte[full.Length - 20];
                Array.Copy(full, 20, payload, 0, payload.Length);
            }
            else
            {
                payload = (byte[])full.Clone();
            }

            if (needDecrypt && payload.Length >= 16)
            {
                if (communicationVersion == 21)
                    DecryptMediaPre2k(payload, payload.Length, 1);
                else
                    DecryptAudioFrame(payload, payload.Length);
            }

            return payload;
        }

        private bool TryExtractVideoPayload(byte[] full, bool needDecrypt, out byte[] normalizedPayload)
        {
            int bestScore = int.MinValue;
            byte[] bestPayload = null;

            foreach (var payload in EnumerateVideoCandidates(full, needDecrypt))
            {
                if (!TryNormalizeVideoPayload(payload, out var candidate))
                    continue;

                int score = ScoreVideoPayload(candidate);
                if (score > bestScore)
                {
                    bestScore = score;
                    bestPayload = candidate;
                }
            }

            if (bestPayload != null)
            {
                normalizedPayload = bestPayload;
                return true;
            }

            normalizedPayload = Array.Empty<byte>();
            return false;
        }

        private IEnumerable<byte[]> EnumerateVideoCandidates(byte[] full, bool needDecrypt)
        {
            foreach (int offset in new[] { 0, 4, 8, 12, 16, 20 })
            {
                if (full.Length <= offset) continue;

                byte[] direct = new byte[full.Length - offset];
                Array.Copy(full, offset, direct, 0, direct.Length);

                if (needDecrypt && direct.Length >= 16)
                {
                    byte[] decrypted = (byte[])direct.Clone();
                    if (communicationVersion == 21)
                        DecryptMediaPre2k(decrypted, decrypted.Length, 1);
                    else
                        DecryptVideoFrame(decrypted, decrypted.Length);
                    yield return decrypted;
                }

                yield return direct;
            }
        }

        private bool TryNormalizeVideoPayload(byte[] payload, out byte[] normalizedPayload)
        {
            int start = FindVideoStartCode(payload);
            if (start < 0)
            {
                normalizedPayload = payload;
                return false;
            }

            if (payload[start] == 0 && payload[start + 1] == 0 && payload[start + 2] == 1)
            {
                normalizedPayload = new byte[payload.Length - start + 1];
                normalizedPayload[0] = 0;
                Array.Copy(payload, start, normalizedPayload, 1, payload.Length - start);
                return true;
            }

            normalizedPayload = new byte[payload.Length - start];
            Array.Copy(payload, start, normalizedPayload, 0, normalizedPayload.Length);
            return true;
        }

        private bool IsKeyVideoFrame(byte rawType, ushort frameType, byte[] payload)
        {
            if (rawType == 0x00 || rawType == 0x5C) return true;

            int nalOffset = payload.Length >= 4 && payload[2] == 0 && payload[3] == 1 ? 4 : 3;
            if (payload.Length <= nalOffset) return false;

            byte nalHeader = payload[nalOffset];
            int h264NalType = nalHeader & 0x1F;
            if (h264NalType == 5 || h264NalType == 7 || h264NalType == 8) return true;

            int h265NalType = (nalHeader >> 1) & 0x3F;
            if (h265NalType is 19 or 20 or 32 or 33 or 34) return true;

            return frameType == 0;
        }

        private int FindVideoStartCode(byte[] payload)
        {
            int limit = Math.Min(payload.Length - 4, 128);
            for (int i = 0; i <= limit; i++)
            {
                if (payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 0 && payload[i + 3] == 1)
                {
                    if (IsLikelyNalHeader(payload, i + 4)) return i;
                }

                if (payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 1)
                {
                    if (IsLikelyNalHeader(payload, i + 3)) return i;
                }
            }

            return -1;
        }

        private int ScoreVideoPayload(byte[] payload)
        {
            int score = 0;
            int nalCount = 0;
            int parameterSetCount = 0;
            int idrCount = 0;

            int i = 0;
            while (i < payload.Length - 4 && nalCount < 12)
            {
                int sc = FindNextStartCode(payload, i);
                if (sc < 0) break;

                int scLen = payload[sc + 2] == 1 ? 3 : 4;
                int nalStart = sc + scLen;
                if (!IsLikelyNalHeader(payload, nalStart))
                {
                    i = sc + 1;
                    score -= 20;
                    continue;
                }

                nalCount++;
                byte nalHeader = payload[nalStart];
                int h264NalType = nalHeader & 0x1F;
                int h265NalType = (nalHeader >> 1) & 0x3F;

                if (h264NalType is 7 or 8 || h265NalType is 32 or 33 or 34)
                {
                    parameterSetCount++;
                    score += 50;
                }

                if (h264NalType == 5 || h265NalType is 19 or 20)
                {
                    idrCount++;
                    score += 30;
                }

                score += 10;
                i = nalStart + 1;
            }

            if (nalCount == 0) return int.MinValue;

            score += nalCount * 5;
            score += parameterSetCount * 40;
            score += idrCount * 20;

            return score;
        }

        private int FindNextStartCode(byte[] payload, int from)
        {
            for (int i = from; i + 3 < payload.Length; i++)
            {
                if (payload[i] == 0 && payload[i + 1] == 0)
                {
                    if (payload[i + 2] == 1) return i;
                    if (payload[i + 2] == 0 && payload[i + 3] == 1) return i;
                }
            }

            return -1;
        }

        private bool IsLikelyNalHeader(byte[] payload, int index)
        {
            if (index >= payload.Length) return false;

            byte nalHeader = payload[index];
            int h264NalType = nalHeader & 0x1F;
            if (h264NalType is > 0 and < 24) return true;

            int h265NalType = (nalHeader >> 1) & 0x3F;
            return h265NalType is > 0 and < 48;
        }

        private VideoCodec DetectVideoCodec(byte[] payload)
        {
            if (payload == null || payload.Length < 5) return VideoCodec.Unknown;

            int offset = payload[2] == 1 ? 3 : 4;
            if (payload.Length <= offset) return VideoCodec.Unknown;

            byte nalHeader = payload[offset];
            int h264NalType = nalHeader & 0x1F;
            if (h264NalType is > 0 and < 24)
                return VideoCodec.H264;

            int h265NalType = (nalHeader >> 1) & 0x3F;
            if (h265NalType is > 0 and < 48)
                return VideoCodec.H265;

            return VideoCodec.Unknown;
        }

        private void DecryptVideoFrame(byte[] data, int length)
        {
            using var aes = Aes.Create();
            aes.Key = aesKey; aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
            using var dec = aes.CreateDecryptor();
            for (int offset = 0; offset + 64 <= length; offset += 80)
                for (int i = 0; i < 4; i++)
                    dec.TransformBlock(data, offset + i * 16, 16, data, offset + i * 16);
        }

        private void DecryptAudioFrame(byte[] data, int length)
        {
            int alignedSize = (length / 16) * 16;
            if (alignedSize == 0) return;

            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            using var dec = aes.CreateDecryptor();
            for (int i = 0; i < alignedSize; i += 16)
                dec.TransformBlock(data, i, 16, data, i);
        }

        // Not tested
        private void DecryptMediaPre2k(byte[] data, int length, int mode)
        {
            int decryptLength;
            if (mode == 0 && length > 2048)
            {
                decryptLength = 2048;
            }
            else
            {
                decryptLength = (length / 16) * 16;
            }
            if (decryptLength > 0)
            {
                using var aes = Aes.Create();
                aes.Key = aesKey;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using var decryptor = aes.CreateDecryptor();
                decryptor.TransformBlock(data, 0, decryptLength, data, 0);
            }
        }

        void GenerateMediaKey(uint ticket)
        {
            WriteUInt32LE(aesKey, 0, ticket);
            WriteUInt64LE(aesKey, 4, 0x618123462c14795c);
            WriteUInt32LE(aesKey, 12, 0x82800df0);
            LogUtils.debug($"[KEY] {BitConverter.ToString(aesKey).Replace("-", "")}");
        }

        byte[] GeneratePassword(string pw)
        {
            byte[] sk = Encoding.ASCII.GetBytes("macrovideo+*#!^@");
            var rng = new Random();
            byte[] rk = new byte[16];
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (int i = 0; i < 16; i++) rk[i] = (byte)chars[rng.Next(chars.Length)];

            var pb = Encoding.ASCII.GetBytes(pw);
            var pad = new byte[48];
            Array.Copy(pb, pad, Math.Min(pb.Length, 48));

            void Enc(byte[] key)
            {
                using var a = Aes.Create();
                a.Key = key; a.Mode = CipherMode.ECB; a.Padding = PaddingMode.None;
                using var e = a.CreateEncryptor();
                for (int i = 0; i < 48; i += 16) e.TransformBlock(pad, i, 16, pad, i);
            }
            Enc(sk); Enc(rk);

            var out_ = new byte[64];
            Array.Copy(rk, 0, out_, 0, 16);
            Array.Copy(pad, 0, out_, 16, 48);
            return out_;
        }

        bool SendData(NetworkStream s, byte[] d)
        {
            try { s.Write(d, 0, d.Length); s.Flush(); return true; }
            catch (Exception ex) { Console.Error.WriteLine($"[SEND] {ex.Message}"); return false; }
        }

        byte[] ReceiveData(NetworkStream s, int max)
        {
            var buf = new byte[max]; int tot = 0;
            var deadline = DateTime.Now.AddSeconds(5);
            while (DateTime.Now < deadline)
            {
                if (s.DataAvailable || tot > 0)
                {
                    int n = s.Read(buf, tot, max - tot);
                    if (n <= 0) break;
                    tot += n;
                    if (tot >= 16) break;
                }
                else Thread.Sleep(10);
            }
            if (tot == 0) return null;
            var r = new byte[tot]; Array.Copy(buf, r, tot); return r;
        }

        int ReadExact(NetworkStream s, byte[] buf, int off, int cnt)
        {
            int tot = 0;
            var deadline = DateTime.Now.AddSeconds(15);
            while (tot < cnt)
            {
                if (DateTime.Now > deadline)
                {
                    needReconnect = true;
                    return tot;
                }
                if (!s.DataAvailable)
                {
                    Thread.Sleep(10);
                    continue;
                }
                int n = s.Read(buf, off + tot, cnt - tot);
                if (n <= 0) break;
                tot += n;
            }
            return tot;
        }

        void WriteUInt32LE(byte[] b, int o, uint v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24); }
        void WriteUInt16LE(byte[] b, int o, ushort v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); }
        void WriteUInt64LE(byte[] b, int o, ulong v) { for (int i = 0; i < 8; i++) b[o + i] = (byte)(v >> (i * 8)); }
        uint ReadUInt32LE(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
        ushort ReadUInt16LE(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
        ulong ReadUInt64LE(byte[] b, int o) { ulong v = 0; for (int i = 0; i < 8; i++) v |= ((ulong)b[o + i]) << (i * 8); return v; }

        public bool PtzRight() => SendControl(V380Commands.PTZ_RIGHT);
        public bool PtzLeft() => SendControl(V380Commands.PTZ_LEFT);
        public bool PtzUp() => SendControl(V380Commands.PTZ_UP);
        public bool PtzDown() => SendControl(V380Commands.PTZ_DOWN);
        public bool PtzStop() => SendControl(V380Commands.PTZ_STOP);
        public bool LightOn() => SendControl(V380Commands.LIGHT_ON);
        public bool LightOff() => SendControl(V380Commands.LIGHT_OFF);
        public bool LightAuto() => SendControl(V380Commands.LIGHT_AUTO);
        public bool ImageColor() => SendControl(V380Commands.IMAGE_COLOR);
        public bool ImageBW() => SendControl(V380Commands.IMAGE_BW);
        public bool ImageAuto() => SendControl(V380Commands.IMAGE_AUTO);
        public bool ImageFlip() => SendControl(V380Commands.IMAGE_FLIP);
        private bool SendControl(byte[] payload)
        {
            if (streamStream == null) return false;
            return SendData(streamStream, payload);
        }

        public string GetDeviceId()
        {
            return deviceId.ToString();
        }

        public string GetDeviceVersion()
        {
            return deviceVersion.ToString();
        }

        public void Dispose()
        {
            authStream?.Close(); authClient?.Close();
            streamStream?.Close(); streamClient?.Close();
            snapshotManager?.Dispose();
        }
    }
}

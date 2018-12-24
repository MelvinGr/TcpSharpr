using System;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using TcpSharpr.Network;

namespace TcpSharpr.Testing.DiffieHellman
{
    public class Program
    {
        private static readonly ECDiffieHellman EcDiffieHellmanServer = ECDiffieHellman.Create();
        private static readonly ECDiffieHellman EcDiffieHellmanClient = ECDiffieHellman.Create();

        [STAThread]
        public static async Task Main()
        {
            var server = new Server(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1805));
            server.CommandManager.RegisterCommand("StartKeyExchange",
                new Func<NetworkClient, ECDiffieHellmanPublicKey, ECDiffieHellmanPublicKey>(
                    (serverClient, clientPublicKey) =>
                    {
                        serverClient.Tag = EcDiffieHellmanServer.DeriveKeyMaterial(clientPublicKey);
                        return EcDiffieHellmanServer.PublicKey;
                    }));

            server.CommandManager.RegisterCommand("CompleteKeyExchange",
                new Action<NetworkClient>(serverClient =>
                {
                    serverClient.SetSymmetricAlgorithm(new RijndaelManaged
                        {Key = (byte[]) serverClient.Tag, IV = new byte[16]});
                    serverClient.Tag = null;
                }));

            server.CommandManager.RegisterCommand("BroadcastToAll",
                new Action<NetworkClient, string>(ServerBroadcastToAll));
            server.Start();

            var client = new Client(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1805));
            client.CommandManager.RegisterCommand("WriteToConsole", new Action<string>(Console.WriteLine));
            await client.ConnectAsync();

            var serverPublicKey =
                await (await client.SendRequestAsync("StartKeyExchange", EcDiffieHellmanClient.PublicKey))
                    .GetResultAsync<ECDiffieHellmanPublicKey>();
            await client.SendAsync("CompleteKeyExchange");

            var privateKey = EcDiffieHellmanClient.DeriveKeyMaterial(serverPublicKey);
            client.NetworkClient.SetSymmetricAlgorithm(new RijndaelManaged {Key = privateKey, IV = new byte[16]});

            Console.WriteLine("/exit to exit");

            while (true)
            {
                var input = Console.ReadLine();

                if (!string.IsNullOrEmpty(input))
                {
                    if (input.ToLower().Equals("/exit"))
                        break;
                    await client.SendAsync("BroadcastToAll", input);
                }
            }

            server.Stop();
            client.Disconnect();
        }

        private static void ServerBroadcastToAll(NetworkClient context, string message)
        {
            var server = context.GetParent();

            var allClients = server.ConnectedClients;

            foreach (var client in allClients)
            {
                Task a = client.SendAsync("WriteToConsole", $"{context.Endpoint}: {message}");
            }
        }
    }
}
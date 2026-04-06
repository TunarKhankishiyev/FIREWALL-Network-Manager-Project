using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace FirewallApp
{
    public class PacketTester
    {
        public async Task<PingReply?> SendPingAsync(string ip, int timeoutMs = 2000)
        {
            var ping = new Ping();
            try
            {
                return await ping.SendPingAsync(ip, timeoutMs);
            }
            catch
            {
                return null;
            }
        }

        public async Task<bool> SendTcpAsync(string ip, int port)
        {
            using var client = new TcpClient();
            try
            {
                await client.ConnectAsync(ip, port);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> SendUdpAsync(string ip, int port)
        {
            using var udp = new UdpClient();
            try
            {
                byte[] data = Encoding.UTF8.GetBytes("AX-Firewall-Test");
                await udp.SendAsync(data, data.Length, new IPEndPoint(IPAddress.Parse(ip), port));
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}

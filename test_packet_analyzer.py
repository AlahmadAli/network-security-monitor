import unittest
from unittest.mock import patch

from scapy.all import IP, TCP
import packet_analyzer as analyzer


class TestPortScanDetection(unittest.TestCase):
    def setUp(self):
        # Start each test with fresh tracking data.
        analyzer.hosts.clear()
        for name in analyzer.stats:
            analyzer.stats[name] = 0

        self.peer = "192.0.2.10"

        # Give every test a controlled clock.
        clock_patch = patch(
            "packet_analyzer.time.monotonic",
            return_value=100.0,
        )
        self.clock = clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def incoming_syn(self, port):
        packet = (
            IP(src=self.peer, dst=analyzer.local_ip)
            / TCP(dport=port, flags="S")
        )

        # Hide packet summaries while testing.
        with patch("builtins.print"):
            analyzer.process_packet(packet)

    def alerts(self):
        return analyzer.hosts[self.peer]["alerts"]

    def test_no_alert_below_threshold(self):
        for port in range(1000, 1009):
            self.incoming_syn(port)

        self.assertEqual(self.alerts(), [])

    def test_alert_at_ten_distinct_ports(self):
        for port in range(1000, 1010):
            self.incoming_syn(port)

        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.alerts()[0]["severity"], "WARNING")
        self.assertIn("Possible TCP port scan", self.alerts()[0]["message"])

    def test_no_duplicate_alert(self):
        for port in range(1000, 1010):
            self.incoming_syn(port)

        self.assertEqual(len(self.alerts()), 1)

        self.incoming_syn(1010)
        self.incoming_syn(1010)

        self.assertEqual(len(self.alerts()), 1)

    def test_expired_ports_do_not_trigger_alert(self):
        for port in range(1000, 1009):
            self.incoming_syn(port)

        # Advance the fake clock by 11 seconds, without waiting.
        self.clock.return_value = 111.0
        self.incoming_syn(1009)

        self.assertEqual(self.alerts(), [])
        self.assertEqual(
            set(analyzer.hosts[self.peer]["incoming_ports"]),
            {1009},
        )


if __name__ == "__main__":
    unittest.main()

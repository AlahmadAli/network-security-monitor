import unittest
from unittest.mock import patch

from scapy.all import IP, TCP, UDP
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

    def test_incoming_syn_ack_does_not_count(self):
        for port in range(1000, 1010):
            packet = (
                IP(src=self.peer, dst=analyzer.local_ip)
                / TCP(dport=port, flags="SA")
            )

            with patch("builtins.print"):
                analyzer.process_packet(packet)

        self.assertEqual(analyzer.hosts[self.peer]["incoming_ports"], {})
        self.assertEqual(self.alerts(), [])

    def test_outgoing_syn_does_not_count(self):
        for port in range(1000, 1010):
            packet = (
                IP(src=analyzer.local_ip, dst=self.peer)
                / TCP(dport=port, flags="S")
            )

            with patch("builtins.print"):
                analyzer.process_packet(packet)

        self.assertEqual(analyzer.hosts[self.peer]["incoming_ports"], {})
        self.assertEqual(self.alerts(), [])

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


class TestHighTrafficIncidents(unittest.TestCase):
    def setUp(self):
        analyzer.hosts.clear()
        for name in analyzer.stats:
            analyzer.stats[name] = 0
        self.peer = "198.51.100.20"
        clock_patch = patch("packet_analyzer.time.monotonic", return_value=100.0)
        self.clock = clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def packet(self, outgoing=False):
        src, dst = ((analyzer.local_ip, self.peer) if outgoing else
                    (self.peer, analyzer.local_ip))
        packet = IP(src=src, dst=dst) / UDP(sport=40000, dport=5000)
        with patch("builtins.print"):
            analyzer.process_packet(packet)

    def reach_threshold(self):
        self.packet()
        host = analyzer.hosts[self.peer]
        host["bytes"] = 10 * 1024 ** 2 - 28
        self.packet()
        return host

    def test_threshold_and_update_on_outgoing_udp(self):
        self.packet()
        self.assertEqual(analyzer.hosts[self.peer]["alerts"], [])
        host = self.reach_threshold()
        self.assertEqual(len(host["alerts"]), 1)
        alert = host["alerts"][0]
        self.assertEqual(alert["severity"], "INFO")
        self.assertEqual(alert["incident_update"], [])
        self.clock.return_value = 104
        self.packet(outgoing=True)
        self.assertEqual(len(host["alerts"]), 1)
        self.assertEqual(len(alert["incident_update"]), 1)
        self.assertIn("total:", alert["incident_update"][0])
        self.assertEqual(alert["last_seen_monotonic"], 104)

    def test_gap_and_latest_incident(self):
        for gap in (5, 5.1):
            with self.subTest(gap=gap):
                analyzer.hosts.clear()
                self.clock.return_value = 100
                host = self.reach_threshold()
                self.clock.return_value = 100 + gap
                self.packet()
                self.assertEqual(len(host["alerts"]), 2)
                self.clock.return_value = 101 + gap
                self.packet()
                self.assertEqual(host["alerts"][0]["incident_update"], [])
                self.assertEqual(len(host["alerts"][1]["incident_update"]), 1)

    def test_summary_does_not_create_or_update_incidents(self):
        host = self.reach_threshold()
        analyzer.detect_suspicious_activity(self.peer, host)
        self.clock.return_value = 106
        analyzer.detect_suspicious_activity(self.peer, host)
        self.assertEqual(len(host["alerts"]), 1)
        self.assertEqual(host["alerts"][0]["incident_update"], [])


if __name__ == "__main__":
    unittest.main()

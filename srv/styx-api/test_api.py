# Copyright (c) 2026 Steve Castellotti
# This file is part of styx-os and is released under the MIT License.
# See LICENSE file in the project root for full license information.

import datetime
import os
import sqlite3
import tempfile
import unittest

from fastapi.testclient import TestClient

import api

FORMAT = "%Y-%m-%d %H:%M:%S"
DEVICE_A = "172.16.100.20"
DEVICE_B = "172.16.100.21"


class HelperTest(unittest.TestCase):
    def test_block_of(self):
        for host, block in [
            ("165.1.213.8", "165.1.0.0/16"),
            ("api.github.com", "github.com"),
            ("GitHub.com.", "github.com"),
            ("www.bbc.co.uk", "bbc.co.uk"),
            ("example.com.au", "example.com.au"),
            ("a.b.example.com.au", "example.com.au"),
            ("a.b.example.com", "example.com"),
            ("localhost", "localhost"),
            ("fe80::1", "fe80::1"),
        ]:
            self.assertEqual(api.block_of(host), block, host)

    def test_scope_of(self):
        self.assertEqual(api.scope_of("192.168.1.5"), "lan")
        self.assertEqual(api.scope_of("10.0.0.1"), "lan")
        self.assertEqual(api.scope_of("172.16.4.4"), "lan")
        self.assertEqual(api.scope_of("169.254.1.1"), "lan")
        self.assertEqual(api.scope_of("fe80::1"), "lan")
        self.assertEqual(api.scope_of("192.0.2.1"), "lan")  # documentation ranges are private to ipaddress
        self.assertEqual(api.scope_of("8.8.8.8"), "wan")
        self.assertEqual(api.scope_of("example.org"), "wan")
        self.assertEqual(api.scope_of(None), "wan")

    def test_seconds_ago_and_epoch(self):
        now = datetime.datetime(2026, 1, 1, 0, 1, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(api.seconds_ago("2026-01-01 00:00:00", now), 60)
        self.assertEqual(api.seconds_ago("2026-01-01 00:02:00", now), 0)
        self.assertEqual(api.seconds_ago(None, now), 0)
        self.assertEqual(api.epoch_of("1970-01-01 00:01:00"), 60)
        self.assertEqual(api.epoch_of("2026-01-01 00:00:00"), 1767225600)

    def test_split_list(self):
        self.assertEqual(api.split_list("443,80,443", 16, numeric=True), [80, 443])
        self.assertEqual(api.split_list("443,x,80", 16, numeric=True), [80, 443])
        self.assertEqual(api.split_list("b,a,b", 8), ["a", "b"])
        self.assertEqual(api.split_list("a,b,c", 2), ["a", "b"])
        self.assertEqual(api.split_list(None, 8), [])
        self.assertEqual(api.split_list("", 8), [])


class ApiTest(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.remove, self.path)
        self.now = datetime.datetime.now(datetime.timezone.utc)
        conn = sqlite3.connect(self.path)
        conn.execute("CREATE TABLE traffic (timestamp TEXT, local TEXT, remote TEXT, port INTEGER,"
                     " sent INTEGER, received INTEGER, domain TEXT)")
        conn.commit()
        conn.close()
        self.client = TestClient(api.TrafficAPI(database_path=self.path).app)

    def insert(self, rows):
        conn = sqlite3.connect(self.path)
        conn.executemany("INSERT INTO traffic VALUES (?,?,?,?,?,?,?)", rows)
        conn.commit()
        conn.close()

    def stamp(self, seconds_back):
        return (self.now - datetime.timedelta(seconds=seconds_back)).strftime(FORMAT)

    def seed(self):
        self.insert([
            (self.stamp(5), DEVICE_A, "8.8.8.8", 443, 100, 1000, "www.example.org"),
            (self.stamp(4), DEVICE_A, "8.8.8.8", 80, 50, 500, "www.example.org"),
            (self.stamp(3), DEVICE_B, "8.8.8.8", 443, 10, 100, "WWW.Example.ORG"),
            (self.stamp(2), DEVICE_A, "198.51.100.7", 443, 7, 70, None),
            (self.stamp(1), DEVICE_A, "10.0.0.5", 22, 1, 2, None),
            (self.stamp(7200), DEVICE_A, "192.0.2.99", 443, 9, 90, "old.example.net"),
        ])


class HostsTest(ApiTest):
    def test_empty_table(self):
        for path in ("/v1/hosts", "/v1/links", "/v1/flows"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertEqual(response.json(), [])

    def test_merges_ports_and_case(self):
        self.seed()
        rows = {r["host"]: r for r in self.client.get("/v1/hosts?relative=60s").json()}
        row = rows["www.example.org"]
        self.assertEqual(row["ports"], [80, 443])
        self.assertEqual(row["count"], 3)
        self.assertEqual(row["sent"], 160)
        self.assertEqual(row["received"], 1600)
        self.assertEqual(row["block"], "example.org")
        self.assertEqual(row["clients"], [DEVICE_A, DEVICE_B])
        self.assertEqual(row["scope"], "wan")

    def test_null_domain_uses_the_ip_and_its_block(self):
        self.seed()
        rows = {r["host"]: r for r in self.client.get("/v1/hosts?relative=60s").json()}
        self.assertEqual(rows["198.51.100.7"]["block"], "198.51.0.0/16")
        self.assertEqual(rows["198.51.100.7"]["ports"], [443])

    def test_private_remote_is_lan(self):
        self.seed()
        rows = {r["host"]: r for r in self.client.get("/v1/hosts?relative=60s").json()}
        self.assertEqual(rows["10.0.0.5"]["scope"], "lan")

    def test_order_is_count_then_host(self):
        self.seed()
        hosts = [r["host"] for r in self.client.get("/v1/hosts?relative=60s").json()]
        self.assertEqual(hosts, ["www.example.org", "10.0.0.5", "198.51.100.7"])

    def test_relative_leaves_old_rows_out(self):
        self.seed()
        self.assertNotIn("old.example.net", [r["host"] for r in self.client.get("/v1/hosts?relative=60s").json()])
        self.assertIn("old.example.net", [r["host"] for r in self.client.get("/v1/hosts?relative=3h").json()])

    def test_client_filter(self):
        self.seed()
        rows = self.client.get(f"/v1/hosts?relative=60s&client={DEVICE_B}").json()
        self.assertEqual([r["host"] for r in rows], ["www.example.org"])
        self.assertEqual(rows[0]["count"], 1)

    def test_ages(self):
        self.seed()
        for row in self.client.get("/v1/hosts?relative=3h").json():
            self.assertGreaterEqual(row["first_seen_ago"], row["last_seen_ago"])
            self.assertGreaterEqual(row["last_seen_ago"], 0)
        row = {r["host"]: r for r in self.client.get("/v1/hosts?relative=3h").json()}["old.example.net"]
        self.assertAlmostEqual(row["last_seen_ago"], 7200, delta=3)

    def test_every_contract_field_is_present(self):
        self.seed()
        row = self.client.get("/v1/hosts?relative=60s").json()[0]
        self.assertEqual(set(row), {"host", "block", "ports", "sent", "received", "count", "open", "blocked",
                                    "untunnelled", "scope", "first_seen_ago", "last_seen_ago", "clients",
                                    "tools", "services"})
        self.assertEqual((row["open"], row["blocked"], row["untunnelled"], row["tools"], row["services"]),
                         (0, 0, False, [], []))

    def test_cut_at_256(self):
        self.insert([(self.stamp(1), DEVICE_A, f"192.0.2.{i % 250}", 443, 1, 1, f"h{i:04d}.example.org")
                     for i in range(300)])
        self.assertEqual(len(self.client.get("/v1/hosts?relative=60s").json()), 256)

    def test_relative_with_absolute_is_400(self):
        self.assertEqual(self.client.get("/v1/hosts?relative=60s&start_date=2026-01-01").status_code, 400)

    def test_end_date_with_client(self):
        self.seed()
        for path in ("/v1/hosts", "/v1/links", "/v1/flows", "/v1/matrix"):
            response = self.client.get(f"{path}?end_date=2999-01-01&client={DEVICE_A}")
            self.assertEqual(response.status_code, 200, path)
        self.assertEqual(len(self.client.get(f"/v1/hosts?end_date=2999-01-01&client={DEVICE_B}").json()), 1)

    def test_malformed_relative_is_400(self):
        for path in ("/v1/hosts", "/v1/links", "/v1/flows", "/v1/matrix"):
            for bad in ("abc", "m", "5x"):
                self.assertEqual(self.client.get(f"{path}?relative={bad}").status_code, 400, f"{path} {bad}")

    def test_matrix_is_unchanged(self):
        self.seed()
        rows = self.client.get("/v1/matrix?relative=60s").json()
        self.assertEqual(set(rows[0]), {"address", "sent", "received", "count"})


class LinksTest(ApiTest):
    def test_one_row_per_device_and_host(self):
        self.seed()
        rows = self.client.get("/v1/links?relative=60s").json()
        pairs = [(r["source"], r["target"]) for r in rows]
        self.assertEqual(pairs, [(DEVICE_A, "www.example.org"), (DEVICE_A, "10.0.0.5"),
                                 (DEVICE_A, "198.51.100.7"), (DEVICE_B, "www.example.org")])
        first = rows[0]
        self.assertEqual((first["count"], first["sent"], first["received"]), (2, 150, 1500))
        self.assertEqual((first["source_kind"], first["via"], first["open"], first["blocked"]), ("device", "", 0, 0))
        self.assertGreaterEqual(first["last_seen_ago"], 0)
        self.assertEqual(set(first), {"source", "source_kind", "via", "target", "sent", "received", "count",
                                      "open", "blocked", "last_seen_ago"})

    def test_cut_at_512(self):
        self.insert([(self.stamp(1), f"172.16.{i // 250}.{i % 250}", "192.0.2.1", 443, 1, 1, "x.example.org")
                     for i in range(600)])
        self.assertEqual(len(self.client.get("/v1/links?relative=60s").json()), 512)


class FlowsTest(ApiTest):
    def test_newest_first(self):
        self.seed()
        rows = self.client.get("/v1/flows?relative=60s").json()
        self.assertEqual([r["ago"] for r in rows], sorted(r["ago"] for r in rows))
        self.assertEqual(len(rows), 5)

    def test_host_filter_is_case_insensitive(self):
        self.seed()
        for host in ("www.example.org", "WWW.EXAMPLE.ORG"):
            rows = self.client.get(f"/v1/flows?relative=60s&host={host}").json()
            self.assertEqual(len(rows), 3)
            self.assertEqual({r["host"] for r in rows}, {"www.example.org"})

    def test_host_filter_with_no_window(self):
        self.seed()
        self.assertEqual(len(self.client.get("/v1/flows?host=old.example.net").json()), 1)

    def test_limit(self):
        self.seed()
        self.assertEqual(len(self.client.get("/v1/flows?relative=60s&limit=2").json()), 2)
        for bad in ("0", "501", "x", "1.5", ""):
            self.assertEqual(self.client.get(f"/v1/flows?limit={bad}").status_code, 400, bad)
        self.assertEqual(self.client.get("/v1/flows?limit=500").status_code, 200)

    def test_default_limit_is_100(self):
        self.insert([(self.stamp(i), DEVICE_A, "192.0.2.1", 443, 1, 1, "x.example.org") for i in range(150)])
        self.assertEqual(len(self.client.get("/v1/flows").json()), 100)

    def test_time_and_ago_agree_with_the_row(self):
        self.insert([(self.stamp(30), DEVICE_A, "192.0.2.1", 443, 12, 34, "x.example.org")])
        row = self.client.get("/v1/flows").json()[0]
        self.assertAlmostEqual(row["time"], int(self.now.timestamp()) - 30, delta=2)
        self.assertAlmostEqual(row["ago"], 30, delta=2)
        self.assertEqual((row["source"], row["via"], row["port"], row["sent"], row["received"]),
                         (DEVICE_A, "", 443, 12, 34))
        self.assertEqual((row["tool"], row["proto"], row["state"], row["blocked"], row["rule"],
                          row["method"], row["url"], row["label"]),
                         (None, None, "finished", False, None, None, None, None))

    def test_relative_with_absolute_is_400(self):
        self.assertEqual(self.client.get("/v1/flows?relative=60s&start_date=2026-01-01").status_code, 400)


if __name__ == "__main__":
    unittest.main()

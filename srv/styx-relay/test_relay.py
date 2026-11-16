# Copyright (c) 2026 Steve Castellotti
# This file is part of styx-os and is released under the MIT License.
# See LICENSE file in the project root for full license information.

import os
import tempfile
import unittest
from unittest import mock

import relay


class RelayTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("relay.socket.socket")
        self.addCleanup(patcher.stop)
        patcher.start()
        self.service = relay.UDPRelayService(udp_port=0)
        self.sock = self.service.udp_sock
        self.client = ("172.16.100.50", 40000)

    def test_valid_request_is_relayed_and_fragmented(self):
        body = "x" * 2500
        with mock.patch("relay.requests.get") as get:
            get.return_value.text = body
            self.service.handle_request(b'{"GET": "/api/v1/matrix?relative=60s"}', self.client)
        get.assert_called_once_with("http://styx-web/api/v1/matrix?relative=60s", timeout=relay.REQUEST_TIMEOUT)
        sent = [call.args[0] for call in self.sock.sendto.call_args_list]
        size = relay.BUFFER_SIZE - 32
        total = -(-len(body) // size)
        self.assertEqual(len(sent), total)
        rebuilt = b""
        for number, fragment in enumerate(sent, start=1):
            header, _, payload = fragment.partition(b":")
            self.assertEqual(header, f"{number}/{total}".encode())
            self.assertLessEqual(len(payload), size)
            rebuilt += payload
        self.assertEqual(rebuilt.decode(), body)
        for call in self.sock.sendto.call_args_list:
            self.assertEqual(call.args[1], self.client)

    def test_python_expression_is_not_evaluated(self):
        marker = os.path.join(tempfile.gettempdir(), "styx-relay-test-marker")
        if os.path.exists(marker):
            os.remove(marker)
        payload = f"__import__('os').system('touch {marker}') or {{'GET': '/api/v1/matrix'}}".encode()
        with mock.patch("relay.requests.get") as get:
            self.service.handle_request(payload, self.client)
        get.assert_not_called()
        self.assertFalse(os.path.exists(marker))

    def test_invalid_requests_are_dropped(self):
        bad = [
            b"",
            b"not json",
            b"[1, 2]",
            b'"/api/v1/matrix"',
            b"{'GET': '/api/v1/matrix'}",      # Python literal, not JSON
            b'{"GET": 5}',
            b'{"GET": null}',
            b'{"POST": "/api/v1/matrix"}',
            b'{"GET": "/admin/"}',
            b'{"GET": "api/v1/matrix"}',
            b'{"GET": "/api/v1/x y"}',
            b'{"GET": "/api/v1/x\\ny"}',
            b'{"GET": "/api/@evil.example/x"}',
            b'{"GET": "/api/\\\\evil.example/x"}',
            b'{"GET": "/api//evil.example/x"}',
            b"\xff\xfe\xfd",
        ]
        for payload in bad:
            with self.subTest(payload=payload), mock.patch("relay.requests.get") as get:
                self.service.handle_request(payload, self.client)
                get.assert_not_called()
        self.sock.sendto.assert_not_called()

    def test_upstream_failure_sends_nothing(self):
        with mock.patch("relay.requests.get", side_effect=relay.requests.Timeout("slow")):
            self.service.handle_request(b'{"GET": "/api/v1/matrix"}', self.client)
        self.sock.sendto.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Regression tests for the P0/P1 core modules.

Pure-Python only (no Playwright/OpenAI needed) so they run anywhere:

    python -m unittest discover -s tests      # stdlib
    pytest tests/                              # if pytest is installed
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.llm import extract_findings_payload, parse_response  # noqa: E402
from core.models import Finding, Verdict, parse_findings  # noqa: E402
from core.oracle import ResponseSnapshot, evaluate  # noqa: E402
from core.redaction import Redactor, redact_packets_file  # noqa: E402
from core.verifier import _snapshot, finding_to_tamper  # noqa: E402


def _finding(
    loc="body",
    name="price",
    payload="0.01",
    url="https://shop.test/api/checkout",
    method="POST",
    **extra,
):
    base = dict(
        control_id="1.4",
        packet_index=0,
        parameter_name=name,
        parameter_location=loc,
        vulnerability_description="d",
        exploitation_hypothesis="h",
        test_payload=payload,
        modified_request_example={
            "url": url,
            "method": method,
            "headers": {},
            "body_data": "price=0.01",
        },
    )
    base.update(extra)
    return Finding.model_validate(base)


def _resp(url, status, body, method="POST"):
    return ResponseSnapshot(url=url, method=method, status=status, body=body)


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.pkt = {
            "headers": {
                "Cookie": "sid=LONGsecretSESSIONvalue123456; cart_id=42; theme=dark",
                "Authorization": "Bearer abcdefabcdefabcdefabcdef",
                "Content-Type": "application/json",
            },
            "body": '{"email":"v@test.com","card":"4111 1111 1111 1111","price":9.99,"order_id":7}',
            "response": {
                "status_code": 200,
                "headers": {
                    "Set-Cookie": "sid=NEWlongRandomTok1234567; Path=/; HttpOnly; Secure; SameSite=Strict"
                },
            },
        }

    def test_secrets_removed(self):
        red = Redactor().redact_packet(self.pkt)
        blob = json.dumps(red)
        for leak in [
            "LONGsecretSESSIONvalue123456",
            "abcdefabcdefabcdefabcdef",
            "v@test.com",
            "4111",
            "NEWlongRandomTok1234567",
        ]:
            self.assertNotIn(leak, blob)

    def test_structure_preserved_for_analysis(self):
        red = Redactor().redact_packet(self.pkt)
        # Low-entropy IDOR identifiers survive.
        self.assertIn("cart_id=42", red["headers"]["Cookie"])
        self.assertIn("theme=dark", red["headers"]["Cookie"])
        self.assertIn("order_id", red["body"])
        # Cookie flags survive (needed for Control 1.2).
        sc = red["response"]["headers"]["Set-Cookie"]
        for flag in ("Path=/", "HttpOnly", "Secure", "SameSite=Strict"):
            self.assertIn(flag, sc)

    def test_reversible_roundtrip(self):
        r = Redactor()
        red = r.redact_packet(self.pkt)
        back = r.reinject(red)
        self.assertEqual(back["headers"]["Authorization"], self.pkt["headers"]["Authorization"])
        self.assertEqual(back["body"], self.pkt["body"])
        self.assertEqual(back["headers"]["Cookie"], self.pkt["headers"]["Cookie"])

    def test_file_helper(self):
        d = tempfile.mkdtemp()
        src = os.path.join(d, "p.json")
        with open(src, "w") as f:
            json.dump([self.pkt], f)
        out, mp = os.path.join(d, "o.json"), os.path.join(d, "m.json")
        redact_packets_file(src, out, mp)
        self.assertTrue(os.path.exists(out) and os.path.exists(mp))
        with open(out) as f:
            out_text = f.read()
        self.assertNotIn("v@test.com", out_text)
        # Map reloads and reverses.
        r = Redactor.load_map(mp)
        self.assertEqual(r.reinject(json.loads(out_text))[0]["body"], self.pkt["body"])

    def test_luhn_false_positive_kept(self):
        # A non-card 16-digit number (fails Luhn) must not be redacted.
        pkt = {"body": '{"ref":"1234567890123456"}'}
        red = Redactor().redact_packet(pkt)
        self.assertIn("1234567890123456", red["body"])


class TestModelsAndParsing(unittest.TestCase):
    def test_coercions(self):
        f = parse_findings(
            [
                {
                    "control_id": "1.4",
                    "packet_index": "0",
                    "parameter_name": "price",
                    "parameter_location": "body",
                    "vulnerability_description": "x",
                    "exploitation_hypothesis": "y",
                    "test_payload": 0.01,
                    "modified_request_example": {
                        "url": "u",
                        "method": "POST",
                        "headers": {},
                        "body_data": "price=0.01",
                    },
                }
            ]
        )
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].packet_index, 0)
        self.assertEqual(f[0].test_payload, "0.01")

    def test_invalid_skipped(self):
        self.assertEqual(parse_findings([{"bogus": 1}]), [])

    def test_extract_variants(self):
        self.assertEqual(extract_findings_payload('[{"a":1}]'), [{"a": 1}])
        self.assertEqual(extract_findings_payload('{"findings":[{"a":1}]}'), [{"a": 1}])
        self.assertEqual(
            extract_findings_payload('ok ```json\n{"findings":[{"a":1}]}\n``` end'),
            [{"a": 1}],
        )
        self.assertIsNone(extract_findings_payload("no json here"))

    def test_extract_ignores_braces_in_strings(self):
        self.assertEqual(
            extract_findings_payload('{"findings":[{"b":"{x} [y]","v":2}]}'),
            [{"b": "{x} [y]", "v": 2}],
        )

    def test_parse_response_empty_vs_error(self):
        _, findings = parse_response('{"findings": []}')
        self.assertEqual(findings, [])
        payload, _ = parse_response("totally not json")
        self.assertIsNone(payload)


URL = "https://shop.test/api/checkout"


class TestOracle(unittest.TestCase):
    def test_price_drop_confirmed(self):
        b = _resp(URL, 200, '{"total":100.0}')
        t = _resp(URL, 200, '{"total":0.01}')
        res = evaluate(_finding(), "0.01", b, t)
        self.assertEqual(res.verdict, Verdict.CONFIRMED)
        self.assertTrue(res.is_live)
        self.assertGreaterEqual(res.confidence, 0.7)

    def test_rejected_status(self):
        b = _resp(URL, 200, "{}")
        t = _resp(URL, 403, "no")
        self.assertEqual(evaluate(_finding(), "0.01", b, t).verdict, Verdict.REJECTED)

    def test_reflected_value_confirmed(self):
        b = _resp(URL, 200, '{"coupon":"NONE"}')
        t = _resp(URL, 200, '{"coupon":"FREE"}')
        f = _finding(name="coupon_code", payload="FREE")
        self.assertEqual(evaluate(f, "FREE", b, t).verdict, Verdict.CONFIRMED)

    def test_server_error_likely(self):
        b = _resp(URL, 200, "{}")
        t = _resp(URL, 500, "boom")
        self.assertEqual(
            evaluate(_finding(name="qty", payload="-1"), "-1", b, t).verdict,
            Verdict.LIKELY,
        )

    def test_inconclusive(self):
        b = _resp(URL, 200, "SAME")
        t = _resp(URL, 200, "SAME")
        f = _finding(loc="query", name="view", payload="admin")
        self.assertEqual(evaluate(f, "admin", b, t).verdict, Verdict.INCONCLUSIVE)

    def test_error_no_response(self):
        self.assertEqual(evaluate(_finding(), "0.01", None, None).verdict, Verdict.ERROR)


class TestOraclePrecision(unittest.TestCase):
    """Tests for the precision upgrades: downstream proof, error-context,
    IDOR semantics, and avoiding the 'largest number' trap."""

    def test_downstream_proof_confirmed(self):
        # The tampered request is the cart; the proof shows up later, at the
        # confirmation step. Whole-flow capture must catch it.
        cart = "https://shop.test/api/cart"
        confirm = "https://shop.test/api/confirm"
        baseline = [
            _resp(cart, 200, '{"ok":true}'),
            _resp(confirm, 200, '{"grand_total":250.00,"order_id":11}'),
        ]
        tampered = [
            _resp(cart, 200, '{"ok":true}'),
            _resp(confirm, 200, '{"grand_total":2.50,"order_id":12}'),
        ]
        f = _finding(name="price", url=cart)
        res = evaluate(f, "2.50", baseline, tampered)
        self.assertEqual(res.verdict, Verdict.CONFIRMED)

    def test_error_context_is_not_a_hit(self):
        # Value is reflected, but inside an error envelope -> must NOT confirm.
        b = _resp(URL, 200, '{"coupon":"NONE"}')
        t = _resp(URL, 200, '{"success":false,"error":"invalid coupon FREE"}')
        f = _finding(name="coupon_code", payload="FREE")
        res = evaluate(f, "FREE", b, t)
        self.assertEqual(res.verdict, Verdict.REJECTED)

    def test_largest_number_trap_avoided(self):
        # A big unrelated number (timestamp) changes, but no monetary field does.
        b = _resp(URL, 200, '{"total":100.0,"timestamp":1699999999999}')
        t = _resp(URL, 200, '{"total":100.0,"timestamp":1700000000000}')
        res = evaluate(_finding(), "0.01", b, t)
        self.assertNotEqual(res.verdict, Verdict.CONFIRMED)

    def test_idor_confirmed(self):
        acct = "https://shop.test/api/account/1001"
        b = _resp(acct, 200, '{"user":"me","orders":[1,2,3],"balance":50}', method="GET")
        t = _resp(
            "https://shop.test/api/account/1002",
            200,
            '{"user":"someone_else","orders":[9,8,7,6],"balance":9999}',
            method="GET",
        )
        f = _finding(
            loc="url_path",
            name="4",
            payload="1002",
            url="https://shop.test/api/account/1002",
            method="GET",
        )
        res = evaluate(f, "1002", b, t)
        self.assertEqual(res.verdict, Verdict.CONFIRMED)

    def test_idor_protected_rejected(self):
        b = _resp("https://shop.test/api/account/1001", 200, '{"user":"me"}', method="GET")
        t = _resp("https://shop.test/api/account/1002", 403, "Forbidden", method="GET")
        f = _finding(
            loc="url_path",
            name="4",
            payload="1002",
            url="https://shop.test/api/account/1002",
            method="GET",
        )
        self.assertEqual(evaluate(f, "1002", b, t).verdict, Verdict.REJECTED)

    def test_idor_identical_inconclusive(self):
        url2 = "https://shop.test/api/account/1002"
        b = _resp("https://shop.test/api/account/1001", 200, '{"generic":"page"}', method="GET")
        t = _resp(url2, 200, '{"generic":"page"}', method="GET")
        f = _finding(loc="url_path", name="4", payload="1002", url=url2, method="GET")
        self.assertEqual(evaluate(f, "1002", b, t).verdict, Verdict.INCONCLUSIVE)

    def test_confidence_is_populated(self):
        b = _resp(URL, 200, '{"total":100.0}')
        t = _resp(URL, 200, '{"total":1.0}')
        res = evaluate(_finding(), "1.0", b, t)
        self.assertGreater(res.confidence, 0.0)


class TestVerifierWiring(unittest.TestCase):
    def test_finding_to_tamper_reinjects(self):
        r = Redactor()
        # make a url containing a secret placeholder
        red_url = "https://shop.test/u/" + r._placeholder_for("secretuser", "AUTH")
        f = _finding()
        f.modified_request_example.url = red_url
        tc = finding_to_tamper(f, r)
        self.assertIn("secretuser", tc["url_pattern"])
        self.assertEqual(tc["param_location"], "body")

    def test_snapshot_none(self):
        self.assertIsNone(_snapshot(None))
        snap = _snapshot({"url": "u", "status": 200, "headers": {}, "body": "x"})
        self.assertEqual(snap.status, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)

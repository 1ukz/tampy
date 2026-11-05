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

from core.judge import build_judge_messages, parse_judge  # noqa: E402
from core.llm import extract_findings_payload, extract_json_object, parse_response  # noqa: E402
from core.models import Finding, OracleResult, Verdict, parse_findings  # noqa: E402
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


def _redsys_body(amount_cents):
    import base64 as _b64
    import json as _json
    import urllib.parse as _up

    params = {
        "DS_MERCHANT_AMOUNT": str(amount_cents),
        "DS_MERCHANT_ORDER": "000123",
        "DS_MERCHANT_CURRENCY": "978",
    }
    blob = _b64.b64encode(_json.dumps(params).encode()).decode()
    return _up.urlencode({"Ds_SignatureVersion": "HMAC_SHA256_V1", "Ds_MerchantParameters": blob})


class TestGatewayOracle(unittest.TestCase):
    """The amount sent to the payment gateway is the money actually charged."""

    REDSYS = "https://sis.redsys.es/sis/realizarPago"

    def _flow(self, cents):
        cart = _resp("https://shop.test/api/cart", 200, '{"ok":true}')
        gw = ResponseSnapshot(
            url=self.REDSYS,
            method="POST",
            status=200,
            body="<html>pago</html>",
            request_body=_redsys_body(cents),
        )
        return [cart, gw]

    def test_gateway_amount_change_confirmed(self):
        baseline = self._flow(25000)  # 250.00 EUR
        tampered = self._flow(1)  # 0.01 EUR
        f = _finding(name="price", url="https://shop.test/api/cart")
        res = evaluate(f, "0.01", baseline, tampered)
        self.assertEqual(res.verdict, Verdict.CONFIRMED)
        self.assertGreaterEqual(res.confidence, 0.9)
        self.assertIn("redsys", res.reason.lower())

    def test_gateway_amount_unchanged_not_confirmed(self):
        # Server ignored the client price: gateway amount stays the same.
        baseline = self._flow(25000)
        tampered = self._flow(25000)
        f = _finding(name="price", url="https://shop.test/api/cart")
        res = evaluate(f, "0.01", baseline, tampered)
        self.assertNotEqual(res.verdict, Verdict.CONFIRMED)


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


class TestTamper(unittest.TestCase):
    def test_body_urlencoded(self):
        from core.tamper import apply_tamper

        req = {
            "method": "POST",
            "url": "https://s.test/c",
            "headers": {},
            "body": "price=100&qty=1",
        }
        out = apply_tamper(
            req, {"param_location": "body", "param_name": "price", "param_value": "1"}
        )
        self.assertIn("price=1", out["body"])
        self.assertIn("qty=1", out["body"])
        self.assertEqual(req["body"], "price=100&qty=1")  # input unchanged

    def test_body_json(self):
        from core.tamper import apply_tamper

        req = {
            "method": "POST",
            "url": "https://s.test/c",
            "headers": {"Content-Type": "application/json"},
            "body": '{"price":100,"qty":1}',
        }
        out = apply_tamper(
            req, {"param_location": "body", "param_name": "price", "param_value": "1"}
        )
        self.assertEqual(json.loads(out["body"])["price"], "1")

    def test_query_and_path(self):
        from core.tamper import apply_tamper

        q = apply_tamper(
            {"method": "GET", "url": "https://s.test/p?id=5&x=1", "headers": {}, "body": None},
            {"param_location": "query", "param_name": "id", "param_value": "9"},
        )
        self.assertIn("id=9", q["url"])
        p = apply_tamper(
            {"method": "GET", "url": "https://s.test/account/1001", "headers": {}, "body": None},
            {"param_location": "url_path", "param_name": "2", "param_value": "1002"},
        )
        self.assertTrue(p["url"].endswith("/account/1002"))

    def test_header(self):
        from core.tamper import apply_tamper

        out = apply_tamper(
            {
                "method": "GET",
                "url": "https://s.test/",
                "headers": {"X-Role": "user"},
                "body": None,
            },
            {"param_location": "headers", "param_name": "x-role", "param_value": "admin"},
        )
        self.assertEqual(out["headers"]["X-Role"], "admin")


class TestPayloads(unittest.TestCase):
    def test_price_sweep_includes_original_first(self):
        from core.payloads import payloads_for

        p = payloads_for(_finding(name="price", payload="5"))
        self.assertEqual(p[0], "5")
        self.assertIn("0.01", p)
        self.assertIn("-1", p)

    def test_id_not_fuzzed(self):
        from core.payloads import payloads_for

        p = payloads_for(_finding(loc="url_path", name="2", payload="1002"))
        self.assertEqual(p, ["1002"])


class TestSignatures(unittest.TestCase):
    def test_detects_redsys_signature(self):
        from core.signatures import signature_fields

        body = "Ds_SignatureVersion=HMAC_SHA256_V1&Ds_MerchantParameters=abc&Ds_Signature=zzz"
        self.assertIn("Ds_Signature", signature_fields("https://sis.redsys.es/sis", body))

    def test_annotate_confirmed_flags_uncovered(self):
        from core.signatures import annotate

        msg = annotate("Live issue confirmed.", True, ["Ds_Signature"])
        self.assertIn("does not cover", msg)

    def test_annotate_rejected_notes_protection(self):
        from core.signatures import annotate

        msg = annotate("Rejected.", False, ["signature"])
        self.assertIn("integrity-checked", msg)


class TestHttpReplay(unittest.TestCase):
    def test_replay_applies_tamper_via_injected_sender(self):
        from core.http_replay import replay

        captured = {}

        def fake_sender(req, timeout):
            captured["req"] = req
            return {"url": req["url"], "method": req["method"], "status": 200, "body": "ok"}

        req = {"method": "POST", "url": "https://s.test/c", "headers": {}, "body": "price=100"}
        out = replay(
            req,
            {"param_location": "body", "param_name": "price", "param_value": "1"},
            sender=fake_sender,
        )
        self.assertIn("price=1", captured["req"]["body"])
        self.assertEqual(out["status"], 200)


class TestJudge(unittest.TestCase):
    def _oracle(self):
        return OracleResult(
            verdict=Verdict.INCONCLUSIVE, confidence=0.3, reason="unclear", signals={}
        )

    def test_parse_judge_valid(self):
        out = parse_judge('{"verdict":"confirmed","confidence":0.9,"rationale":"total dropped"}')
        self.assertEqual(out["verdict"], Verdict.CONFIRMED)
        self.assertEqual(out["confidence"], 0.9)

    def test_parse_judge_fenced_and_prose(self):
        text = 'Ruling:\n```json\n{"verdict":"rejected","confidence":0.8}\n```'
        out = parse_judge(text)
        self.assertEqual(out["verdict"], Verdict.REJECTED)

    def test_parse_judge_bad(self):
        self.assertIsNone(parse_judge("not json"))
        self.assertIsNone(parse_judge('{"verdict":"maybe"}'))

    def test_build_messages_redacts_evidence(self):
        # A token in a response body must be redacted before egress to the judge.
        r = ResponseSnapshot(
            url=URL,
            method="POST",
            status=200,
            body='{"jwt":"eyJhbGciOiJIUzI1NiJ.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4abc"}',
        )
        msgs = build_judge_messages(_finding(), self._oracle(), [r], [r], Redactor())
        blob = json.dumps(msgs)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ", blob)
        self.assertEqual(msgs[0]["role"], "system")

    def test_extract_json_object(self):
        self.assertEqual(extract_json_object('x {"a":1} y'), {"a": 1})
        self.assertIsNone(extract_json_object("no object"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

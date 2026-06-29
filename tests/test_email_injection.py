#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests para email_injection_detector — casos positivos Y negativos."""

import pytest
from email_injection_detector import check_email_params, _has_header_injection, _has_multiple_emails


class TestEmailInjectionPositive:
    """Casos que DEBEN ser bloqueados."""

    def test_crlf_bcc_in_subject(self):
        result = check_email_params({"subject": "Hello\r\nBcc:evil@hack.com"})
        assert result.status.value == "blocked"
        assert result.threat_score >= 0.9

    def test_lf_cc_in_subject(self):
        result = check_email_params({"subject": "Hi\nCc:victim@corp.com"})
        assert result.status.value == "blocked"

    def test_crlf_to_injection(self):
        result = check_email_params({"to": "a@b.com\r\nTo:other@evil.com"})
        assert result.status.value == "blocked"

    def test_crlf_content_type(self):
        result = check_email_params({
            "subject": "Report\r\nContent-Type:text/html<script>alert(1)</script>"
        })
        assert result.status.value == "blocked"

    def test_x_header_injection(self):
        result = check_email_params({
            "subject": "Hello\r\nX-Mailer:evil"
        })
        assert result.status.value == "blocked"

    def test_multiple_emails_in_to(self):
        result = check_email_params({
            "to": "good@corp.com, evil@hack.com"
        })
        assert result.status.value == "blocked"


class TestEmailInjectionNegative:
    """Casos legitimos que NO deben ser bloqueados."""

    def test_normal_subject(self):
        result = check_email_params({"subject": "Re: Your order #12345"})
        assert result.status.value == "safe"

    def test_normal_body_with_line_breaks(self):
        """El body LEGITIMAMENTE tiene saltos de linea."""
        result = check_email_params({
            "body": "Hi John,\n\nHope you are well.\n\nBest regards,\nPedro"
        })
        assert result.status.value == "safe"

    def test_subject_with_colon(self):
        result = check_email_params({"subject": "Re: Fwd: Meeting notes"})
        assert result.status.value == "safe"

    def test_single_email_in_to(self):
        result = check_email_params({"to": "user@example.com"})
        assert result.status.value == "safe"

    def test_body_with_url(self):
        """Un body normal con URLs no debe disparar."""
        result = check_email_params({
            "body": "Check this: https://example.com/report"
        })
        assert result.status.value == "safe"


class TestHelpers:
    """Tests de funciones auxiliares."""

    def test_header_injection_bcc(self):
        assert _has_header_injection("Hello\r\nBcc:evil@hack.com") is True

    def test_header_injection_none(self):
        assert _has_header_injection("Hello world") is False

    def test_multiple_emails(self):
        assert _has_multiple_emails("a@b.com, c@d.com") is True

    def test_single_email(self):
        assert _has_multiple_emails("only@one.com") is False

# hal-id: #HAL-20261110-0008-PK-T1
from saferender import extract as X


def test_urls_basic_and_trailing_punctuation():
    t = "Visit https://a.example/x?y=1, or (see https://b.example/path). Also www.c.example."
    assert X.find_urls(t) == ["https://a.example/x?y=1", "https://b.example/path", "www.c.example"]


def test_urls_dedupe_case_insensitive():
    assert X.find_urls("https://A.example/p https://a.example/p") == ["https://A.example/p"]


def test_ocr_scheme_repair():
    assert X.find_urls("pay at https:/ /overdue.example/pay", ocr=True) == ["https://overdue.example/pay"]


def test_defang_host_only():
    assert X.defang("https://evil.example/a.b/c") == "hxxps://evil[.]example/a.b/c"
    assert X.defang("www.evil.example") == "www[.]evil[.]example"


def test_host_of():
    assert X.host_of("https://Login.Example:8443/x") == "login.example"
    assert X.host_of("www.c.example/p") == "www.c.example"


def test_phones_us_formats():
    assert X.find_phones("Call (800) 555-0143 or +1 212-555-0187 now") == ["+18005550143", "+12125550187"]


def test_no_false_phone_from_invoice_number():
    assert X.find_phones("Invoice 7731 total 1,250.00 ref 20261110") == []


def test_emails():
    assert set(X.find_emails("reply to billing@vendor.example or Billing@Vendor.example")) == {
        "billing@vendor.example", "Billing@Vendor.example"}


def test_lookalike_flags_imitations():
    assert X.lookalike("login-micros0ft-support.example") == "microsoft"
    assert X.lookalike("m1crosoft.example") == "microsoft"
    assert X.lookalike("rnicrosoft.example") == "microsoft"
    assert X.lookalike("contoso.com.billing-check.example") == "contoso"


def test_lookalike_spares_real_domains():
    for h in ("login.microsoftonline.com", "contoso.sharepoint.com", "www.microsoft.com", "docusign.net",
              "payments-portal.example", "10.0.0.1"):
        assert X.lookalike(h) is None, h


def test_org_domains_from_env(monkeypatch):
    monkeypatch.setenv("SAFERENDER_ORG_DOMAINS", "fabrikam.org")
    assert X.lookalike("fabrikam-payroll.example") == "fabrikam"
    assert X.lookalike("hr.fabrikam.org") is None


def test_brand_named_in_display_name():
    assert X.brand_named("Microsoft 365 Security") == "microsoft"
    assert X.brand_named("Jane Smith") is None

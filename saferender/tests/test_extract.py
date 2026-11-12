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

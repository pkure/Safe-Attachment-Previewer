# hal-id: #HAL-20261118-0002-PK-D2
"""Unit tests for deep.py: decoding layers and false-positive guards. Pure text, no samples needed."""

import base64
import io
import zipfile

from saferender import deep as D


def urls(text):
    return {u: layer for u, layer in D.deobfuscate(text)["urls"]}


def test_plain_url_is_layer_zero():
    assert urls('var u = "https://plain.example/x";') == {"https://plain.example/x": 0}


def test_string_concatenation():
    assert urls('go("ht" + "tps://con" + \'cat.example/a\')').get("https://concat.example/a") is None  # mixed quotes stay
    assert urls('go("ht" + "tps://con" + "cat.example/a")')["https://concat.example/a"] == 1


def test_escapes_charcode_reverse():
    codes = ",".join(str(ord(c)) for c in "https://cc.example/z")
    found = urls(f'String.fromCharCode({codes}); "\\x68\\x74\\x74\\x70\\x73://hex.example/q";'
                 f' "{"https://rev.example/r"[::-1]}".split("").reverse().join("")')
    assert found["https://cc.example/z"] == 1
    assert found["https://hex.example/q"] == 1
    assert found["https://rev.example/r"] == 1


def test_nested_layers_keep_going():
    inner = base64.b64encode(b'location="https://deep.example/3"').decode()
    outer = base64.b64encode(f'eval(atob("{inner}"))'.encode()).decode()
    assert urls(f'eval(atob("{outer}"))')["https://deep.example/3"] == 2


def test_smuggled_zip_becomes_a_blob_with_its_download_name():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "hello")
    b64 = base64.b64encode(buf.getvalue()).decode()
    d = D.deobfuscate(f'var d = atob("{b64}"); a.download = "pay.zip"; new Blob([d]);')
    assert [(n, b[:2]) for n, b, _ in d["blobs"]] == [("pay.zip", b"PK")]


def test_random_tokens_are_not_payloads():
    # Long tracking tokens decode to random bytes. Without file magic or smuggling code they must not become "files".
    page = '<a href="https://t.example/c?id=Zq8x0PlkW3mNbV7rT2yUiOpAsDfGhJkLzXcVbNm1234567890abcdEFGHijklMNOPqrst">x</a>'
    assert D.deobfuscate(page)["blobs"] == []


def test_html_entities_are_not_hidden_links():
    assert urls('<a href="https://news.example/a?x=1&amp;y=2">read</a>')["https://news.example/a?x=1&y=2"] == 0


def test_inline_images_ignored():
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(200)).decode()
    assert D.deobfuscate(f'<img src="data:image/png;base64,{png}">')["blobs"] == []


def test_html_for_render_strips_every_loader():
    from saferender.formats import html_for_render
    page = ('<p>hi</p><img src="file:///etc/x.png"><img src=\'https://track.example/p.gif\'>'
            '<img src="data:image/png;base64,AAAA"><iframe src="file:///etc/passwd"></iframe><object data="x"></object>'
            '<embed src="y"><script>alert(1)</script><link rel="stylesheet" href="https://css.example/a.css">'
            '<td background="file:///z.png" bgcolor="#000"><div style="background:url(file:///q.png)">'
            '<a href="https://link.example/a">a</a><svg><image href="file:///s.png"/></svg>')
    out, n = html_for_render(page)
    low = out.lower()
    for bad in ("file:", "https:", "<script", "<iframe", "<object", "<embed", "<link", "<svg", "alert"):
        assert bad not in low, bad
    assert 'src="data:image/png;base64,AAAA"' in out and 'bgcolor="#000"' in out and "<p>hi</p>" in out
    assert n >= 10


def nest(n):
    s = 'location="https://x.example/a"'
    for _ in range(n):
        s = 'atob("' + base64.b64encode(s.encode()).decode() + '")'
    return s


def test_deep_nesting_is_followed():
    d = D.deobfuscate(nest(8))
    assert dict(d["urls"])["https://x.example/a"] == 8 and not d["truncated"]


def test_nesting_past_the_limit_is_reported_not_silent():
    d = D.deobfuscate(nest(D.LIMITS["layers"] + 3))
    assert d["truncated"] and not d["urls"]

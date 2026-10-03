var J = require('./engine.js'), fails = 0, n = 0, pending = [];
function eq(a, b, m) { n++; if (JSON.stringify(a) !== JSON.stringify(b)) { fails++; console.log('FAIL', m, JSON.stringify(a), JSON.stringify(b)); } }
// RFC 7519 section 3.1 example JWT (HS256), and RFC 7515 A.1 key
var RFC = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
var KEY = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';
var d = J.decode(RFC);
eq(d.header, { typ: 'JWT', alg: 'HS256' }, 'rfc header'); eq(d.claims.iss, 'joe', 'rfc iss'); eq(d.claims.exp, 1300819380, 'rfc exp'); eq(d.claims['http://example.com/is_root'], true, 'rfc private claim');
eq(J.iso(1300819380), '2011-03-22T18:43:00Z', 'exp date');
eq(d.signingInput, RFC.split('.').slice(0, 2).join('.'), 'signing input');
// RFC 7519 section 6.1 unsecured JWT
var U = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.';
var u = J.decode(U); eq(u.header, { alg: 'none' }, 'unsecured header'); eq(u.signature, '', 'empty sig');
eq(J.check(u, 1300819000, 0).some(function (x) { return x.level === 'bad' && /none/.test(x.text); }), true, 'none flagged');
// check: time rules
var rf = J.check(d, 1300819379, 0); eq(rf.some(function (x) { return x.level === 'ok' && /Not expired: 1 s left/.test(x.text); }), true, 'one sec left');
rf = J.check(d, 1300819380, 0); eq(rf.some(function (x) { return x.level === 'bad' && /Expired 0 s ago/.test(x.text); }), true, 'exp is exclusive');
rf = J.check(d, 1300819400, 60); eq(rf.some(function (x) { return x.level === 'ok'; }), true, 'leeway');
rf = J.check(d, 1700000000, 0); eq(rf.some(function (x) { return /Expired/.test(x.text); }), true, 'expired');
function tok(h, c, s) { var e = function (o) { return J.bytesToB64u(new TextEncoder().encode(JSON.stringify(o))); }; return e(h) + '.' + e(c) + '.' + (s === undefined ? 'c2ln' : s); }
var t1 = J.decode(tok({ alg: 'HS256' }, { nbf: 2000, iat: 1500, exp: 3000 }));
eq(J.check(t1, 1000, 0).some(function (x) { return x.level === 'bad' && /Not valid yet/.test(x.text); }), true, 'nbf future');
eq(J.check(t1, 2500, 0).some(function (x) { return x.level === 'info' && /Lifetime: 25 min 0 s/.test(x.text); }), true, 'lifetime');
eq(J.check(J.decode(tok({ alg: 'HS256' }, { iat: 9999 })), 1000, 0).some(function (x) { return /future/.test(x.text); }), true, 'iat future');
eq(J.check(J.decode(tok({ alg: 'HS256' }, { sub: 'a' })), 1000, 0).some(function (x) { return x.level === 'warn' && /never expires/.test(x.text); }), true, 'no exp warn');
eq(J.check(J.decode(tok({ alg: 'HS256' }, { exp: '3000' })), 1000, 0).some(function (x) { return x.level === 'bad' && /NumericDate/.test(x.text); }), true, 'string exp');
eq(J.check(J.decode(tok({ alg: 'HS256' }, { exp: 5, iat: 10 })), 1, 0).some(function (x) { return /before "iat"/.test(x.text); }), true, 'exp before iat');
eq(J.check(J.decode(tok({}, { exp: 5 })), 1, 0).some(function (x) { return /no "alg"/.test(x.text); }), true, 'no alg');
eq(J.check(J.decode(tok({ alg: 'HS256' }, { exp: 5 }, '')), 1, 0).some(function (x) { return /empty/.test(x.text); }), true, 'empty sig flagged');
eq(J.check(J.decode(tok({ alg: 'HS256' }, { aud: [1] })), 1, 0).some(function (x) { return /aud/.test(x.text); }), true, 'bad aud');
eq(J.check(J.decode(tok({ alg: 'HS256' }, { aud: ['a', 'b'], iss: 'x' })), 1, 0).some(function (x) { return /aud|iss/.test(x.text); }), false, 'good aud');
// decode errors
eq(!!J.decode('abc').error, true, 'one part'); eq(!!J.decode('a.b').error, true, 'two parts'); eq(!!J.decode('').error, true, 'empty'); eq(!!J.decode('a.b.c.d').error, true, 'four');
eq(/encrypted/.test(J.decode('a.b.c.d.e').error), true, 'JWE');
eq(!!J.decode('%%%.e30.x').error, true, 'bad b64'); eq(!!J.decode('e30.bm90anNvbg.x').error, true, 'bad json'); eq(!!J.decode('W10.e30.x').error, true, 'array header'); eq(!!J.decode('e30.e30.%').error, true, 'bad sig b64');
eq(!!J.decode('e30.e30.eA').error, false, 'minimal ok');
eq(J.decode('  Bearer ' + RFC + '  ').header.alg, 'HS256', 'bearer prefix'); eq(J.decode(RFC.replace(/\./g, '.\n')).claims.iss, 'joe', 'whitespace');
eq(!!J.decode('/w.e30.x').error, true, 'invalid utf8');
eq(J.dur(59), '59 s', 'dur s'); eq(J.dur(3600), '1 h 0 min', 'dur h'); eq(J.dur(86400), '1 day 0 h', 'dur day'); eq(J.dur(86400 * 3 + 7200), '3 days 2 h', 'dur days');
eq(J.bytesToB64u(J.b64uToBytes('eyJhbGciOiJub25lIn0')), 'eyJhbGciOiJub25lIn0', 'b64 roundtrip');
// HMAC verification against the RFC 7515 key
pending.push(J.verifyHmac(d, J.b64uToBytes(KEY)).then(function (r) { eq(r.supported, true, 'hmac supported'); eq(r.valid, true, 'RFC signature valid'); }));
pending.push(J.verifyHmac(d, new TextEncoder().encode('wrong')).then(function (r) { eq(r.valid, false, 'wrong secret'); }));
var parts = RFC.split('.'); parts[1] = J.bytesToB64u(new TextEncoder().encode(JSON.stringify({ iss: 'eve', exp: 1300819380 }))); var tampered = J.decode(parts.join('.'));
pending.push(J.verifyHmac(tampered, J.b64uToBytes(KEY)).then(function (r) { eq(r.valid, false, 'tampered payload fails'); }));
pending.push(J.verifyHmac(J.decode(tok({ alg: 'RS256' }, {})), new Uint8Array(1)).then(function (r) { eq(r.supported, false, 'RS256 unsupported'); }));
pending.push(J.verifyHmac(u, new Uint8Array(1)).then(function (r) { eq(r.supported, false, 'none unsupported'); }));
Promise.all(pending).then(function () { console.log(n - fails + '/' + n + ' pass'); process.exit(fails ? 1 : 0); });

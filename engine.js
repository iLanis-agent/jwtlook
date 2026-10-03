(function (root) {
  function b64uToBytes(s) {
    if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
    if (s.length % 4 === 1) return null;
    var b = s.replace(/-/g, '+').replace(/_/g, '/'); while (b.length % 4) b += '=';
    if (typeof atob === 'function') { var bin = atob(b), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
    return new Uint8Array(Buffer.from(b, 'base64'));
  }
  function bytesToB64u(u) {
    var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    var b = typeof btoa === 'function' ? btoa(s) : Buffer.from(s, 'binary').toString('base64');
    return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function utf8(u) { return typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { fatal: true }).decode(u) : Buffer.from(u).toString('utf8'); }
  function part(s, name) {
    var u = b64uToBytes(s); if (!u) return { error: name + ' is not valid base64url.' };
    var txt; try { txt = utf8(u); } catch (e) { return { error: name + ' is not valid UTF-8.' }; }
    var o; try { o = JSON.parse(txt); } catch (e) { return { error: name + ' is not valid JSON.' }; }
    if (o === null || typeof o !== 'object' || Array.isArray(o)) return { error: name + ' must be a JSON object.' };
    return { value: o };
  }
  function decode(token) {
    if (typeof token !== 'string') return { error: 'Paste a token.' };
    var t = token.trim().replace(/^bearer\s+/i, '').replace(/\s+/g, '');
    if (t === '') return { error: 'Paste a token.' };
    var p = t.split('.');
    if (p.length === 5) return { error: 'This has 5 parts: it looks like an encrypted JWT (JWE). Its contents cannot be read without the key.' };
    if (p.length !== 3) return { error: 'A signed JWT has 3 parts separated by dots; this has ' + p.length + '.' };
    var h = part(p[0], 'Header'); if (h.error) return { error: h.error };
    var c = part(p[1], 'Payload'); if (c.error) return { error: c.error };
    if (p[2] !== '' && b64uToBytes(p[2]) === null) return { error: 'Signature is not valid base64url.' };
    return { header: h.value, claims: c.value, signingInput: p[0] + '.' + p[1], signature: p[2], raw: t };
  }
  function isNum(x) { return typeof x === 'number' && isFinite(x); }
  // nowSec: seconds since epoch; leeway seconds
  function check(d, nowSec, leeway) {
    leeway = leeway || 0;
    var c = d.claims, h = d.header, out = [];
    function add(level, text) { out.push({ level: level, text: text }); }
    var alg = h.alg;
    if (alg === undefined) add('bad', 'Header has no "alg".');
    else if (typeof alg === 'string' && alg.toLowerCase() === 'none') add('bad', 'alg is "none": an unsecured JWT. Nothing proves who made it. Never accept it where a signature is required.');
    if (d.signature === '' && !(typeof alg === 'string' && alg.toLowerCase() === 'none')) add('bad', 'The signature part is empty.');
    ['exp', 'nbf', 'iat'].forEach(function (k) { if (k in c && !isNum(c[k])) add('bad', '"' + k + '" must be a number of seconds (NumericDate), found ' + JSON.stringify(c[k]) + '.'); });
    if (isNum(c.exp)) {
      if (nowSec >= c.exp + leeway) add('bad', 'Expired ' + dur(nowSec - c.exp) + ' ago.');
      else add('ok', 'Not expired: ' + dur(c.exp - nowSec) + ' left.');
    } else if (!('exp' in c)) add('warn', 'No "exp": this token never expires by itself.');
    if (isNum(c.nbf)) { if (nowSec + leeway < c.nbf) add('bad', 'Not valid yet: "nbf" is ' + dur(c.nbf - nowSec) + ' away.'); else add('ok', 'Past its "nbf" time.'); }
    if (isNum(c.iat)) { if (c.iat > nowSec + leeway) add('warn', '"iat" is ' + dur(c.iat - nowSec) + ' in the future: check clocks.'); }
    if (isNum(c.iat) && isNum(c.exp)) { if (c.exp < c.iat) add('warn', '"exp" is before "iat".'); else add('info', 'Lifetime: ' + dur(c.exp - c.iat) + '.'); }
    ['iss', 'sub', 'jti'].forEach(function (k) { if (k in c && typeof c[k] !== 'string') add('warn', '"' + k + '" should be a string.'); });
    if ('aud' in c && !(typeof c.aud === 'string' || (Array.isArray(c.aud) && c.aud.every(function (x) { return typeof x === 'string'; })))) add('warn', '"aud" should be a string or an array of strings.');
    return out;
  }
  function dur(s) {
    s = Math.abs(Math.round(s));
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.floor(s / 60) + ' min ' + (s % 60) + ' s';
    if (s < 86400) return Math.floor(s / 3600) + ' h ' + Math.floor(s % 3600 / 60) + ' min';
    var d = Math.floor(s / 86400); return d + (d === 1 ? ' day ' : ' days ') + Math.floor(s % 86400 / 3600) + ' h';
  }
  function iso(sec) { return new Date(sec * 1000).toISOString().replace('.000Z', 'Z'); }
  var HASH = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
  // secret: Uint8Array of key bytes
  function verifyHmac(d, secret) {
    var alg = d.header.alg, hash = HASH[alg];
    if (!hash) return Promise.resolve({ supported: false, reason: 'Only HS256, HS384 and HS512 can be checked here (they need the shared secret). ' + (alg ? alg + ' needs a public key.' : '') });
    var s = typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null;
    if (!s) return Promise.resolve({ supported: false, reason: 'This browser cannot do HMAC here.' });
    var input = new TextEncoder().encode(d.signingInput);
    return s.importKey('raw', secret, { name: 'HMAC', hash: hash }, false, ['sign']).then(function (k) { return s.sign('HMAC', k, input); }).then(function (sig) {
      var got = bytesToB64u(new Uint8Array(sig));
      return { supported: true, valid: got === d.signature, expected: got };
    });
  }
  var api = { decode: decode, check: check, verifyHmac: verifyHmac, b64uToBytes: b64uToBytes, bytesToB64u: bytesToB64u, dur: dur, iso: iso };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.JwtLook = api;
})(typeof window !== 'undefined' ? window : this);

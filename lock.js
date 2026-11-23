/* Floor Fix lock + decrypt. WebCrypto only. Silent. No site facts in this file. */
(function () {
  'use strict';
  var BASE = new URL('./', location.href);
  var IDB_NAME = 'ffh-lock';
  var IDB_STORE = 'kv';
  var APP_CSS = ['styles.css', 'cc.css', 'vendor/b6_floor_map.css'];
  var APP_JS = ['vendor/nc_art.js', 'vendor/ff_engine.js', 'vendor/b6_floor_map.js', 'app_more.js', 'app.js'];
  var dbp = null;
  var meta = null;
  var booting = false;

  function $(id) { return document.getElementById(id); }
  function pathURL(p) { return new URL(p, BASE).href; }
  function setErr(t) {
    var e = $('lock-err');
    if (!e) return;
    if (!t) { e.hidden = true; e.textContent = ''; return; }
    e.hidden = false;
    e.textContent = t;
  }
  function setProg(t, frac) {
    var p = $('lock-prog');
    var bar = $('lock-bar');
    var fill = $('lock-bar-fill');
    if (p) { p.hidden = !t; p.textContent = t || ''; }
    if (bar) bar.hidden = !t;
    if (fill) fill.style.width = Math.max(0, Math.min(100, Math.round((frac || 0) * 100))) + '%';
  }

  function openDb() {
    if (dbp) return dbp;
    dbp = new Promise(function (res, rej) {
      try {
        var r = indexedDB.open(IDB_NAME, 1);
        r.onupgradeneeded = function () { r.result.createObjectStore(IDB_STORE); };
        r.onsuccess = function () { res(r.result); };
        r.onerror = function () { rej(r.error || new Error('storage')); };
      } catch (e) { rej(e); }
    });
    return dbp;
  }
  function idbGet(k) {
    return openDb().then(function (db) {
      return new Promise(function (res, rej) {
        var q = db.transaction(IDB_STORE, 'readonly').objectStore(IDB_STORE).get(k);
        q.onsuccess = function () { res(q.result); };
        q.onerror = function () { rej(q.error); };
      });
    });
  }
  function idbSet(k, v) {
    return openDb().then(function (db) {
      return new Promise(function (res, rej) {
        var tx = db.transaction(IDB_STORE, 'readwrite');
        tx.objectStore(IDB_STORE).put(v, k);
        tx.oncomplete = function () { res(true); };
        tx.onerror = tx.onabort = function () { rej(tx.error); };
      });
    });
  }

  function loadMeta() {
    if (meta) return Promise.resolve(meta);
    return fetch(pathURL('crypto.json'), { cache: 'reload' }).then(function (r) {
      if (!r.ok) throw new Error('missing crypto.json');
      return r.json();
    }).then(function (j) { meta = j; return j; });
  }
  function plainName(pack) { return 'ffh-plain-' + pack; }
  function coreName(pack) { return 'ffh-core-' + pack; }

  function deriveKey(pass, salt, iter) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']).then(function (km) {
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: iter, hash: 'SHA-256' },
        km,
        { name: 'AES-GCM', length: 256 },
        true,
        ['decrypt']
      );
    });
  }
  function normalize(s) {
    return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
  }
  function b64(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bundlePath(id) { return 'b/' + id + '.bin'; }
  function unmaskBuf(buf) {
    var u = new Uint8Array(buf);
    if (u.length % 2) throw new Error('bad pack');
    var out = new Uint8Array(u.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = ((u[2 * i] & 0x0f) << 4) | (u[2 * i + 1] & 0x0f);
    return out.buffer;
  }
  function gunzipBuf(buf) {
    if (typeof DecompressionStream === 'undefined') {
      return Promise.reject(new Error('This browser cannot open the library.'));
    }
    return new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
  }

  function getBundle(id, coreCache) {
    var u = pathURL(bundlePath(id));
    return coreCache.match(u, { ignoreSearch: true }).then(function (hit) {
      if (hit) return hit.arrayBuffer().then(unmaskBuf);
      return fetch(u).then(function (r) {
        if (!r.ok) throw new Error('missing pack file');
        var copy = r.clone();
        coreCache.put(u, copy);
        return r.arrayBuffer().then(unmaskBuf);
      });
    });
  }

  function decryptSlice(key, buf, off, len) {
    var slice = new Uint8Array(buf, off, len);
    var iv = slice.subarray(0, 12);
    var data = slice.subarray(12);
    var ivCopy = new Uint8Array(iv);
    var dataCopy = new Uint8Array(data);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivCopy }, key, dataCopy).then(gunzipBuf);
  }

  function putPlain(cache, path, bytes, mime) {
    var headers = { 'Content-Type': mime || 'application/octet-stream' };
    var res = new Response(bytes, { headers: headers });
    return cache.put(pathURL(path), res);
  }

  function decryptGroup(key, files, bundles, cache, coreCache, onProg) {
    var ids = Object.keys(bundles);
    var buffers = {};
    var done = 0;
    var total = files.length + ids.length;
    function bump(msg) {
      done++;
      if (onProg) onProg(msg, done / total);
    }
    return ids.reduce(function (p, id) {
      return p.then(function () {
        return getBundle(id, coreCache).then(function (buf) {
          buffers[id] = buf;
          bump('Reading the locked library…');
        });
      });
    }, Promise.resolve()).then(function () {
      function one(i) {
        if (i >= files.length) return Promise.resolve();
        var f = files[i];
        return decryptSlice(key, buffers[f.b], f.o, f.n).then(function (plain) {
          return putPlain(cache, f.path, plain, f.t).then(function () {
            bump('Saving on this phone…');
            return one(i + 1);
          });
        });
      }
      return one(0);
    });
  }

  function fileList(m, group) {
    var out = [];
    var files = m.files || {};
    Object.keys(files).forEach(function (path) {
      var f = files[path];
      if (f.g === group) out.push({ path: path, b: f.b, o: f.o, n: f.n, t: f.t });
    });
    return out;
  }
  function bundleMap(m, group) {
    var map = {};
    var list = group === 'lib' ? (m.lib_bundles || []) : (m.core_bundles || []);
    list.forEach(function (id) { map[id] = true; });
    return map;
  }

  function confirmCanary(cache, pack) {
    return cache.match(pathURL('canary'), { ignoreSearch: true }).then(function (r) {
      if (!r) throw new Error('bad passcode');
      return r.text();
    }).then(function (t) {
      if (String(t).trim() !== 'FLOOR_FIX_OK:' + pack) throw new Error('bad passcode');
    });
  }

  function unlockWithPass(pass) {
    return loadMeta().then(function (m) {
      var salt = b64(m.salt);
      setProg('Checking the passcode…', 0.05);
      return deriveKey(pass, salt, m.iter).then(function (key) {
        return caches.open(plainName(m.pack)).then(function (plain) {
          return caches.open(coreName(m.pack)).then(function (core) {
            var files = fileList(m, 'core');
            setProg('Unlocking the library…', 0.08);
            return decryptGroup(key, files, bundleMap(m, 'core'), plain, core, function (msg, frac) {
              setProg(msg, 0.08 + frac * 0.8);
            }).then(function () {
              return confirmCanary(plain, m.pack);
            }).then(function () {
              return crypto.subtle.exportKey('raw', key).then(function (raw) {
                return idbSet('pack', m.pack).then(function () {
                  return idbSet('key', raw);
                }).then(function () {
                  return idbSet('unlocked', 1);
                });
              });
            });
          });
        });
      });
    });
  }

  function alreadyUnlocked() {
    return loadMeta().then(function (m) {
      return idbGet('unlocked').then(function (u) {
        if (!u) return false;
        return idbGet('pack').then(function (p) {
          if (p !== m.pack) return false;
          return caches.open(plainName(m.pack)).then(function (c) {
            return c.match(pathURL('data/pack.json'), { ignoreSearch: true }).then(function (hit) {
              return !!hit;
            });
          });
        });
      });
    }).catch(function () { return false; });
  }

  function addSheet(href) {
    var l = document.createElement('link');
    l.rel = 'stylesheet';
    l.href = pathURL(href);
    document.head.appendChild(l);
  }
  function loadScript(path) {
    return caches.open(plainName(meta.pack)).then(function (c) {
      return c.match(pathURL(path), { ignoreSearch: true });
    }).then(function (r) {
      if (!r) throw new Error('missing ' + path);
      return r.text();
    }).then(function (code) {
      var s = document.createElement('script');
      s.text = code;
      document.body.appendChild(s);
    });
  }
  function bootApp() {
    if (booting) return Promise.resolve();
    booting = true;
    return loadMeta().then(function () {
      var lock = $('lock-root');
      var app = $('app');
      if (lock) lock.hidden = true;
      if (app) app.hidden = false;
      APP_CSS.forEach(addSheet);
      function next(i) {
        if (i >= APP_JS.length) return Promise.resolve();
        return loadScript(APP_JS[i]).then(function () { return next(i + 1); });
      }
      return next(0);
    });
  }

  function registerSW() {
    if (!('serviceWorker' in navigator) || location.protocol === 'file:') return Promise.resolve(null);
    return navigator.serviceWorker.register(pathURL('sw.js')).then(function (reg) {
      if (reg.waiting) reg.waiting.postMessage('ffh-skip-waiting');
      return navigator.serviceWorker.ready.then(function () { return reg; });
    }).catch(function () { return null; });
  }

  function installFetchGate() {
    var orig = window.fetch.bind(window);
    window.fetch = function (input, init) {
      var req = (input instanceof Request) ? input : new Request(input, init);
      var u = new URL(req.url, location.href);
      if (u.origin !== location.origin) return orig(input, init);
      if (!meta) return orig(input, init);
      return caches.open(plainName(meta.pack)).then(function (c) {
        return c.match(req, { ignoreSearch: true }).then(function (hit) {
          if (hit) return hit;
          var rel = u.pathname.replace(new URL('./', location.href).pathname, '');
          if (rel.indexOf('/') === 0) rel = rel.slice(1);
          var f = meta.files && meta.files[rel];
          if (!f) return orig(input, init);
          return decryptOnDemand(rel, f).then(function (res) { return res || orig(input, init); });
        });
      });
    };
  }

  function decryptOnDemand(path, f) {
    return idbGet('key').then(function (raw) {
      if (!raw) return null;
      return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']).then(function (key) {
        return caches.open(coreName(meta.pack)).then(function (core) {
          return getBundle(f.b, core).then(function (buf) {
            return decryptSlice(key, buf, f.o, f.n).then(function (plain) {
              return caches.open(plainName(meta.pack)).then(function (c) {
                return putPlain(c, path, plain, f.t).then(function () {
                  return new Response(plain, { headers: { 'Content-Type': f.t || 'application/octet-stream' } });
                });
              });
            });
          });
        });
      });
    }).catch(function () { return null; });
  }

  function onSubmit(ev) {
    ev.preventDefault();
    var btn = $('unlock');
    var input = $('pass');
    var pass = normalize(input && input.value);
    if (!pass) { setErr('Type the passcode.'); return; }
    setErr('');
    if (btn) btn.disabled = true;
    setProg('Unlocking…', 0.02);
    unlockWithPass(pass).then(function () {
      if (input) input.value = '';
      setProg('Opening the app…', 1);
      if (navigator.storage && navigator.storage.persist) {
        try { navigator.storage.persist(); } catch (e) { /* best effort */ }
      }
      return registerSW().then(function () {
        installFetchGate();
        return bootApp();
      });
    }).catch(function () {
      setErr('Wrong passcode. Try again.');
      setProg('', 0);
      if (btn) btn.disabled = false;
      if (input) { input.value = ''; input.focus(); }
    });
  }

  function start() {
    var form = $('lock-form');
    if (form) form.addEventListener('submit', onSubmit);
    registerSW();
    alreadyUnlocked().then(function (ok) {
      if (!ok) {
        var input = $('pass');
        if (input) input.focus();
        return;
      }
      setProg('Opening the saved library…', 1);
      installFetchGate();
      return bootApp();
    }).catch(function () {
      var input = $('pass');
      if (input) input.focus();
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();

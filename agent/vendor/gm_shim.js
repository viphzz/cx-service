/**
 * OCS GM API 垫片（document-start 注入，对每个 frame 生效）
 *
 * 为什么必须有这一层：
 * ocs.user.js 入口有硬性环境检测，12 个 GM_* 只要有一个 undefined 就 confirm + return。
 * 另外 @ocsjs/core 的 store 层按 `typeof globalThis.unsafeWindow === 'undefined'`
 * 决定用 MemoryStoreProvider（刷新即丢）还是 GMStoreProvider（持久化）。
 * 所以 unsafeWindow 必须在 core 之前就存在。
 *
 * 语义映射：
 *   GM_setValue   -> localStorage（同源持久，跨标签共享）
 *   GM_getTab     -> window.top 上的对象（每标签页临时态，需跨 iframe 共享）
 *   GM_addValueChangeListener -> BroadcastChannel（同源跨 frame 通知）
 *   GM_xmlhttpRequest -> fetch（跨域交给 Playwright 的 route 兜底）
 *   GM_notification   -> 转发给外部桥 window.__ocsNotify
 */
(function () {
  if (window.__OCS_SHIM__) return;
  window.__OCS_SHIM__ = true;

  var PFX = '__ocs_v_';
  var topWin;
  try { topWin = window.top; } catch (e) { topWin = window; }
  if (!topWin) topWin = window;

  /* ---- unsafeWindow ---- */
  window.unsafeWindow = window;

  /* ---- fetch 保护层 ----
   * ocs.user.js:9930 把 window.fetch 换成了一个箭头函数，里面写的是
   *   originalFetch.apply(this, [input, init])
   * 箭头函数的 this 来自词法作用域，不是调用者。原生 fetch 拿到错误的
   * this 就直接抛 "Illegal invocation"，OCS 所有请求都会挂——答题全废正是
   * 这个原因。这里在 OCS 捕获之前，先把原生 fetch 包成永久绑定 window 的
   * 函数，OCS 之后 apply 任何 this 都无所谓了。
   */
  var __nativeFetch = window.fetch;
  if (typeof __nativeFetch === 'function') {
    window.fetch = function (input, init) {
      return __nativeFetch.call(window, input, init);
    };
  }

  /* ---- GM_info ---- */
  window.GM_info = {
    script: {
      name: 'OCS 网课助手',
      version: '4.13.16',
      icon: '',
      scriptHandler: 'ocs-runner'
    },
    scriptHandler: 'ocs-runner',
    version: '4.13.16',
    scriptMetaStr:
      '// ==UserScript==\n' +
      '// @name        OCS 网课助手\n' +
      '// @version     4.13.16\n' +
      '// @run-at      document-start\n' +
      '// ==/UserScript==\n'
  };

  /* ---- 持久化存储 ---- */
  window.GM_getValue = function (key, def) {
    try {
      var v = localStorage.getItem(PFX + key);
      return v === null ? def : JSON.parse(v);
    } catch (e) { return def; }
  };

  var bc = null;
  try { bc = new BroadcastChannel('ocs-gm-bus'); } catch (e) { bc = null; }

  var listeners = Object.create(null);
  var lid = 0;

  function fire(key, pre, curr) {
    for (var id in listeners) {
      var item = listeners[id];
      if (item && item.key === key) {
        try { item.cb(key, pre, curr, false); } catch (e) {}
      }
    }
  }

  if (bc) {
    bc.onmessage = function (e) {
      var d = e.data || {};
      if (d.type !== 'set') return;
      for (var id in listeners) {
        var item = listeners[id];
        if (item && item.key === d.key) {
          try { item.cb(d.key, d.pre, d.curr, true); } catch (err) {}
        }
      }
    };
  }

  window.GM_setValue = function (key, value) {
    var pre;
    try { pre = window.GM_getValue(key); } catch (e) { pre = undefined; }
    try { localStorage.setItem(PFX + key, JSON.stringify(value)); } catch (e) {}
    fire(key, pre, value);
    if (bc) { try { bc.postMessage({ type: 'set', key: key, pre: pre, curr: value }); } catch (e) {} }
  };

  window.GM_deleteValue = function (key) {
    try { localStorage.removeItem(PFX + key); } catch (e) {}
  };

  window.GM_listValues = function () {
    var out = [];
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (k && k.indexOf(PFX) === 0) out.push(k.slice(PFX.length));
      }
    } catch (e) {}
    return out;
  };

  window.GM_addValueChangeListener = function (key, cb) {
    var id = ++lid;
    listeners[id] = { key: key, cb: cb };
    return id;
  };

  window.GM_removeValueChangeListener = function (id) {
    delete listeners[id];
  };

  /* ---- 标签页存储：挂 top，因为 OCS 用它在 iframe 与主页之间同步状态 ---- */
  try {
    if (!topWin.__ocsTab) topWin.__ocsTab = {};
  } catch (e) {
    if (!window.__ocsTab) window.__ocsTab = {};
  }

  window.GM_getTab = function (cb) {
    var tab;
    try { tab = topWin.__ocsTab || {}; } catch (e) { tab = window.__ocsTab || {}; }
    if (typeof cb === 'function') cb(tab);
    return tab;
  };

  window.GM_saveTab = function (tab) {
    try {
      var target = topWin.__ocsTab || (topWin.__ocsTab = {});
      for (var k in tab) { if (Object.prototype.hasOwnProperty.call(tab, k)) target[k] = tab[k]; }
    } catch (e) {}
  };

  /* ---- 网络：跨域请求 ---- */
  window.GM_xmlhttpRequest = function (opts) {
    opts = opts || {};
    var init = {
      method: (opts.method || 'GET').toUpperCase(),
      headers: opts.headers || {},
      // 超星接口靠 cookie 认人，不带上等于没登录
      credentials: 'include'
    };
    if (opts.data !== undefined && init.method !== 'GET') {
      init.body = typeof opts.data === 'string' ? opts.data : JSON.stringify(opts.data);
      if (!init.headers['Content-Type'] && !init.headers['content-type']) {
        init.headers['Content-Type'] = 'application/json';
      }
    }

    // 必须 bind：裸调 fetch 时 this 是 undefined，
    // 浏览器会抛 "Failed to execute 'fetch' on 'Window': Illegal invocation"
    var doFetch = (typeof window.fetch === 'function') ? window.fetch.bind(window) : null;

    function fail(err) {
      if (opts.onerror) { try { opts.onerror(err); } catch (e) {} }
      if (opts.ontimeout) { try { opts.ontimeout(err); } catch (e) {} }
    }

    if (!doFetch) {
      fail(new Error('fetch unavailable'));
      return;
    }

    doFetch(opts.url, init)
      .then(function (r) {
        return r.text().then(function (text) {
          var payload = text;
          if (opts.responseType === 'json') {
            try { payload = JSON.parse(text); } catch (e) { payload = text; }
          }
          var res = {
            status: r.status,
            statusText: r.statusText,
            response: payload,
            responseText: text,
            finalUrl: r.url,
            readyState: 4
          };
          if (opts.onload) { try { opts.onload(res); } catch (e) {} }
          return res;
        });
      })
      .catch(fail);
  };

  /* ---- 通知：转发给外部桥（Playwright expose_binding 提供） ---- */
  window.GM_notification = function (opts) {
    opts = opts || {};
    var fn = null;
    try { fn = window.__ocsNotify || topWin.__ocsNotify; } catch (e) { fn = window.__ocsNotify; }
    if (typeof fn === 'function') {
      try {
        fn(JSON.stringify({
          title: opts.title || '',
          text: opts.text || '',
          important: !!opts.highlight,
          ts: Date.now()
        }));
      } catch (e) {}
    }
  };

  /* ---- 资源 ---- */
  window.GM_getResourceText = function () { return ''; };

  /* ---- 控制台桥（可选，用于把 OCS 内部日志抽出来） ---- */
  var _log = console.log;
  console.log = function () {
    try {
      var fn = window.__ocsLog;
      if (typeof fn === 'function') {
        var line = Array.prototype.map.call(arguments, function (a) {
          if (typeof a === 'string') return a;
          try { return JSON.stringify(a); } catch (e) { return String(a); }
        }).join(' ');
        if (line.indexOf('[ocsjs]') >= 0 || line.indexOf('[OCS]') >= 0) fn(line.slice(0, 2000));
      }
    } catch (e) {}
    return _log.apply(console, arguments);
  };
})();

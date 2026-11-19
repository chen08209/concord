(function (global) {
  const native = global.__native;
  delete global.__native;
  const input = JSON.parse(native.input());
  const MAX_TIMERS = 64;
  const MAX_REQUESTS = 20;
  const MAX_LOG_LINE = 4096;
  const MS_TIMEOUTS = 300;
  const isResponse = input.kind === 'http-response';
  const hasRequest = input.request != null;

  const toText = (value) => (value === undefined || value === null ? '' : String(value));
  const isNil = (value) => value === undefined || value === null;
  const isObject = (value) => value !== null && (typeof value === 'object' || typeof value === 'function');
  const stringify = (value) => {
    try {
      const text = JSON.stringify(value);
      return text === undefined ? null : text;
    } catch (e) {
      return null;
    }
  };

  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const B64_INDEX = {};
  for (let i = 0; i < 64; i++) B64_INDEX[B64[i]] = i;

  const bytesToB64 = (bytes) => {
    const parts = [];
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i];
      const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      const n = (a << 16) | (b << 8) | c;
      parts.push(
        B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=') + (i + 2 < bytes.length ? B64[n & 63] : '='),
      );
    }
    return parts.join('');
  };

  const b64ToBytes = (text) => {
    const clean = text.replace(/[\s=]+/g, '');
    const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
    let acc = 0;
    let bits = 0;
    let at = 0;
    for (let i = 0; i < clean.length; i++) {
      const value = B64_INDEX[clean[i]];
      if (value === undefined) return null;
      acc = (acc << 6) | value;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[at++] = (acc >> bits) & 255;
      }
    }
    return out.subarray(0, at);
  };

  const utf8Encode = (text) => {
    const out = [];
    for (let i = 0; i < text.length; i++) {
      let code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        const low = text.charCodeAt(i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
          i++;
        }
      }
      if (code >= 0xd800 && code <= 0xdfff) code = 0xfffd;
      if (code < 0x80) out.push(code);
      else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 63));
      else if (code < 0x10000) out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      else out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    }
    return new Uint8Array(out);
  };

  const utf8Decode = (bytes, fatal) => {
    let out = '';
    let i = 0;
    const bad = () => {
      if (fatal) throw new TypeError('The encoded data was not valid utf-8');
      out += '�';
    };
    while (i < bytes.length) {
      const first = bytes[i];
      let need = 0;
      let code = 0;
      let min = 0;
      if (first < 0x80) {
        out += String.fromCharCode(first);
        i++;
        continue;
      } else if (first >= 0xc2 && first <= 0xdf) {
        need = 1;
        code = first & 0x1f;
        min = 0x80;
      } else if (first >= 0xe0 && first <= 0xef) {
        need = 2;
        code = first & 0x0f;
        min = 0x800;
      } else if (first >= 0xf0 && first <= 0xf4) {
        need = 3;
        code = first & 0x07;
        min = 0x10000;
      } else {
        bad();
        i++;
        continue;
      }
      let used = 1;
      while (used <= need && i + used < bytes.length && (bytes[i + used] & 0xc0) === 0x80) {
        code = (code << 6) | (bytes[i + used] & 63);
        used++;
      }
      if (used <= need || code < min || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
        bad();
        i += used <= need ? used : 1;
        continue;
      }
      out += String.fromCodePoint(code);
      i += used;
    }
    return out;
  };

  const bytesOf = (value) => {
    if (!isObject(value)) return null;
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    return null;
  };

  const rangeError = (message) => new RangeError(message);

  global.btoa = (value) => {
    const text = toText(value);
    const bytes = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code > 0xff) throw rangeError('btoa: the string has characters outside Latin1');
      bytes[i] = code;
    }
    return bytesToB64(bytes);
  };

  global.atob = (value) => {
    let text = toText(value).replace(/[ \t\n\f\r]/g, '');
    text = text.replace(/=+$/, '');
    const bytes = b64ToBytes(text);
    if (bytes === null || text.length % 4 === 1) throw rangeError('atob: the string is not valid base64');
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return out;
  };

  global.TextEncoder = class TextEncoder {
    constructor() {
      this.encoding = 'utf-8';
    }
    encode(text) {
      return utf8Encode(toText(text));
    }
  };

  global.TextDecoder = class TextDecoder {
    constructor(label, options) {
      const name = label === undefined ? 'utf-8' : String(label).trim().toLowerCase();
      if (name !== 'utf-8' && name !== 'utf8' && name !== 'unicode-1-1-utf-8') {
        throw rangeError('TextDecoder supports utf-8 only, not ' + name);
      }
      this.encoding = 'utf-8';
      this.fatal = !!(options && options.fatal);
      this.ignoreBOM = !!(options && options.ignoreBOM);
    }
    decode(data) {
      if (data === undefined) return '';
      let bytes = bytesOf(data);
      if (bytes === null) throw new TypeError('TextDecoder.decode expects an ArrayBuffer or a view of one');
      if (!this.ignoreBOM && bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) bytes = bytes.subarray(3);
      return utf8Decode(bytes, this.fatal);
    }
  };

  const bodyValue = (body) => {
    if (body.b !== undefined) return b64ToBytes(body.b);
    return body.s;
  };

  const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  const canon = (name) => {
    if (!TOKEN.test(name)) return name;
    return name
      .split('-')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
      .join('-');
  };
  const validValue = (value) => !/[\u0000-\u0008\u000a-\u001f\u007f]/.test(value);

  const headerKey = (target, property) => {
    const names = Object.keys(target);
    if (names.indexOf(property) >= 0) return property;
    const lower = property.toLowerCase();
    for (const name of names) if (name.toLowerCase() === lower) return name;
    return property;
  };

  const headerObject = (header) => {
    const target = {};
    for (const name of Object.keys(header).sort()) target[name] = header[name].join(', ');
    return new Proxy(target, {
      get: (t, property, receiver) => (typeof property === 'string' ? t[headerKey(t, property)] : Reflect.get(t, property, receiver)),
      set: (t, property, value) => {
        t[typeof property === 'string' ? headerKey(t, property) : property] = value;
        return true;
      },
      has: (t, property) => (typeof property === 'string' ? headerKey(t, property) in t : property in t),
      deleteProperty: (t, property) => delete t[typeof property === 'string' ? headerKey(t, property) : property],
    });
  };

  const exportHeader = (object, shown) => {
    const header = new Map();
    for (const key of Object.keys(object)) {
      const field = object[key];
      if (isNil(field) || !TOKEN.test(key)) continue;
      const name = canon(key);
      let values;
      if (Array.isArray(field)) values = field.map(toText);
      else {
        const text = String(field);
        const was = shown && shown[name];
        values = was && was.length > 1 && was.join(', ') === text ? was.slice() : [text];
      }
      const kept = values.filter(validValue);
      if (kept.length > 0) header.set(name, kept);
    }
    return Array.from(header.entries());
  };

  const headerArray = (header) => {
    const list = [];
    for (const name of Object.keys(header).sort()) for (const value of header[name]) list.push({ field: name, value });
    return list;
  };

  const exportEntries = (list) => {
    const header = new Map();
    for (const entry of list) {
      if (!isObject(entry) || isNil(entry.field) || isNil(entry.value)) continue;
      const key = toText(entry.field);
      const value = toText(entry.value);
      if (!TOKEN.test(key) || !validValue(value)) continue;
      const name = canon(key);
      if (!header.has(name)) header.set(name, []);
      header.get(name).push(value);
    }
    return Array.from(header.entries());
  };

  const headerField = (object, shown) => {
    const value = object.headers;
    if (Array.isArray(value)) return exportEntries(value);
    return isObject(value) ? exportHeader(value, shown) : undefined;
  };

  const statusOf = (value) => {
    if (isNil(value)) return 0;
    if (typeof value === 'string') {
      const found = /\b[1-9]\d\d\b/.exec(value);
      return found ? parseInt(found[0], 10) : 0;
    }
    const number = Math.trunc(Number(value));
    return Number.isFinite(number) ? number : 0;
  };

  const encodeBody = (value) => {
    const bytes = bytesOf(value);
    if (bytes) return { b: bytesToB64(bytes) };
    if (isObject(value)) {
      const text = stringify(value);
      if (text !== null) return { s: text };
    }
    return { s: String(value) };
  };

  const bodyField = (object) => {
    for (const name of ['body', 'bodyBytes']) {
      const value = object[name];
      if (isNil(value)) continue;
      return encodeBody(value);
    }
    return undefined;
  };

  const withPath = (raw, path) => {
    try {
      return new URL(path, raw).href;
    } catch (e) {
      return '';
    }
  };

  const requestHeaders = hasRequest ? input.request.headers : null;
  const shownHeaders = (header) => (input.full ? headerArray(header) : headerObject(header));
  const responseHeaders = input.response ? input.response.headers : null;
  const responseTrailers = input.response ? input.response.trailers : undefined;

  let finished = false;
  const finish = (value) => {
    if (finished) return;
    finished = true;
    const result = {};
    const emit = () => native.done(JSON.stringify(result));
    if (!hasRequest) {
      const text = stringify(value);
      if (text !== null) result.value = text;
      return emit();
    }
    if (typeof value === 'string') {
      result.body = { s: value };
      return emit();
    }
    if (!isObject(value)) return emit();
    if (isResponse) {
      result.status = statusOf(value.status);
      result.header = headerField(value, responseHeaders);
      if (isObject(value.trailers)) result.trailers = exportHeader(value.trailers, responseTrailers);
    } else {
      result.url = toText(value.url);
      const path = toText(value.path);
      if (!result.url && path) result.url = withPath(input.request.url, path);
      result.header = headerField(value, requestHeaders);
      let answer = value.response;
      if (!isObject(answer) && statusOf(value.status) !== 0) answer = value;
      if (isObject(answer)) {
        result.response = { status: statusOf(answer.status), header: headerField(answer, null), body: bodyField(answer) };
        return emit();
      }
    }
    result.body = bodyField(value);
    result.abort = !!value.abort;
    return emit();
  };

  const timers = new Map();
  let nextTimer = 0;
  global.setTimeout = (callback, delay, ...args) => {
    if (typeof callback !== 'function') throw new TypeError('setTimeout expects a function');
    if (timers.size >= MAX_TIMERS) throw new Error('more than ' + MAX_TIMERS + ' timers are pending');
    let ms = Number(delay) || 0;
    if (!(ms >= 0)) ms = 0;
    ms = Math.min(ms, 24 * 3600 * 1000);
    const id = ++nextTimer;
    timers.set(id, { callback, args });
    native.timer(id, ms);
    return id;
  };
  global.clearTimeout = (id) => {
    if (timers.delete(Number(id))) native.cancel(Number(id));
  };
  global.__fire = (id) => {
    const timer = timers.get(id);
    if (!timer) return;
    timers.delete(id);
    timer.callback(...timer.args);
  };

  const format = (value) => {
    if (isObject(value) && typeof value !== 'function' && !(value instanceof Error)) {
      const text = stringify(value);
      if (text !== null) return text;
    }
    return toText(value);
  };
  const logger = (level) => (...args) => {
    let line = args.map(format).join(' ');
    if (line.length > MAX_LOG_LINE) line = line.slice(0, MAX_LOG_LINE) + '…';
    native.log(level, line);
  };
  global.console = { log: logger('info'), info: logger('info'), debug: logger('debug'), warn: logger('warn'), error: logger('error') };

  const storeKey = (value) => (isNil(value) ? input.name : String(value));
  global.$persistentStore = {
    read: (key) => {
      const value = native.read(storeKey(key));
      return value === undefined ? null : value;
    },
    write: (value, key) => (isNil(value) ? native.remove(storeKey(key)) : native.write(storeKey(key), String(value))),
  };

  const openUrl = (options) => {
    const url = isObject(options) ? (options.url ?? options['open-url'] ?? options.openUrl) : options;
    return typeof url === 'string' ? url : '';
  };

  global.$notification = {
    post: (title, subtitle, body, options) => {
      native.notify(toText(title), toText(subtitle), toText(body), openUrl(options));
    },
  };

  global.$utils = {
    ungzip: (data) => {
      const bytes = bytesOf(data);
      if (!bytes) return null;
      const out = native.ungzip(bytesToB64(bytes));
      return out === undefined ? null : b64ToBytes(out);
    },
  };

  const requests = new Map();
  let nextRequest = 0;
  const httpMethod = (method) => (options, callback) => {
    if (requests.size >= MAX_REQUESTS) throw new Error('more than ' + MAX_REQUESTS + ' requests are running');
    const request = { method, headers: [], timeout: 5000, redirect: true, binary: false, insecure: false };
    if (!isObject(options)) {
      request.url = toText(options);
    } else {
      request.url = toText(options.url);
      if (isObject(options.headers)) request.headers = exportHeader(options.headers, null);
      const body = options.body;
      if (!isNil(body)) {
        const bytes = bytesOf(body);
        if (bytes) request.body = { b: bytesToB64(bytes) };
        else if (isObject(body)) {
          request.body = { s: stringify(body) || '' };
          if (!request.headers.some(([name]) => name === 'Content-Type')) request.headers.push(['Content-Type', ['application/json']]);
        } else request.body = { s: String(body) };
      }
      if (!isNil(options.timeout)) {
        const value = Number(options.timeout);
        if (value > 0) request.timeout = value >= MS_TIMEOUTS ? value : value * 1000;
      }
      if (options['auto-redirect'] !== undefined) request.redirect = !!options['auto-redirect'];
      request.binary = !!options['binary-mode'];
      request.insecure = !!options.insecure;
    }
    const id = ++nextRequest;
    requests.set(id, { callback: typeof callback === 'function' ? callback : null, binary: request.binary });
    native.http(id, JSON.stringify(request));
  };
  global.$httpClient = {};
  for (const method of ['get', 'post', 'put', 'delete', 'head', 'options', 'patch']) global.$httpClient[method] = httpMethod(method.toUpperCase());
  global.__httpDone = (id, json) => {
    const pending = requests.get(id);
    if (!pending) return;
    requests.delete(id);
    if (!pending.callback) return;
    const result = JSON.parse(json);
    if (result.error !== undefined) {
      pending.callback(result.error);
      return;
    }
    const header = {};
    for (const [name, values] of result.headers) header[name] = values;
    const response = { status: result.status, statusCode: result.status, headers: headerObject(header) };
    const body = pending.binary ? b64ToBytes(result.body.b) : result.body.s;
    pending.callback(null, response, body);
  };

  global.$environment = {
    system: input.system,
    'surge-version': '5.10.0',
    'surge-build': '3000',
    language: 'en',
    'device-model': '',
  };
  global.$script = {
    name: input.name,
    type: input.kind,
    startTime: input.started,
    sessionID: input.session,
    binaryBodyMode: input.binary,
  };
  global.$done = finish;

  if (hasRequest) {
    const request = {
      url: input.request.url,
      method: input.request.method,
      headers: shownHeaders(requestHeaders),
      id: input.request.id,
    };
    if (input.request.scheme !== undefined) {
      request.scheme = input.request.scheme;
      request.path = input.request.path;
    }
    if (input.request.body !== undefined && !isResponse) request.body = bodyValue(input.request.body);
    global.$request = request;
  }
  if (isResponse && input.response) {
    const response = { status: input.response.status, statusCode: input.response.status, headers: shownHeaders(responseHeaders) };
    if (input.response.body !== undefined) response.body = bodyValue(input.response.body);
    if (responseTrailers !== undefined) response.trailers = headerObject(responseTrailers);
    global.$response = response;
  }
  if (input.cronexp) global.$cronexp = input.cronexp;
  if (input.event) global.$event = { name: input.event };
  if (input.trigger) global.$trigger = input.trigger;
  if (input.argument !== undefined && input.argument !== null) global.$argument = input.argument;
  if (input.rule) global.$request = input.rule;
  if (input.domain !== undefined) global.$domain = input.domain;
})(globalThis);

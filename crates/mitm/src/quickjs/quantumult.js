(function (global) {
  global.$task = {
    fetch(request) {
      return new Promise((resolve, reject) => {
        const options = typeof request === 'string' ? { url: request } : Object.assign({}, request);
        const opts = options.opts || {};
        if (opts.redirection === false) options['auto-redirect'] = false;
        if (opts['skip-cert-verify']) options.insecure = true;
        if (options.body === undefined && options.bodyBytes !== undefined) options.body = new Uint8Array(options.bodyBytes);
        const send = $httpClient[String(options.method || 'GET').toLowerCase()];
        if (!send) {
          reject({ error: 'unsupported method ' + options.method });
          return;
        }
        send(options, (error, response, body) => {
          if (error) reject({ error: String(error) });
          else resolve({ statusCode: response.status, headers: response.headers, body });
        });
      });
    },
  };
  global.$prefs = {
    valueForKey: (key) => {
      const value = $persistentStore.read(key);
      return value === null ? undefined : value;
    },
    setValueForKey: (value, key) => $persistentStore.write(value, key),
    removeValueForKey: (key) => $persistentStore.write(null, key),
    removeAllValues: () => false,
  };
  global.$notify = (title, subtitle, message, options) => $notification.post(title, subtitle, message, options);
})(globalThis);

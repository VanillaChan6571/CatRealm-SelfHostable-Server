'use strict';

// All untrusted outbound URLs must pass this policy at connection time. Keep
// the checked DNS answer pinned; a separate preflight lookup is not sufficient.
const dns = require('node:dns').promises;
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const ipaddr = require('ipaddr.js');

function isPublicAddress(address) {
  try {
    const parsed = ipaddr.parse(address);
    // IPv4-mapped IPv6, NAT64, Teredo and 6to4 are deliberately excluded too.
    return parsed.range() === 'unicast';
  } catch { return false; }
}

function parsePublicUrl(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Only public HTTP(S) URLs without credentials are allowed');
  }
  return url;
}

async function resolvePublicHost(hostname, lookup = dns.lookup) {
  const host = hostname.replace(/^\[|\]$/g, '');
  const records = net.isIP(host)
    ? [{ address: host, family: net.isIP(host) }]
    : await lookup(host, { all: true, verbatim: true });
  if (!records.length || !records.every(({ address }) => isPublicAddress(address))) {
    throw new Error('Blocked non-public host');
  }
  return records[0];
}

let activeRequests = 0;
const MAX_CONCURRENT_REQUESTS = 8;

async function publicRequest(value, options = {}) {
  if (activeRequests >= MAX_CONCURRENT_REQUESTS) throw new Error('Outbound request capacity reached');
  activeRequests += 1;
  let request;
  let timer;
  try {
    const url = parsePublicUrl(value);
    const timeout = Math.min(8000, options.timeout || 6000);
    const maxBytes = options.maxBytes || 256 * 1024;
    const operation = (async () => {
      const address = await resolvePublicHost(url.hostname);
      // DNS may finish after the overall deadline. Never open that connection.
      if (!timer) throw new Error('Outbound request timed out');
      return new Promise((resolve, reject) => {
        request = (url.protocol === 'https:' ? https : http).request(url, {
          method: options.method || 'GET',
          agent: false,
          headers: { 'Accept-Encoding': 'identity', ...options.headers },
          lookup: (_host, lookupOptions, callback) => {
            callback(null, lookupOptions?.all ? [address] : address.address, address.family);
          },
        }, (response) => {
          const chunks = [];
          let size = 0;
          response.on('error', reject);
          response.on('data', (chunk) => {
            size += chunk.length;
            if (size > maxBytes) {
              response.destroy(new Error('Outbound response exceeds size limit'));
              return;
            }
            chunks.push(chunk);
          });
          response.on('end', () => resolve({
            status: response.statusCode,
            url: url.href,
            headers: response.headers,
            data: Buffer.concat(chunks).toString('utf8'),
          }));
        });
        request.on('error', reject);
        request.end(options.body);
      });
    })();
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => {
        timer = null;
        request?.destroy(new Error('Outbound request timed out'));
        reject(new Error('Outbound request timed out'));
      }, timeout);
      timer.unref?.();
    })]);
  } finally {
    clearTimeout(timer);
    timer = null;
    activeRequests -= 1;
  }
}

async function publicGet(value, options = {}, depth = 0) {
  const response = await publicRequest(value, { ...options, maxBytes: options.maxContentLength || 2 * 1024 * 1024 });
  if (response.status >= 300 && response.status < 400 && options.maxRedirects !== 0) {
    if (depth >= 5 || !response.headers.location) throw new Error('Invalid or excessive redirect');
    return publicGet(new URL(response.headers.location, value).href, options, depth + 1);
  }
  if (options.validateStatus && !options.validateStatus(response.status)) throw new Error('Outbound HTTP status rejected');
  if (options.responseType === 'json') response.data = JSON.parse(response.data);
  return response;
}

module.exports = { isPublicAddress, parsePublicUrl, resolvePublicHost, publicRequest, publicGet };

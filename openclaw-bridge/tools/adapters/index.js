const { CurlAdapter } = require('./curl-adapter.js');
const { NslookupAdapter } = require('./nslookup-adapter.js');
const { WhoisAdapter } = require('./whois-adapter.js');

function registerBatch1Tools(toolRegistry) {
  if (!toolRegistry || typeof toolRegistry.register !== 'function') {
    throw new Error('toolRegistry is required');
  }

  toolRegistry.register('curl', new CurlAdapter());
  toolRegistry.register('nslookup', new NslookupAdapter());
  toolRegistry.register('whois', new WhoisAdapter());
}

module.exports = {
  registerBatch1Tools,
  CurlAdapter,
  NslookupAdapter,
  WhoisAdapter,
};

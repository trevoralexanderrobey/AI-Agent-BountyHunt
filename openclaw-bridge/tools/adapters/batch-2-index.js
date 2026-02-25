const { HashcatAdapter } = require('./hashcat-adapter.js');
const { SqlmapAdapter } = require('./sqlmap-adapter.js');
const { NiktoAdapter } = require('./nikto-adapter.js');

function registerBatch2Tools(toolRegistry) {
  if (!toolRegistry || typeof toolRegistry.register !== 'function') {
    throw new Error('toolRegistry is required');
  }

  toolRegistry.register('hashcat', new HashcatAdapter());
  toolRegistry.register('sqlmap', new SqlmapAdapter());
  toolRegistry.register('nikto', new NiktoAdapter());
}

module.exports = {
  registerBatch2Tools,
  HashcatAdapter,
  SqlmapAdapter,
  NiktoAdapter,
};

const { AircrackAdapter } = require('./aircrack-adapter.js');
const { MsfvenomAdapter } = require('./msfvenom-adapter.js');
const { FfufAdapter } = require('./ffuf-adapter.js');

function registerBatch3Tools(toolRegistry) {
  if (!toolRegistry || typeof toolRegistry.register !== 'function') {
    throw new Error('toolRegistry is required');
  }

  toolRegistry.register('aircrack', new AircrackAdapter());
  toolRegistry.register('msfvenom', new MsfvenomAdapter());
  toolRegistry.register('ffuf', new FfufAdapter());
}

module.exports = {
  registerBatch3Tools,
  AircrackAdapter,
  MsfvenomAdapter,
  FfufAdapter,
};

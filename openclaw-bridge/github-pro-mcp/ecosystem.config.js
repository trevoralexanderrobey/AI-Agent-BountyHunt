module.exports = {
  apps: [
    {
      name: 'openclaw-mcp',
      cwd: __dirname,
      script: 'dist/server.js',
      exec_mode: 'fork',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      env: {
        // Defaults; runtime env will override when the start script exports .env
        OPENCLAW_TRANSPORT: 'http',
        OPENCLAW_GATEWAY_BASE_URL: 'http://localhost:11434/v1',
        OPENCLAW_DEFAULT_MODEL: 'qwen2.5-coder:7b',
        OPENCLAW_BRIDGE_BASE_URL: 'http://127.0.0.1:8787',
        BIONICLINK_BASE_URL: 'https://127.0.0.1:8090',
        OPENCODE_SERVER_BASE_URL: 'http://127.0.0.1:8090',
        OPENCODE_DAEMON_BASE_URL: 'http://127.0.0.1:8091',
        OPENCODE_DAEMON_PORT: '8091',
        OPENCODE_SERVER_PORT: '8090',
        OPENCODE_MAX_ACTIVE_SESSIONS: '2',
        OPENCODE_QUEUE_MAX: '8'
      }
    },
    {
      name: 'openclaw-opencode-daemon',
      cwd: `${__dirname}/../skills/opencode-daemon`,
      script: 'server.js',
      exec_mode: 'fork',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1024M',
      env: {
        OPENCODE_DAEMON_PORT: '8091',
        OPENCODE_DAEMON_HOST: '127.0.0.1',
        OPENCODE_SERVER_PORT: '8090',
        OPENCODE_SERVER_HOST: '127.0.0.1',
        OPENCODE_SERVER_BASE_URL: 'http://127.0.0.1:8090',
        OPENCODE_DAEMON_BASE_URL: 'http://127.0.0.1:8091',
        OPENCODE_DEFAULT_MODEL: 'ollama/qwen2.5-coder:7b',
        OPENCODE_MAX_ACTIVE_SESSIONS: '2',
        OPENCODE_QUEUE_MAX: '8'
      }
    }
  ]
};

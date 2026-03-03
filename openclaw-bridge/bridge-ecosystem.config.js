module.exports = {
  apps: [
    {
      name: "openclaw-bridge",
      script: "dist/bridge/server.js",
      cwd: __dirname,
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      watch: false,
      time: true,
      merge_logs: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      out_file: ".bridge/logs/bridge-out.log",
      error_file: ".bridge/logs/bridge-error.log",
      min_uptime: "10s",
      max_restarts: 20,
      exp_backoff_restart_delay: 200,
      kill_timeout: 5000,
      max_memory_restart: "512M",
      env: {
        NODE_ENV: "development"
      }
    }
  ]
};

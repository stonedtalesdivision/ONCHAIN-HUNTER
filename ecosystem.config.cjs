module.exports = {
  apps: [{
    name: "onchain-hunter",
    script: "dist/autonomous.js",
    cwd: "/root/ONCHAIN-HUNTER",
    interpreter: "node",
    autorestart: true,
    restart_delay: 5000,
    exp_backoff_restart_delay: 100,
    max_restarts: 50,
    max_memory_restart: "500M",
    time: true,
    env: { NODE_ENV: "production" }
  }]
};

module.exports = {
  apps: [
    {
      name: "veriff-backend",
      script: "./dist/server.js",
      interpreter: "bun",
      watch: false,
    },
  ],
};

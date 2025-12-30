module.exports = {
  apps: [
    {
      name: "[NODE:3000] peacekeeper",
      script: "_dist/server.js",
      interpreter: "npm",
      interpreterArgs: "start",
    },
  ],
};

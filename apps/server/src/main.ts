import { buildServer } from "./server.js";

const server = await buildServer({});

await server.listen({ port: server.envs.PORT, host: server.envs.HOST });

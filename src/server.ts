import "dotenv/config";
import app from "./app";
import http, { Server } from "node:http";
import { connectToDB } from "./config/db";
import mongoose from "mongoose";

let server: Server;
async function startServer() {
  server = http.createServer(app);

  await connectToDB();

  server.listen(process.env.PORT || 3000, () => {
    console.log(`Server listening on port: ${process.env.PORT}`);
  });
}

startServer().catch((err) => {
  console.error(`Error while starting the server ${err}`);
  process.exit(1);
});

// Graceful shutdown
const shutdown = async (signal: string) => {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  server.close(async () => {
    await mongoose.connection.close();
    console.log("HTTP server and MongoDB connections closed.");
    process.exit(0);
  });
};
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

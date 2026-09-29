import mongoose from "mongoose";
import dns from "node:dns";
// 1. Expose Node's native crypto module globally for Jest sandbox environment
// if (!globalThis.crypto) {
//   globalThis.crypto = crypto;
// }
// Configure DNS for both the server and test environments
// dns.setDefaultResultOrder("ipv4first");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

export async function connectToDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI!);
    console.log("Mongo connection is successfully established");
  } catch (error) {
    console.error(`MongoDB connection error`, error);
    process.exit(1);
  }
}

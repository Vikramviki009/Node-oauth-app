import { toFile } from "qrcode";
const otpAuthURL = process.argv[2];

if (!otpAuthURL) {
  throw new Error("Pass otpAuthURL as an arguement");
}

export async function main() {
  await toFile("totp.png", otpAuthURL);
  console.log("Saved QR Code");
}

main().catch((err) => {
  console.log(err, "Error");
  process.exit(1);
});

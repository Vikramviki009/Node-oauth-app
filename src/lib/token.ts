import jwt from "jsonwebtoken";

export function createAccessToken(
  id: string,
  role: "user" | "admin",
  tokenVersion: number,
) {
  const payload = {
    sub: id,
    role,
    tokenVersion,
  };
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: "30m",
  });
}

export function createRefreshToken(id: string, tokenVersion: number) {
  const payload = {
    sub: id,
    tokenVersion,
  };
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET!, {
    expiresIn: "7d",
  });
}

export function verifyRefreshToken(token: string) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
    sub: string;
    tokenVersion: number;
  };
}

export function verifyAccessToken(token: string) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    role: string;
    tokenVersion: number;
  };
}

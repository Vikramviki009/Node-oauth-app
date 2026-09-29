export const isProd = process.env.NODE_ENV === "production";

export const baseCookieOptions = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: isProd,
  path: "/",
};

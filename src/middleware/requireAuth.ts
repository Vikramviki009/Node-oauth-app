import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.model";
import { TokenExpiredError } from "jsonwebtoken";

export default async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      code: "UNAUTHORIZED",
      message: "Authorization token missing or malformed",
    });
  }
  let payload: ReturnType<typeof verifyAccessToken>;
  try {
    payload = verifyAccessToken(authHeader.split(" ")[1]);
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      return res.status(401).json({
        code: "TOKEN_EXPIRED",
        message: "Access token is expired",
      });
    }

    return res.status(401).json({
      code: "INVALID_TOKEN",
      message: "Invalid access token",
    });
  }

  try {
    const user = await User.findById(payload.sub)
      .select(
        "name email role isEmailVerified googleId twoFactorEnabled tokenVersion",
      )
      .lean();
    if (!user) {
      return res.status(401).json({
        code: "USER_NOT_FOUND",
        message: "User not found",
      });
    }
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        code: "TOKEN_INVALIDATED",
        message: "Session token has been invalidated, please login again",
      });
    }
    req.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role,
      googleId: user?.googleId,
      tokenVersion: user.tokenVersion,
      isEmailVerified: user.isEmailVerified,
      twoFactorEnabled: user.twoFactorEnabled,
    };
    next();
  } catch (error) {
    next(error);
  }
}

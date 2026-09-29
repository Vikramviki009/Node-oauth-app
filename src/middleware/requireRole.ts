import { NextFunction, Request, Response } from "express";

export function requireRole(...allowedRoles: Array<"user" | "admin">) {
  return function (req: Request, res: Response, next: NextFunction) {
    if (!req.user) {
      return res.status(401).json({
        code: "NOT_AUTHENTICATED",
        message: "User not authenticated, Please login",
      });
    }
    if (!allowedRoles.includes(req?.user.role)) {
      return res.status(403).json({
        code: "NOT_AUTHORIZED",
        message: "You do not have permission to access this route",
      });
    }

    next();
  };
}

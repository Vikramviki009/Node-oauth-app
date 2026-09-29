import { Request, Response } from "express";
import { User } from "../../models/user.model";

export async function fetchUsershandler(req: Request, res: Response) {
  try {
    const users = await User.find(
      {},
      { id: 1, email: 1, role: 1, name: 1, isEmailVerified: 1, createdAt: 1 },
    ).sort({
      createdAt: -1,
    });
    return res.status(200).json({
      users,
    });
  } catch (error) {
    return res.status(500).json({
      message: "Internal Server error",
    });
  }
}

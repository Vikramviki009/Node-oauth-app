import { Request, Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";

const userRouter = Router();

userRouter.get("/me", requireAuth, (req: Request, res: Response) => {
  const authUser = req.user;

  return res.json({
    user: authUser,
  });
});

export default userRouter;

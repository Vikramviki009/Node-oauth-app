import { Router } from "express";
import requireAuth from "../middleware/requireAuth";
import { requireRole } from "../middleware/requireRole";
import { fetchUsershandler } from "../controllers/user/user.controllers";

const adminRouter = Router();

adminRouter.get("/users", requireAuth, requireRole("admin"), fetchUsershandler);

export default adminRouter;

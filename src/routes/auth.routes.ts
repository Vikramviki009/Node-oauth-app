import { Router } from "express";
import {
  forgotPasswordHandler,
  googleOAuthCallbackHandler,
  googleOAuthStartHandler,
  loginHandler,
  logoutHandler,
  refreshTokenHandler,
  registerHandler,
  resendVerifyEmailHandler,
  resetPasswordHandler,
  twoFASetupHandler,
  twoFAVerifyHandler,
  twoFADisableHandler,
  verifyEmailHandler,
} from "../controllers/auth/auth.controllers";
import requireAuth from "../middleware/requireAuth";

const authRouter = Router();

authRouter.post("/register", registerHandler);
authRouter.post("/login", loginHandler);
authRouter.get("/verify-email", verifyEmailHandler);
authRouter.post("/resend-verification-link", resendVerifyEmailHandler);
authRouter.post("/refresh", refreshTokenHandler);
authRouter.post("/logout", requireAuth, logoutHandler);
authRouter.post("/forgot-password", forgotPasswordHandler);
authRouter.post("/reset-password", resetPasswordHandler);
authRouter.get("/google", googleOAuthStartHandler);
authRouter.get("/google/callback", googleOAuthCallbackHandler);
authRouter.post("/2FA/setup", requireAuth, twoFASetupHandler);
authRouter.post("/2FA/verify", requireAuth, twoFAVerifyHandler);
authRouter.post("/2FA/disable", requireAuth, twoFADisableHandler);
export default authRouter;

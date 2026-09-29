import { Request, Response } from "express";
import { loginSchema, registerSchema, twoFAVerifySchema } from "./auth.schema";
import z from "zod";
import { User } from "../../models/user.model.js";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt, { TokenExpiredError } from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import { baseCookieOptions } from "../../lib/cookie";
import crypto from "node:crypto";
import { OAuth2Client } from "google-auth-library";
import { generateSecret, generateURI, verify } from "otplib";
import QRCode from "qrcode";

const config = {
  google_client_id: process.env.GOOGLE_CLIENT_ID,
  google_client_secret: process.env.GOOGLE_CLIENT_SECRET,
  google_redirect_uri: process.env.GOOGLE_REDIRECT_URI,
};
function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

export function getGoogleClient() {
  if (!config.google_client_id || !config.google_client_secret) {
    throw new Error("Missing google client id and client secret");
  }
  return new OAuth2Client({
    client_id: config.google_client_id,
    client_secret: config.google_client_secret,
    redirectUri: config.google_redirect_uri,
  });
}
export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data",
        error: z.treeifyError(result.error),
      });
    }
    const { email, password, name } = result.data;
    const normalisedEmail = email.trim().toLowerCase();
    const user = await User.findOne({
      email: normalisedEmail,
    });
    if (user) {
      return res.status(409).json({
        message: "Email already exists. Please use a different one",
      });
    }

    const passwordhash = await hashPassword(password);
    const newlyCreatedUser = await User.create({
      email: normalisedEmail,
      name,
      passwordhash,
    });

    const verifyToken = jwt.sign(
      {
        sub: newlyCreatedUser.id,
        type: "email_verification",
      },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn: "1d",
      },
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newlyCreatedUser.email,
      "Verify your Email!",
      `<p>Please verify your email by clicking the link below</p>
        <p><a href="${verifyUrl}">Click to verify</a></p>
        `,
    );
    return res.status(201).json({
      message: "User registered Successfully",
      user: {
        id: newlyCreatedUser.id,
        name: newlyCreatedUser.name,
        email: newlyCreatedUser.email,
        role: newlyCreatedUser.role,
        isEmailVerified: newlyCreatedUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server error",
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string;
  if (!token) {
    return res.status(400).json({
      message: "Missing verification token in the URL",
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
      type: string;
    };
    if (payload.type !== "email_verification") {
      return res.status(400).json({
        message: "Invalid token type",
      });
    }
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }
    if (user.isEmailVerified) {
      return res.json({
        message: "Email already verified. Please login",
      });
    }
    user.isEmailVerified = true;
    await user.save();

    return res.status(200).json({
      message: "User successfully Verified",
    });
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(400).json({
        message: "Verification link expired. Please request a new one",
      });
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(400).json({
        message: "Invalid verifcation link",
      });
    }
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function resendVerifyEmailHandler(req: Request, res: Response) {
  try {
    const result = z
      .object({
        email: z.email(),
      })
      .safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data",
        error: z.treeifyError(result.error),
      });
    }
    const { email } = result.data;
    const user = await User.findOne({
      email,
    });
    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }
    if (user.isEmailVerified) {
      return res.json({
        message: "Email is already verified. Please continue to login",
      });
    }
    const verifyToken = jwt.sign(
      {
        sub: user.id,
        type: "email_verification",
      },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn: "1d",
      },
    );
    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;
    await sendEmail(
      user.email,
      "Verify your email: ",
      `<p>Please verify your email by clicking the link below</p>
        <p><a href="${verifyUrl}">Click to verify</a></p>
        `,
    );
    res.status(200).json({
      message: "Verification email resent",
    });
  } catch (error) {
    res.status(500).json({
      message: "Internal Server error",
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data",
        error: z.treeifyError(result.error),
      });
    }
    const { email, password, twoFactorCode } = result.data;
    const normalisedEmail = email.trim().toLowerCase();
    const user = await User.findOne({
      email: normalisedEmail,
    });
    if (!user) {
      return res.status(401).json({
        message: "Invalid email and password",
      });
    }
    if (!user.passwordhash) {
      return res.status(400).json({
        message:
          "This account was created using Google login. Please sign in with Google or reset your password.",
      });
    }
    const ok = await checkPassword(password, user.passwordhash);
    if (!ok) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }
    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Please verify your email before logging in",
      });
    }

    if (user.twoFactorEnabled) {
      if (!user.twoFactorSecret) {
        return res.status(500).json({
          message:
            "Two factor authentication is misconfigured for this account",
        });
      }

      if (!twoFactorCode) {
        return res.status(403).json({
          message: "Two factor code is required",
          twoFactorRequired: true,
        });
      }

      const twoFactorResult = twoFAVerifySchema.safeParse({
        code: twoFactorCode,
      });

      if (!twoFactorResult.success) {
        return res.status(400).json({
          message: "Invalid two factor code",
          errors: z.treeifyError(twoFactorResult.error),
        });
      }

      const { code: validTwoFactorCode } = twoFactorResult.data;

      // Verify Two FA with otplib
      const { valid } = await verify({
        token: validTwoFactorCode,
        secret: user.twoFactorSecret,
      });

      if (!valid) {
        return res.status(401).json({
          message: "Invalid two factor code",
        });
      }
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    res.cookie("refreshToken", refreshToken, {
      ...baseCookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "User logged in Successfully!",
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server error",
    });
  }
}

export async function refreshTokenHandler(req: Request, res: Response) {
  try {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) {
      res.clearCookie("refreshToken", baseCookieOptions);
      return res.status(401).json({
        code: "REFRESH_TOKEN_MISSING",
        message: "Missing refresh token",
      });
    }
    let payload: ReturnType<typeof verifyRefreshToken>;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (refreshTokenError) {
      res.clearCookie("refreshToken", baseCookieOptions);
      if (refreshTokenError instanceof TokenExpiredError) {
        return res.status(401).json({
          code: "REFRESH_TOKEN_EXPIRED",
          message: "Refresh token expired",
        });
      }
      return res.status(401).json({
        code: "REFRESH_TOKEN_INVALID",
        message: "Refresh token invalid",
      });
    }
    const user = await User.findById(payload.sub);
    if (!user) {
      res.clearCookie("refreshToken", baseCookieOptions);

      return res.status(401).json({
        code: "USER_NOT_FOUND",
        message: "User not found",
      });
    }
    if (user.tokenVersion !== payload.tokenVersion) {
      res.clearCookie("refreshToken", baseCookieOptions);
      return res.status(401).json({
        code: "REFRESH_TOKEN_INVALIDATED",
        message: "Refresh token invalidated",
      });
    }

    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );
    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);
    res.cookie("refreshToken", newRefreshToken, {
      ...baseCookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.json({
      message: "User tokens refreshed",
      accessToken: newAccessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log("Refresh token error", error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  res.clearCookie("refreshToken", baseCookieOptions);
  const userAuth = req.user;

  const user = await User.findById(userAuth?.id);
  if (!user) {
    return res.status(404).json({
      message: "User not found",
    });
  }
  user.tokenVersion = user.tokenVersion + 1;
  await user.save();
  return res.status(200).json({
    message: "User logged out",
  });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  const emailBody = req.body as { email: string };

  const result = z
    .object({
      email: z.email(),
    })
    .safeParse(emailBody);

  if (!result.success) {
    return res.status(400).json({
      message: "Please provide a valid email id",
      errors: z.treeifyError(result.error),
    });
  }
  const { email } = result.data;
  const normalisedEmail = email.trim().toLowerCase();
  try {
    const user = await User.findOne({
      email: normalisedEmail,
    });
    if (!user) {
      return res.json({
        message:
          "If the provided email is registered with us. We will send you a reset password link. Thank you",
      });
    }
    const rawToken = crypto.randomBytes(32).toString("hex");
    const resetPasswordHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = resetPasswordHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 mins expiry for the reset password link

    await user.save();

    const resetPasswordLink = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      "Reset Password link",
      `
        <p>To reset your password, please click the link below</p>
        <p><a href="${resetPasswordLink}">Click here</a></p>
        `,
    );

    return res.json({
      message:
        "If the provided email is registered with us. We will send you a reset password link. Thank you!",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const results = z
    .object({
      token: z.string().min(1, "Reset password token is missing "),
      resetPassword: z
        .string()
        .min(6, "Password should be minimum of 6 characters"),
    })
    .safeParse({
      token: req.query.token || req.body.token,
      resetPassword: req.body.password,
    });
  if (!results.success) {
    return res.status(400).json({
      message: "Invalid Token or Reset Password",
      error: z.treeifyError(results.error),
    });
  }
  const { resetPassword, token } = results.data;
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  try {
    const user = await User.findOne({
      resetPasswordToken: resetPasswordToken,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid of expired reset password token",
      });
    }
    const passwordHash = await hashPassword(resetPassword);
    user.passwordhash = passwordHash;
    user.resetPasswordExpires = undefined;
    user.resetPasswordToken = undefined;
    user.tokenVersion = user.tokenVersion + 1;
    await user.save();

    res.clearCookie("refreshToken", baseCookieOptions);

    return res.status(200).json({
      message:
        "Password reset successful. Please try logging in with new password",
    });
  } catch (error) {
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function googleOAuthStartHandler(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();
    const state = crypto.randomBytes(10).toString("hex");

    res.cookie("oauth_state", state, {
      ...baseCookieOptions,
      maxAge: 10 * 60 * 1000,
    });

    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
      state,
    });

    res.redirect(url);
  } catch (error) {
    console.log("Google sign method start error", error);
    return res.status(500).json({
      message: "Internal server Error",
    });
  }
}

export async function googleOAuthCallbackHandler(req: Request, res: Response) {
  const { code, state, error } = req.query as Record<
    string,
    string | undefined
  >;
  // Case 1: Google reports an authorization error or user denies the consent
  if (error) {
    return res.status(400).json({
      message: `Google reports an authorization error or failure: ${error}`,
    });
  }

  // Case 2: Validate CSRF state
  const savedState = req.cookies?.oauth_state;
  res.clearCookie("oauth_state", baseCookieOptions);

  if (!state || !savedState || state !== savedState) {
    return res.status(403).json({
      message: "Invalid or Expired OAuth State parameter(Potential CSRF)",
    });
  }

  // Case 3: Missing Authorization Code
  if (!code) {
    return res.status(400).json({
      message: "Missing Google's Authorization code",
    });
  }

  try {
    const client = getGoogleClient();
    const { tokens } = await client.getToken(code);

    if (!tokens.id_token) {
      return res.status(400).json({
        message: "Missing Google's id_token",
      });
    }

    // verify id_token and extract user info
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: config.google_client_id,
    });

    const payload = ticket.getPayload();
    const googleId = payload?.sub;
    const email = payload?.email?.trim().toLowerCase();
    const isEmailVerified = payload?.email_verified;

    if (!googleId || !email || !isEmailVerified) {
      return res.status(400).json({
        message:
          "Google's email id is not verified or missing google account info",
      });
    }

    // User resolutions
    // Case A: user already registered with googleId
    let user = await User.findOne({
      googleId,
    });

    if (!user) {
      // Case B: User already registered with email/password: Sync email verified, googleId and user.name
      user = await User.findOne({
        email,
      });

      if (user) {
        // Existing user: update googleId, user name and isEmailVerified if updated
        if (!user.isEmailVerified) user.isEmailVerified = true;
        if (!user.name && payload?.name) user.name = payload?.name;
        user.googleId = googleId;
        await user.save();
      } else {
        // Case C: Brand New user: Create the user
        user = await User.create({
          googleId,
          email,
          isEmailVerified,
          name: payload?.name,
        });
      }
    } else {
      // Existing Google User: Sync email verified and user name if updated
      let isModified = false;
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        isModified = true;
      }
      if (!user.name && payload?.name) {
        user.name = payload?.name;
        isModified = true;
      }
      if (isModified) {
        await user.save();
      }
    }

    // Issue access and refresh tokens irrespective of type of user
    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion,
    );
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    res.cookie("refreshToken", refreshToken, {
      ...baseCookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      message: "Google login successful",
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        googleId,
      },
    });
  } catch (error) {
    console.log(`Error from Google authorization callback handler ${error}`);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function twoFASetupHandler(req: Request, res: Response) {
  const authUser = req.user;

  try {
    const user = await User.findById(authUser?.id);
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.twoFactorEnabled) {
      return res.status(400).json({
        message:
          "Two-factor authentication is already enabled for this account. Please disable it first to reconfigure",
      });
    }

    const secret = generateSecret();
    const issuer = "nodeOAuthAdvancedApp";
    const oAuthUrl = generateURI({
      secret,
      issuer,
      label: user.email,
    });

    const qrCode = await QRCode.toDataURL(oAuthUrl);

    user.twoFactorSecret = secret;
    user.twoFactorEnabled = false;
    await user.save();

    return res.status(200).json({
      message: "2FA setup initiated successfully",
      secret,
      qrCode,
      oAuthUrl,
    });
  } catch (error) {
    console.log(`Error while setting up twoFA ${error}`);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function twoFAVerifyHandler(req: Request, res: Response) {
  const authUser = req.user;

  try {
    const user = await User.findById(authUser!.id);
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.twoFactorEnabled) {
      return res.status(400).json({
        message:
          "Two-factor authentication is enabled for this account. Please disable it first to reconfigure",
      });
    }

    if (!user.twoFactorSecret) {
      return res.status(400).json({
        message:
          "Two-factor authentication has not been initiated for this account yet. Please run the set up first",
      });
    }

    const twoFAResult = twoFAVerifySchema.safeParse(req.body);
    if (!twoFAResult.success) {
      return res.status(400).json({
        message: "Invalid two-factor authentication code",
        errors: z.treeifyError(twoFAResult.error),
      });
    }
    const { code } = twoFAResult.data;
    const { valid } = await verify({
      token: code,
      secret: user.twoFactorSecret,
    });
    if (!valid) {
      return res.status(400).json({
        message: "Invalid two-factor authentication code",
      });
    }
    user.twoFactorEnabled = true;
    await user.save();

    return res.status(200).json({
      message: "Two-factor authentication is enabled successfully",
      twoFactorEnabled: true,
    });
  } catch (error) {
    console.log(`Error in two-factor authentication verify handler ${error}`);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

export async function twoFADisableHandler(req: Request, res: Response) {
  const authUser = req.user;

  if (!authUser) {
    return res.status(401).json({
      message: "You are not authenticated",
    });
  }

  try {
    const user = await User.findById(authUser.id);
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({
        message:
          "Two-factor authentication is not currently enabled for this account",
      });
    }

    const result = twoFAVerifySchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid two-factor code",
        errors: z.treeifyError(result.error),
      });
    }

    const { code } = result.data;

    const { valid } = await verify({
      token: code,
      secret: user.twoFactorSecret,
    });

    if (!valid) {
      return res.status(400).json({
        message: "Invalid two-factor authentication code",
      });
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save();

    return res.status(200).json({
      message: "Two-factor authentication disabled successfully",
      twoFactorEnabled: false,
    });
  } catch (error) {
    console.log(`Error while disabling Two FA ${error}`);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
}

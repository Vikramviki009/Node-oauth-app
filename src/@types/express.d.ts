export interface AuthUser {
  id: string;
  name?: string | null;
  email: string;
  role: "user" | "admin";
  googleId: string | null | undefined;
  tokenVersion: number;
  isEmailVerified: boolean;
  twoFactorEnabled: boolean;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

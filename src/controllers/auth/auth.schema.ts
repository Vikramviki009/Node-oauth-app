import z from "zod";

export const registerSchema = z.object({
  email: z.email(),
  password: z.string().min(6),
  name: z.string().min(3),
});

export const loginSchema = z.object({
  email: z.email(),
  password: z.string().min(6),
  twoFactorCode: z.string().optional(),
});

export const twoFAVerifySchema = z.object({
  code: z
    .string()
    .trim()
    .length(6, "Two-factor code must be 6 digits")
    .regex(/^\d{6}$/, "Two-factor code must contain only numbers"),
});

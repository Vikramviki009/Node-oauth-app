import nodemailer from "nodemailer";

export async function sendEmail(to: string, sub: string, html: string) {
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS
  ) {
    console.log("Email env's are not available");
    return;
  }
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT) || 587;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const email_from = process.env.EMAIL_FROM;

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: {
      user,
      pass,
    },
  });

  try {
    await transporter.sendMail({
      from: `Node Auth <${email_from}>`,
      to,
      subject: sub,
      html,
    });
  } catch (error) {
    console.log(`Error sending mail`, error);
  }
}

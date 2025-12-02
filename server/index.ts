import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { PrismaClient } from "./generated/prisma/client";

// @ts-expect-error PrismaClient constructor is callable without explicit options per generated docs
const prisma = new PrismaClient();
dotenv.config();
const app = express();

const JWT_SECRET = process.env.JWT_SECRET || "secret";

//sign up route
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { email, password: hashedPassword },
  });
  res.json(user);
});


//login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { email },
  });
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = jwt.sign({ userId: user.id }, JWT_SECRET);
  res.json({ token });
});

//protected route
app.get("/protected", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const decoded = jwt.verify(token, JWT_SECRET);

  // Ensure decoded token is an object with a userId field
  if (typeof decoded !== "object" || decoded === null || !("userId" in decoded)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = (decoded as jwt.JwtPayload & { userId: number }).userId;

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });
  if (!user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  res.json({ message: "Protected route accessed successfully" });
});


app.listen(3000, () => {
  console.log(`Server is running on port 3000`);
});

export default app;
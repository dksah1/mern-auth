const express = require("express");
const authController = require("../controllers/authController");

const authRouter = express.Router();

authRouter.post("/signup", authController.signup);
authRouter.post("/signin", authController.signin);
authRouter.post("/logout", authController.signout);
authRouter.patch("/sendcode", authController.sendVerificationCode);

module.exports = authRouter;

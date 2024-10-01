const express = require("express");
const authController = require("../controllers/authController");
const { identifier } = require("../middleware/identification");

const authRouter = express.Router();

authRouter.post("/signup", authController.signup);
authRouter.post("/signin", authController.signin);
authRouter.post("/logout", identifier, authController.signout);
authRouter.patch("/sendcode", identifier, authController.sendVerificationCode);
authRouter.patch("/verify", identifier, authController.verifyVerificationCode);
authRouter.patch("/changepassword", identifier, authController.changePassword);

module.exports = authRouter;

const express = require("express");
const authController = require("../controllers/authController");

const authRouter = express.Router();

authRouter.get("/signup", authController.signup);

module.exports = authRouter;

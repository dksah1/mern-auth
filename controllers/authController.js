const { signupSchema, signinSchema } = require("../middleware/validator");
const User = require("../models/user.model");
const { doHash, doHashValidation } = require("../utils/hashing");
const jwt = require("jsonwebtoken");

exports.signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { error, value } = signupSchema.validate({ email, password });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(401).json({
        success: false,
        message: "Email already exists",
      });
    }

    // Now this will work as intended with async/await
    const hashedPassword = await doHash(password, 12);

    const newUser = new User({
      email,
      password: hashedPassword,
    });

    const result = await newUser.save();
    result.password = undefined;

    res.status(201).json({
      success: true,
      message: "Account created successfully",
      result,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

exports.signin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { error, value } = signinSchema.validate({ email, password });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }
    const existingUser = await User.findOne({ email }).select("+password");
    if (!existingUser) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }
    const result = await doHashValidation(password, existingUser.password);
    if (!result) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }
    const token = jwt.sign(
      {
        userId: existingUser._id,
        email: existingUser.email,
        verified: existingUser.verified,
      },
      process.env.JWT_SECRET
    );

    res
      .cookie("Authorization", "Bearer", +token, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV === "production",
      })
      .json({
        success: true,
        token,
        message: "Logged in successfully",
      });
  } catch (error) {
    console.log(error);
  }
};

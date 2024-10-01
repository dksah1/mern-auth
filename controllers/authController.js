const transport = require("../middleware/sendMail");
const {
  signupSchema,
  signinSchema,
  acceptCodeSchema,
  changePasswordSchema,
} = require("../middleware/validator");
const User = require("../models/user.model");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashing");
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
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
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
exports.signout = async (req, res) => {
  res.clearCookie("Authorization").status(200).json({
    success: true,
    message: "Logged out successfully",
  });
};
exports.sendVerificationCode = async (req, res) => {
  const { email } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }
    if (existingUser.verified) {
      return res.status(400).json({
        success: false,
        message: "You are already verified",
      });
    }
    const codeValue = Math.floor(Math.random() * 1000000).toString();
    let info = await transport.sendMail({
      from: process.env.NODE_EMAIL,
      to: existingUser.email,
      subject: "Verify your email",
      html: "<h1>" + codeValue + "</h1>",
    });
    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET
      );
      existingUser.verificationCode = hashedCodeValue;
      existingUser.verificationCodeValidation = Date.now();
      await existingUser.save();
      return res.status(200).json({
        success: true,
        message: "Verification code sent successfully",
      });
    }
    res.status(400).json({
      success: false,
      message: "Verification code sent failed",
    });
  } catch (error) {
    console.log(error);
  }
};
exports.verifyVerificationCode = async (req, res) => {
  const { email, providedCode } = req.body;
  try {
    // Validate email and code
    const { error, value } = acceptCodeSchema.validate({ email, providedCode });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }

    const codeValue = providedCode.toString(); // Ensure providedCode is a string
    const existingUser = await User.findOne({ email }).select(
      "+verificationCode +verificationCodeValidation"
    );

    // Check if user exists
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Check if user is already verified
    if (existingUser.verified) {
      return res.status(400).json({
        success: false,
        message: "You are already verified",
      });
    }

    // Check if verification code and validation time exist
    if (
      !existingUser.verificationCode ||
      !existingUser.verificationCodeValidation
    ) {
      //   console.log("Verification Code or Validation missing");
      return res.status(400).json({
        success: false,
        message: "Something is wrong with the code!",
      });
    }

    // Check if the verification code has expired (5 minutes validity)
    const currentTime = Date.now();
    const codeExpiryTime = existingUser.verificationCodeValidation.getTime(); // Use getTime() for comparison
    // console.log(
    //   "Code validation timestamp:",
    //   codeExpiryTime,
    //   "Current timestamp:",
    //   currentTime
    // );

    if (currentTime - codeExpiryTime > 5 * 60 * 1000) {
      return res.status(400).json({
        success: false,
        message: "Code has expired",
      });
    }

    // Hash the provided code for comparison
    const hashedCodeValue = hmacProcess(
      codeValue,
      process.env.HMAC_VERIFICATION_CODE_SECRET
    );
    // console.log("Provided Code:", codeValue);
    // console.log("Hashed Code:", hashedCodeValue);
    // console.log("Stored Verification Code:", existingUser.verificationCode);

    // Compare the hashed code with the stored verification code
    if (hashedCodeValue === existingUser.verificationCode) {
      // Mark user as verified and clear verification data
      existingUser.verified = true;
      existingUser.verificationCode = undefined;
      existingUser.verificationCodeValidation = undefined;
      await existingUser.save();
      return res.status(200).json({
        success: true,
        message: "Your account has been verified",
      });
    }

    // If code does not match, return error
    return res.status(400).json({
      success: false,
      message: "Invalid verification code",
    });
  } catch (error) {
    console.log("Error during verification:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

exports.changePassword = async (req, res) => {
  const { userId, verified } = req.user;
  const { oldPassword, newPassword } = req.body;

  try {
    const { error, value } = changePasswordSchema.validate({
      oldPassword,
      newPassword,
    });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }
    if (!verified) {
      return res.status(401).json({
        success: false,
        message: "you are not verified",
      });
    }
    const existingUser = await User.findOne({ _id: userId }).select(
      "+password"
    );
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }
    const result = await doHashValidation(oldPassword, existingUser.password);
    if (!result) {
      return res.status(401).json({
        success: false,
        message: "Invalid Credentials",
      });
    }
    const hashedPassword = await doHash(newPassword, 12);
    existingUser.password = hashedPassword;
    await existingUser.save();
    return res.status(200).json({
      success: true,
      message: "Password updated succcessfully",
    });
  } catch (error) {
    console.log(error);
  }
};

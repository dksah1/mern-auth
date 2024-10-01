const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "email is required"],
      trim: true,
      unique: [true, "Email must be unique"],
      minLength: [5, "email must have at least 5 character"],
      lowercase: true,
    },
    password: {
      type: String,
      required: [true, "password is required"],
      trim: true,
      select: false,
    },
    verified: {
      type: Boolean,
      default: false,
    },
    verificationCode: {
      type: String,
      select: false,
    },

    verificationCodeValidation: {
      type: Date,
      select: false,
    },

    forgotPasswordCode: {
      type: Number,
      select: false,
    },
    forgotPasswordCodeValidation: {
      type: Number,
      select: false,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("User", userSchema);

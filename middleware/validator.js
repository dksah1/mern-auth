const Joi = require("joi");

exports.signupSchema = Joi.object({
  email: Joi.string()
    .min(6)
    .max(60)
    .required()
    .email({
      tlds: { allow: ["com", "net", "in", "org"] },
    }),
  password: Joi.string()
    .required()
    .pattern(
      new RegExp(
        "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$"
      )
    ), // Corrected pattern
});

exports.signinSchema = Joi.object({
  email: Joi.string()
    .min(6)
    .max(60)
    .required()
    .email({
      tlds: { allow: ["com", "net", "in", "org"] },
    }),
  password: Joi.string()
    .required()
    .pattern(
      new RegExp(
        "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$"
      )
    ), // Corrected pattern
});

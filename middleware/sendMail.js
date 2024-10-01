const nodeMailer = require("nodeMailer");

const transport = new nodeMailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.NODE_EMAIL,
    pass: process.env.NODE_EMAIL_PASSWORD,
  },
});

module.exports = transport;

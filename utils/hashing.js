const { hash, compare } = require("bcryptjs");

exports.doHash = async (value, saltValue) => {
  const result = await hash(value, saltValue); // Use await for async hash function
  return result;
};

exports.doHashValidation = async (value, hashedValue) => {
  const result = await compare(value, hashedValue);
  return result;
};

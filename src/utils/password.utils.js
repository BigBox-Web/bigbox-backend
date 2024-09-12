const generateRandomPassword = (length = 12) => {
  const lowercase = "abcdefghijklmnopqrstuvwxyz";
  const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const specialChars = "!@#$%^&*";

  const allChars = lowercase + uppercase + digits + specialChars;

  const getRandomChar = (str) => str[Math.floor(Math.random() * str.length)];

  const passwordArray = [getRandomChar(lowercase), getRandomChar(uppercase), getRandomChar(digits), getRandomChar(specialChars)];

  for (let i = 4; i < length; i++) {
    passwordArray.push(getRandomChar(allChars));
  }

  return passwordArray.sort(() => Math.random() - 0.5).join("");
};

module.exports = {
  generateRandomPassword,
};

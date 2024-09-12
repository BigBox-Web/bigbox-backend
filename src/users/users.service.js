const { z } = require("zod");
const bcrypt = require("bcrypt");
const { sendEmail } = require("../utils/email.utils");
const { generateRandomPassword } = require("../utils/password.utils");
const { insertUser, findUserByEmail, resetPasswordUserByEmail, findUsers, findUserById, deleteUser, editUser, updatePasswordUser } = require("./users.repository");

const registerSchema = z.object({
  email: z.string().email(),
  fullname: z.string().regex(/^[a-zA-Z\s]+$/, "Full name can only contain letters and spaces."),
  username: z.string().regex(/^[a-z0-9]+$/, "Username can only contain lowercase letters and numbers."),
  phone_number: z.string(),
  password: z
    .string()
    .min(8)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).+$/, "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character."),
});

const registerUser = async (newUserData) => {
  registerSchema.parse(newUserData);

  const existingUser = await findUserByEmail(newUserData.email);

  if (existingUser) {
    throw new Error("Email is already registered.");
  }

  const user = await insertUser(newUserData);

  return user;
};

const loginSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(8)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).+$/, "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character."),
});

const loginUser = async (loginData) => {
  loginSchema.parse(loginData);

  const existingUser = await findUserByEmail(loginData.email);

  if (!existingUser) {
    throw new Error("User not found.");
  }

  const isPasswordValid = await bcrypt.compare(loginData.password, existingUser.password);

  if (!isPasswordValid) {
    throw new Error("Invalid email or password.");
  }

  return existingUser;
};

const forgotPasswordSchema = z.object({
  email: z.string().regex(/^[a-z0-9_.]+@[a-z0-9]+.(com|org|net)$/, "Invalid email format."),
});

const forgotPasswordUser = async (email) => {
  forgotPasswordSchema.parse({ email });

  const user = await findUserByEmail(email);

  if (!user) {
    throw new Error("User not found.");
  }

  const newPassword = generateRandomPassword();
  await resetPasswordUserByEmail(email, newPassword);

  const subject = "Password Reset";
  const text = `Your new password is: ${newPassword}`;

  await sendEmail(email, subject, text);
};

const getAllUsers = async () => {
  const users = await findUsers();

  return users;
};

const getUserById = async (id) => {
  const user = await findUserById(id);

  if (!user) {
    throw new Error("User not found.");
  }

  return user;
};

const deleteUserById = async (id) => {
  await getUserById(id);

  await deleteUser(id);
};

const editUserById = async (id, userData) => {
  await getUserById(id);

  const user = editUser(id, userData);

  return user;
};

const changePasswordSchema = z.object({
  oldPassword: z.string().min(8, "Old password must be at least 8 characters."),
  newPassword: z
    .string()
    .min(8)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).+$/, "New password must include at least one uppercase letter, one lowercase letter, one number, and one special character."),
  confirmNewPassword: z.string().min(8, "Confirm new password must be at least 8 characters."),
});

const changePasswordUser = async (id, oldPassword, newPassword, confirmNewPassword) => {
  changePasswordSchema.parse({ oldPassword, newPassword, confirmNewPassword });

  const user = await findUserById(id);

  if (!user) {
    throw new Error("User not found.");
  }

  const passwordValid = await bcrypt.compare(oldPassword, user.password);

  if (!passwordValid) {
    throw new Error("Invalid old password.");
  }

  if (newPassword !== confirmNewPassword) {
    throw new Error("New password and confirm password do not match.");
  }

  // Hash the new password before updating it
  await updatePasswordUser(user.email, newPassword);
};

module.exports = {
  registerUser,
  loginUser,
  forgotPasswordUser,
  getAllUsers,
  getUserById,
  deleteUserById,
  editUserById,
  changePasswordUser,
};

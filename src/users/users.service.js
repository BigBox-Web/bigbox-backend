const { z } = require("zod");
const bcrypt = require("bcrypt");
const { sendEmail } = require("../utils/email.utils");
const { generateRandomPassword } = require("../utils/password.utils");
const { insertUser, findUserByEmail, findUserByUsername, resetPasswordUserByEmail, findUsers, findUserById, deleteUser, editUser, updatePasswordUser } = require("./users.repository");

const registerSchema = z.object({
  fullname: z
    .string()
    .min(3, "Your fullname is too short")
    .max(50, "Your fullname is too long")
    .regex(/^[a-zA-Z\s]+$/, "Your fullname should only contain letters and spaces"),
  email: z.string().email("Invalid email format"),
  phone_number: z
    .string()
    .min(10, "Your phone number is too short")
    .max(15, "Your phone number is too long")
    .regex(/^[0-9]+$/, "Your phone number should only contain digits"),
  username: z
    .string()
    .min(3, "Your username is under 3 characters")
    .max(16, "Your username is over 16 characters")
    .regex(/^[a-z0-9]+$/, "Username can only contain lowercase letters and numbers"),
  password: z.string().min(8, "Your password is under 8 characters"),
});

const registerUser = async (newUserData) => {
  registerSchema.parse(newUserData);

  const existingUser = await findUserByEmail(newUserData.email);

  if (existingUser) {
    throw new Error("Email is already registered");
  }

  const existingUsername = await findUserByUsername(newUserData.username);

  if (existingUsername) {
    throw new Error("Username is already registered");
  }

  const user = await insertUser(newUserData);

  return user;
};

const loginSchema = z.object({
  username: z
    .string()
    .min(3, "Your username is under 3 characters")
    .max(16, "Your username is over 16 characters")
    .regex(/^[a-z0-9]+$/, "Username can only contain lowercase letters and numbers"),
  password: z.string().min(8, "Your password is under 8 characters"),
});

const loginUser = async (loginData) => {
  loginSchema.parse(loginData);

  const existingUser = await findUserByUsername(loginData.username);

  if (!existingUser) {
    throw new Error("User not found");
  }

  const isPasswordValid = await bcrypt.compare(loginData.password, existingUser.password);

  if (!isPasswordValid) {
    throw new Error("Invalid username or password");
  }

  return existingUser;
};

const forgotPasswordSchema = z.object({
  email: z.string().email("Invalid email format"),
});

const forgotPasswordUser = async (email) => {
  forgotPasswordSchema.parse({ email });

  const user = await findUserByEmail(email);

  if (!user) {
    throw new Error("User not found");
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
    throw new Error("User not found");
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
  oldPassword: z.string().min(8, "Old password must be at least 8 characters"),
  newPassword: z.string().min(8, "Your password is under 8 characters"),
  confirmNewPassword: z.string().min(8, "Confirm new password must be at least 8 characters"),
});

const changePasswordUser = async (id, oldPassword, newPassword, confirmNewPassword) => {
  changePasswordSchema.parse({ oldPassword, newPassword, confirmNewPassword });

  const user = await getUserById(id);

  const passwordValid = await bcrypt.compare(oldPassword, user.password);

  if (!passwordValid) {
    throw new Error("Invalid old password");
  }

  if (newPassword !== confirmNewPassword) {
    throw new Error("New password and confirm password do not match");
  }

  await updatePasswordUser(user.username, newPassword);
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

const prisma = require("../db/connection");
const bcrypt = require("bcrypt");

const insertUser = async (newUserData) => {
  const hashedPassword = await bcrypt.hash(newUserData.password, 10);
  const user = await prisma.users.create({
    data: {
      fullname: newUserData.fullname,
      email: newUserData.email,
      phone_number: newUserData.phone_number,
      username: newUserData.username,
      password: hashedPassword,
    },
  });

  return user;
};

const findUserByEmail = async (email) => {
  const user = await prisma.users.findUnique({
    where: {
      email,
    },
  });

  return user;
};

const findUserByUsername = async (username) => {
  const user = await prisma.users.findUnique({
    where: {
      username,
    },
  });

  return user;
};

const resetPasswordUserByEmail = async (email, newPassword) => {
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  const user = await prisma.users.update({
    where: {
      email,
    },
    data: {
      password: hashedPassword,
    },
  });

  return user;
};

const findUsers = async () => {
  const users = await prisma.users.findMany();

  return users;
};

const findUserById = async (id) => {
  const user = await prisma.users.findUnique({
    where: {
      id,
    },
  });

  return user;
};

const deleteUser = async (id) => {
  await prisma.users.delete({
    where: {
      id,
    },
  });
};

const editUser = async (id, userData) => {
  const user = await prisma.users.update({
    where: {
      id,
    },
    data: {
      role: userData.role,
      fullname: userData.fullname,
      profile_url: userData.profile_url,
    },
  });

  return user;
};

const updatePasswordUser = async (username, newPassword) => {
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  const user = await prisma.users.update({
    where: {
      username,
    },
    data: {
      password: hashedPassword,
    },
  });

  return user;
};

module.exports = {
  insertUser,
  findUserByEmail,
  findUserByUsername,
  resetPasswordUserByEmail,
  findUsers,
  findUserById,
  deleteUser,
  editUser,
  updatePasswordUser,
};

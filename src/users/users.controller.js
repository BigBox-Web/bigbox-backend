const express = require("express");
const { registerUser, loginUser, forgotPasswordUser, getAllUsers, getUserById, deleteUserById, editUserById, changePasswordUser } = require("./users.service");
const { generateAccessToken, generateRefreshToken, authenticateToken } = require("../middleware/auth.middleware");
const profileUpload = require("../middleware/upload.middleware");

const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const newUserData = req.body;
    const user = await registerUser(newUserData);

    res.status(201).send({
      data: user,
      message: "User created successfully",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await loginUser({ username, password });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.status(200).send({
      data: {
        user,
        accessToken,
        refreshToken,
      },
      message: "Login successful",
    });
  } catch (error) {
    res.status(401).send(error.message);
  }
});

router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await forgotPasswordUser(email);

    res.status(200).send({
      data: user,
      message: "New password sent to your email",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.get("/", authenticateToken, async (req, res) => {
  try {
    const user = await getAllUsers();

    res.status(200).send({
      data: user,
      message: "Users retrieved successfully",
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

router.get("/:id", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await getUserById(userId);

    res.status(200).send({
      data: user,
      message: "User retrieved successfully",
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

router.delete("/:id", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    await deleteUserById(userId);

    res.status(200).send("User deleted successfully");
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.patch("/settings/profile/:id", authenticateToken, profileUpload, async (req, res) => {
  try {
    const userId = req.params.id;
    const userData = req.body;
    const user = await editUserById(userId, userData);

    res.status(200).send({
      data: user,
      message: "User profile updated successfully",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.post("/settings/change-password", authenticateToken, async (req, res) => {
  try {
    const { id, oldPassword, newPassword, confirmNewPassword } = req.body;
    const user = await changePasswordUser(id, oldPassword, newPassword, confirmNewPassword);

    res.status(200).send({
      data: user,
      message: "Password changed successfully",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

module.exports = router;

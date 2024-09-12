const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const path = require("path");
const userController = require("./users/users.controller");
const ticketController = require("./tickets/tickets.controller");
const replyController = require("./replies/replies.controller");

dotenv.config();

const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(cors());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.get("/", (req, res) => {
  res.send({
    teamName: "Team 45",
    project: "BigBox Web",
  });
});

app.use("/users", userController);
app.use("/tickets", ticketController);
app.use("/", replyController);

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});

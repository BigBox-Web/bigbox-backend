const express = require("express");
const { createReply, getAllReplies, getReplyById, deleteReplyById, editReplyById } = require("./replies.service");
const { authenticateToken } = require("../middleware/auth.middleware");

const router = express.Router();

router.post("/:ticketId/replies", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const ticketId = parseInt(req.params.ticketId);
    const { reply_body } = req.body;

    const newReplyData = {
      reply_body,
      ticket_id: ticketId,
      user_id: userId,
    };

    const reply = await createReply(newReplyData);

    res.status(201).send({
      data: reply,
      message: "Reply created successfully.",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.get("/replies", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const replies = await getAllReplies(userId);

    res.status(200).send({
      data: replies,
      message: "Replies retrieved successfully.",
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

router.get("/replies/:id", authenticateToken, async (req, res) => {
  try {
    const replyId = parseInt(req.params.id);
    const reply = await getReplyById(replyId);

    res.status(200).send({
      data: reply,
      message: "Reply retrieved successfully.",
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

router.delete("/replies/:id", authenticateToken, async (req, res) => {
  try {
    const replyId = parseInt(req.params.id);
    await deleteReplyById(replyId);

    res.status(200).send("Reply deleted successfully.");
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.patch("/replies/:id", authenticateToken, async (req, res) => {
  try {
    const replyId = parseInt(req.params.id);
    const replyData = req.body;
    const reply = await editReplyById(replyId, replyData);

    res.status(200).send({
      data: reply,
      message: "reply updated successfully.",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

module.exports = router;

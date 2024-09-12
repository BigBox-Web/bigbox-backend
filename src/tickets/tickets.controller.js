const express = require("express");
const { createTicket, getAllTickets, getTicketById, deleteTicketById, editTicketById } = require("./tickets.service");
const { authenticateToken } = require("../middleware/auth.middleware");

const router = express.Router();

router.post("/", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const newTicketData = req.body;

    newTicketData.user_id = userId;

    const ticket = await createTicket(newTicketData);

    res.status(201).send({
      data: ticket,
      message: "Ticket created successfully.",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.get("/", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const tickets = await getAllTickets(userId);

    res.status(200).send({
      data: tickets,
      message: "Tickets retrieved successfully.",
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

router.get("/:id", authenticateToken, async (req, res) => {
  try {
    const ticketId = parseInt(req.params.id);
    const ticket = await getTicketById(ticketId);

    res.status(200).send({
      data: ticket,
      message: "Ticket retrieved successfully.",
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

router.delete("/:id", authenticateToken, async (req, res) => {
  try {
    const ticketId = parseInt(req.params.id);
    await deleteTicketById(ticketId);

    res.status(200).send("Ticket deleted successfully.");
  } catch (error) {
    res.status(400).send(error.message);
  }
});

router.patch("/:id", authenticateToken, async (req, res) => {
  try {
    const ticketId = parseInt(req.params.id);
    const ticketData = req.body;
    const ticket = await editTicketById(ticketId, ticketData);

    res.status(200).send({
      data: ticket,
      message: "Ticket updated successfully.",
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

module.exports = router;

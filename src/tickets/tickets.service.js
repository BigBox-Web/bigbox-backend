const { insertTicket, findTickets, findTicketById, deleteTicket, editTicket } = require("./tickets.repository");
const { format } = require("date-fns");

const createTicket = async (newTicketData) => {
  if (!(newTicketData.request_ticket && newTicketData.due_date && newTicketData.role_pic && newTicketData.product_status && newTicketData.ticket_body)) {
    throw new Error("Ticket not found.");
  }

  newTicketData.due_date = format(new Date(newTicketData.due_date), "dd-MM-yyyy");

  const ticket = await insertTicket(newTicketData);

  return ticket;
};

const getAllTickets = async (userId) => {
  const tickets = await findTickets(userId);

  tickets.forEach((ticket) => {
    ticket.due_date = format(new Date(ticket.due_date), "dd-MM-yyyy");
  });

  return tickets;
};

const getTicketById = async (id) => {
  const ticket = await findTicketById(id);

  if (!ticket) {
    throw new Error("Ticket not found.");
  }

  return ticket;
};

const deleteTicketById = async (id) => {
  await getTicketById(id);

  await deleteTicket(id);
};

const editTicketById = async (id, ticketData) => {
  await getTicketById(id);

  const ticket = editTicket(id, ticketData);

  return ticket;
};

module.exports = {
  createTicket,
  getAllTickets,
  getTicketById,
  deleteTicketById,
  editTicketById,
};

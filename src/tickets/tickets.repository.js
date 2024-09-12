const prisma = require("../db/connection");

const insertTicket = async (newTicketData) => {
  const ticket = await prisma.tickets.create({
    data: {
      request_ticket: newTicketData.request_ticket,
      due_date: newTicketData.due_date,
      role_pic: newTicketData.role_pic,
      product_status: newTicketData.product_status,
      ticket_body: newTicketData.ticket_body,
      user_id: newTicketData.user_id,
    },
  });

  return ticket;
};

const findTickets = async (userId) => {
  const tickets = await prisma.tickets.findMany({
    where: {
      user_id: userId,
    },
  });

  return tickets;
};

const findTicketById = async (id) => {
  const ticket = await prisma.tickets.findUnique({
    where: {
      id,
    },
  });

  return ticket;
};

const deleteTicket = async (id) => {
  await prisma.tickets.delete({
    where: {
      id,
    },
  });
};

const editTicket = async (id, ticketData) => {
  const ticket = await prisma.tickets.update({
    where: {
      id,
    },
    data: {
      status: ticketData.status,
      priority_status: ticketData.priority_status,
      request_ticket: ticketData.request_ticket,
      due_date: ticketData.due_date,
      role_pic: ticketData.role_pic,
      product_status: ticketData.product_status,
      ticket_body: ticketData.ticket_body,
    },
  });

  return ticket;
};

module.exports = {
  insertTicket,
  findTickets,
  findTicketById,
  deleteTicket,
  editTicket,
};

const prisma = require("../db/connection");

const insertReply = async (newReplyData) => {
  const reply = await prisma.replies.create({
    data: {
      reply_body: newReplyData.reply_body,
      ticket_id: newReplyData.ticket_id,
      user_id: newReplyData.user_id,
    },
  });

  return reply;
};

const findReplies = async (userId) => {
  const replies = await prisma.replies.findMany({
    where: {
      user_id: userId,
    },
  });

  return replies;
};

const findReplyById = async (id) => {
  const reply = await prisma.replies.findUnique({
    where: {
      id,
    },
  });

  return reply;
};

const deleteReply = async (id) => {
  await prisma.replies.delete({
    where: {
      id,
    },
  });
};

const editReply = async (id, replyData) => {
  const reply = await prisma.replies.update({
    where: {
      id,
    },
    data: {
      reply_body: replyData.reply_body,
    },
  });

  return reply;
};

module.exports = {
  insertReply,
  findReplies,
  findReplyById,
  deleteReply,
  editReply,
};

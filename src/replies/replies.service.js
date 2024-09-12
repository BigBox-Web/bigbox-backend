const { insertReply, findReplies, findReplyById, deleteReply, editReply } = require("./replies.repository");

const createReply = async (newReplyData) => {
  if (!newReplyData.reply_body) {
    throw new Error("Reply not found.");
  }

  const reply = await insertReply(newReplyData);

  return reply;
};

const getAllReplies = async (userId) => {
  const replies = await findReplies(userId);

  return replies;
};

const getReplyById = async (id) => {
  const reply = await findReplyById(id);

  if (!reply) {
    throw new Error("Reply not found.");
  }

  return reply;
};

const deleteReplyById = async (id) => {
  await getReplyById(id);

  await deleteReply(id);
};

const editReplyById = async (id, replyData) => {
  await getReplyById(id);

  const reply = editReply(id, replyData);

  return reply;
};

module.exports = {
  createReply,
  getAllReplies,
  getReplyById,
  deleteReplyById,
  editReplyById,
};

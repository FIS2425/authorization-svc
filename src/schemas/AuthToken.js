// This file will contain the schema for the AuthToken model.
// This schema will be used for security purposes. Storing and managing running, valid tokens
import mongoose from 'mongoose';

const authTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  roles: {
    type: [String],
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: process.env.JWT_EXPIRATION || '1h',
  },
});

export default mongoose.model('AuthToken', authTokenSchema)

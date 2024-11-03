import mongoose from 'mongoose';
import { validate as uuidValidate, v4 as uuidv4 } from 'uuid';

const userSchema = new mongoose.Schema(
  {
    _id: {
      type: String,
      default: () => uuidv4(),
      validate: {
        validator: uuidValidate,
        message: (props) => `${props.value} no es un UUID válido`,
      },
    },
    name: {
      type: String,
      required: [true],
    },
    email: {
      type: String,
      required: [true],
    },
    password: {
      type: String,
      required: [true],
    },
    role: {
      type: String,
      enum: ['admin', 'doctor', 'patient'],
      default: 'user',
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model('User', userSchema);

import mongoose from 'mongoose';
import { validate as uuidValidate, v4 as uuidv4 } from 'uuid';

import bcrypt from 'bcrypt';

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
      unique: [true],
    },
    password: {
      type: String,
      required: [true],
    },
    role: {
      type: [String],
      required: [true],
      enum: ['admin', 'clinicadmin', 'doctor', 'patient'],
      default: 'patient',
    },
    doctorid: {
      type: String,
    },
    patientid: {
      type: String,
    }
  },
  {
    timestamps: true,
  }
);

// Pre-save hook to hash the password before saving the user to the database
userSchema.pre('save', async function (next) {
  try {
    // Check if the password has been modified or is new
    if (!this.isModified('password')) {
      return next();
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;

    next()
  } catch (error) {
    next(error);
  }
})

// Method to compare passwords
userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error(error);
  }
}

export default mongoose.model('User', userSchema);

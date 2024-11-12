import mongoose from 'mongoose';
import { validate as uuidValidate, v4 as uuidv4 } from 'uuid';

const permissionSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: () => uuidv4(),
    validate: {
      validator: uuidValidate,
      message: (props) => `${props.value} is not a valid UUID`,
    },
  },
  method: {
    type: String,
    enum: ['get', 'create', 'edit', 'delete', 'changePassword'],
    required: true,
  },
  onRoles: {
    type: [String],
    enum: ['admin', 'clinicadmin', 'doctor', 'patient', 'himself'],
    required: true,
  },
});

const roleSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: () => uuidv4(),
    validate: {
      validator: uuidValidate,
      message: (props) => `${props.value} is not a valid UUID`,
    },
  },
  role: {
    type: String,
    enum: ['admin', 'clinicadmin', 'doctor', 'patient'],
    required: true,
  },
  permissions: [permissionSchema],
});

const Role = mongoose.model('Role', roleSchema);

export default Role;

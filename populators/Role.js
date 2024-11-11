import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import Role from '../src/schemas/Role.js'; // Adjust path if needed

const MONGO_URI = process.env.MONGOURL;

const connectToDatabase = async () => {
  mongoose
    .connect(MONGO_URI)
    .then(() => {
      console.log('MongoDB connection successful');
    })
    .catch((error) => {
      console.error('MongoDB connection error:', error.message);
    });
};

const roles = [
  {
    _id: uuidv4(),
    role: 'admin',
    permissions: [
      {
        _id: uuidv4(),
        method: 'get',
        onRoles: ['clinicadmin', 'doctor', 'patient', 'himself'],
      },
      {
        _id: uuidv4(),
        method: 'create',
        onRoles: ['clinicadmin', 'doctor', 'patient'],
      },
      {
        _id: uuidv4(),
        method: 'edit',
        onRoles: ['clinicadmin', 'doctor', 'patient'],
      },
      {
        _id: uuidv4(),
        method: 'delete',
        onRoles: ['clinicadmin', 'doctor', 'patient'],
      },
      { _id: uuidv4(), method: 'changePassword', onRoles: ['himself'] },
    ],
  },
  {
    _id: uuidv4(),
    role: 'clinicadmin',
    permissions: [
      {
        _id: uuidv4(),
        method: 'get',
        onRoles: ['doctor', 'patient', 'himself'],
      },
      {
        _id: uuidv4(),
        method: 'create',
        onRoles: ['doctor', 'patient', 'himself'],
      },
      { _id: uuidv4(), method: 'edit', onRoles: ['doctor', 'patient'] },
      { _id: uuidv4(), method: 'delete', onRoles: ['doctor', 'patient'] },
      { _id: uuidv4(), method: 'changePassword', onRoles: ['himself'] },
    ],
  },
  {
    _id: uuidv4(),
    role: 'doctor',
    permissions: [
      { _id: uuidv4(), method: 'get', onRoles: ['patient', 'himself'] },
      { _id: uuidv4(), method: 'changePassword', onRoles: ['himself'] },
    ],
  },
  {
    _id: uuidv4(),
    role: 'patient',
    permissions: [
      { _id: uuidv4(), method: 'get', onRoles: ['himself'] },
      { _id: uuidv4(), method: 'changePassword', onRoles: ['himself'] },
    ],
  },
];

async function populateRoles() {
  try {
    // Delete roles if they already exist
    await Role.deleteMany({
      role: { $in: roles.map((role) => role.role) },
    });

    // Save roles
    for (const roleData of roles) {
      const role = new Role(roleData);
      await role.save();
      console.log(`Role ${role.role} created successfully`);
    }

    console.log('All roles have been created');
  } catch (error) {
    console.error('Error populating roles:', error);
  } finally {
    mongoose.disconnect();
  }
}

// Run the script
(async () => {
  await connectToDatabase();
  await populateRoles();
})();

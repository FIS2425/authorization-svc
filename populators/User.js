import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import User from '../src/schemas/User.js'; // Adjust path if needed

const MONGO_URI = process.env.MONGOURL;

const connectToDatabase = async () => {
  mongoose
    .connect(MONGO_URI)
    .then(() => {
      console.log('Conexión con MongoDB OK');
    })
    .catch((error) => {
      console.error('Error de conexión con MongoDB:', error.message);
    });
}

// Sample user data
const sampleUsers = [
  {
    _id: uuidv4(),
    name: 'admin_user',
    password: 'admin123', // This will be hashed before saving
    roles: ['admin'],
  },
  {
    _id: uuidv4(),
    name: 'clinic_admin',
    password: 'clinicadmin123',
    roles: ['clinicadmin'],
    clinicid: 'clinic67890',
  },
  {
    _id: uuidv4(),
    name: 'doctor_user',
    password: 'doctor123',
    roles: ['doctor'],
  },
  {
    _id: uuidv4(),
    name: 'patient_user',
    password: 'patient123',
    roles: ['patient'],
    patientid: 'patient12345',
  },
  {
    _id: uuidv4(),
    name: 'multi_role_user',
    password: 'multiuser123',
    roles: ['doctor', 'clinicadmin'],
    doctorid: uuidv4(),
  },
];

async function populateUsers() {
  try {
    // Delete sample users (unique username)
    await User.deleteMany({ name: { $in: sampleUsers.map((user) => user.name) } });

    // Save each user with plain-text passwords (they will be hashed by the schema's pre-save hook)
    for (const userData of sampleUsers) {
      const user = new User(userData);
      await user.save();
      console.log(`User ${user.name} created successfully`);
    }

    console.log('All sample users have been created');
  } catch (error) {
    console.error('Error populating users:', error);
  } finally {
    mongoose.disconnect();
  }
}

// Run the script
(async () => {
  await connectToDatabase();
  await populateUsers();
})();
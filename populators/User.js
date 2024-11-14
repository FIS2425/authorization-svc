import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import User from '../src/schemas/User.js'; // Adjust path if needed

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

// Sample user data
const sampleUsers = [
  {
    _id: uuidv4(),
    email: 'admin@cloudmedix.com',
    password: 'Admin.123', // This will be hashed before saving
    roles: ['admin'],
  },
  {
    _id: uuidv4(),
    email: 'clinicadmin@cloudmedix.com',
    password: 'Clinicadmin.123',
    roles: ['clinicadmin'],
  },
  {
    _id: uuidv4(),
    email: 'doctor@cloudmedix.com',
    password: 'Doctor.123',
    roles: ['doctor'],
  },
  {
    _id: uuidv4(),
    email: 'patient@cloudmedix.com',
    password: 'Patient.123',
    roles: ['patient'],
    patientid: 'patient12345',
  },
  {
    _id: uuidv4(),
    email: 'multiuser@cloudmedix.com',
    password: 'Multiuser.123',
    roles: ['doctor', 'clinicadmin'],
    doctorid: uuidv4(),
  },
];

async function populateUsers() {
  try {
    // Delete sample users (unique email addresses) if they already exist
    await User.deleteMany({
      email: { $in: sampleUsers.map((user) => user.email) },
    });

    // Save each user with plain-text passwords (they will be hashed by the schema's pre-save hook)
    for (const userData of sampleUsers) {
      const user = new User(userData);
      await user.save();
      console.log(`User ${user.email} created successfully`);
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

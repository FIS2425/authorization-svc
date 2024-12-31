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
  {
    _id: 'af1520a8-2d04-441e-ba19-aef5faf45dc8',
    email: 'alfredoc@cloudmedix.com',
    password: 'Alfredoc.123',
    roles: ['doctor'],
    doctorid: 'fea82b90-c146-4ea6-91b3-85a73c82e259',
  },
  {
    _id: '679f55e3-a3cd-4a47-aebd-13038c1528a0',
    email: 'frandoc@cloudmedix.com',
    password: 'Frandoc.123',
    roles: ['doctor'],
    doctorid: 'a1ac971e-7188-4eaa-859c-7b2249e3c46b',
  },
  {
    _id: '27163ac7-4f4d-4669-a0c1-4b8538405475',
    email: 'adminstaff@cloudmedix.com',
    password: 'Adminstaff.123',
    roles: ['doctor', 'clinicadmin'],
    doctorid: '6a86e820-e108-4a71-8f10-57c3e0ccd0ac',
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

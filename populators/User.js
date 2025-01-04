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
  {
    _id: '8d0f780c-45f6-423d-ad86-87ef69740da9',
    email: 'patient1@cloudmedix.com',
    password: 'Patient.123',
    roles: ['patient'],
    patientid: 'f8b8d3e7-4bb7-4d1b-99a4-e3a8f0452f63',
  },
  {
    _id: '03ceec7e-6682-42be-b4ad-bcfe1baf73dc',
    email: 'patient2@cloudmedix.com',
    password: 'Patient.123',
    roles: ['patient'],
    patientid: 'b1a7f9e3-6c5d-49d2-8f4a-3b7e9f5a6c71',
  },
  {
    _id: '307408c6-954c-4505-bb4b-74e713267b84',
    email: 'patient3@cloudmedix.com',
    password: 'Patient.123',
    roles: ['patient'],
    patientid: 'd4f8b1a9-3e7c-45d2-9c6a-2b9f7e4a8c53',
  },
  {
    _id: 'f1c78f18-b62e-4b0f-80fa-1655be4cd80e',
    email: 'patient4@cloudmedix.com',
    password: 'Patient.123',
    roles: ['patient'],
    patientid: 'a2c7f9d1-5b3a-42d8-8e5f-7c4b9f1e8a92',
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

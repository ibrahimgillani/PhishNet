import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const MONGO_URI = 'mongodb://localhost:27017/phishnet';
const NEW_PASSWORD = 'PhishNet@2026';

async function resetPasswords() {
  await mongoose.connect(MONGO_URI);
  const newHash = await bcrypt.hash(NEW_PASSWORD, 10);

  const r1 = await mongoose.connection.db.collection('users').updateOne(
    { email: 'gillanimails@outlook.com' },
    { $set: { password: newHash } }
  );
  const r2 = await mongoose.connection.db.collection('users').updateOne(
    { email: 'gillanimails@gmail.com' },
    { $set: { password: newHash } }
  );

  console.log('✅ Password reset complete!');
  console.log(`   outlook (gillanimails@outlook.com): ${r1.modifiedCount ? 'Updated' : 'No change'}`);
  console.log(`   gmail   (gillanimails@gmail.com):   ${r2.modifiedCount ? 'Updated' : 'No change'}`);
  console.log(`\n   New password: ${NEW_PASSWORD}`);
  process.exit(0);
}

resetPasswords().catch(err => { console.error('Error:', err.message); process.exit(1); });

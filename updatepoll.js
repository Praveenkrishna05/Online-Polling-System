const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://praveen_krishna:Praveen%402005@polls.q1w15gv.mongodb.net/polling_system?retryWrites=true&w=majority&appName=Polls');
mongoose.connection.once('open', async () => {
  await mongoose.connection.db.collection('polls').updateMany({}, { $set: { votedBy: [] } });
  console.log('Polls updated');
  mongoose.connection.close();
});
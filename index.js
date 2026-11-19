import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";

const app = express();
const PORT = process.env.PORT || 6000

//middleware
app.use(cors());
app.use(express.json());




// Create a MongoClient and connect it to mongodb
const client = new MongoClient(process.env.MONGO_CLIENT_URI);
export async function connectToMongodb() {
  try {
    await client.connect();
    console.log("Successfully connected to mongodb");
    return client;
  } catch (err) {
    console.log(err);
  }
}
const connectedClient = await connectToMongodb();


//creating database and collections in mongodb
const db = connectedClient.db('pizzaplaza');
const users = db.collection('user');
const sessions = db.collection('session');
const items = db.collection('items')
const orders = db.collection('orders')
const transactions = db.collection('transactions')


//add new data to items collection
app.post('/items', async (req, res) => {
  const newItem = req.body;
  const result = await items.insertOne(newItems);
  res.send(result)
})

//add new data to items collection
app.post('/items', async (req, res) => {
  const newItem = req.body;
  const result = await items.insertOne(newItems);
  res.send(result)
})

//display all or query filtered data from jobs collection
app.get('/items', async (req, res) => {
  const query={};
  const cursor = items.find(query);
  const result = await cursor.toArray();
  res.send(result)
})





//homepage of backend
app.get('/', (req, res) => {
  res.send("Welcome to the backend of PizzaPlaza")
})

app.listen(PORT, () => {
  console.log(`app is listening on Port ${PORT}`);
})
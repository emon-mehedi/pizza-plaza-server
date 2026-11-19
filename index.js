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
    console.error("Failed to connect to mongodb:", err);
    process.exit(1);
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
  try {
    const newItem = req.body;
    const result = await items.insertOne(newItem);
    res.send(result)
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message)
  }
})

//display all or query filtered data from items collection
app.get('/items', async (req, res) => {
  try {
    const query = {};
    const cursor = items.find(query);
    const result = await cursor.toArray();
    res.send(result)
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message)
  }
})


//place a new order
app.post('/orders', async (req, res) => {
  try {
    const result = await orders.insertOne(req.body);
    res.send(result)
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message)
  }
})

//homepage of backend
app.get('/', (req, res) => {
  res.send("Welcome to the backend of PizzaPlaza")
})

app.listen(PORT, () => {
  console.log(`app is listening on Port ${PORT}`);
})
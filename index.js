// requiring express what we installed to make an app
const express = require("express");

// initializing cors by requiring it
const cors = require("cors");

// making an app using express
const app = express();

// configuring dotenv
require("dotenv").config();

// declaring port
const port = process.env.PORT || 3000;

// getting middlewares by using the app created by express
app.use(cors());
app.use(express.json());

// configuring DATABASE
const { MongoClient, ServerApiVersion } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ezm1s.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    console.log("ready");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// get request to get the response of the app
app.get("/", (req, res) => {
  res.send("Evenzaa is running");
});

// listening to the app
app.listen(port, () => {
  console.log(`Evenzaa is open at ${port}`);
});

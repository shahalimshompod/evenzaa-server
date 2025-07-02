// requiring express what we installed to make an app
const express = require("express");

// initializing cors by requiring it
const cors = require("cors");

// making an app using express
const app = express();

// configuring dotenv
require("dotenv").config();

// importing crypto for hashing password
const crypto = require("crypto");

// declaring port
const port = process.env.PORT || 3000;

// getting middlewares by using the app created by express
app.use(
  cors({
    origin: "https://evenzaa-client.vercel.app/",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// configuring DATABASE
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
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
    // connecting the server with database collections
    const events = client.db("Evenzaa").collection("all_events");
    const user_credentials = client
      .db("Evenzaa")
      .collection("user_credentials");
    const user_data = client.db("Evenzaa").collection("user_data");

    // function for hashing the password
    const hashPassword = (password) => {
      return crypto.createHash("sha256").update(password).digest("hex");
    };

    // function for generating token
    const generateToken = () => {
      return crypto.randomBytes(64).toString("hex");
    };

    // middlewares here "verifyToken"
    const verifyUserToken = async (req, res, next) => {
      try {
        const authHeader = req.headers.authorization;

        console.log("auth header --> ", authHeader);

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return res.status(401).json({
            success: false,
            message: "Unauthorized: No token provided",
          });
        }

        const token = authHeader.split(" ")[1];
        console.log("Received token:", token);

        if (!token) {
          return res.status(403).json({
            success: false,
            message: "Forbidden: Invalid token format",
          });
        }

        const user = await user_credentials.findOne({ userToken: token });
        if (!user) {
          return res.status(403).json({
            success: false,
            message: "Forbidden: Invalid or expired token",
          });
        }

        const userData = await user_data.findOne({ email: user.email });
        if (!userData) {
          return res.status(404).json({
            success: false,
            message: "User data not found",
          });
        }

        req.user = {
          _id: userData._id,
          email: userData.email,
          name: userData.name,
          image: userData.image,
          createdAt: userData.createdAt,
        };

        next();
      } catch (error) {
        console.error("Token verification failed:", error);
        return res.status(500).json({
          success: false,
          message: "Internal Server Error",
          error: error.message,
        });
      }
    };

    // operations

    // post operations here
    // post operation for storing user credentials like email, password
    app.post("/user_credential", async (req, res) => {
      try {
        // getting desired data from client side
        const data = req.body;
        const email = data.email;
        const password = data.password;

        // generating hash password from the password
        const hashedPassword = hashPassword(password);

        // checking if data is loaded from the client side
        if (!data || !email || !password || !hashedPassword) {
          return res.send({
            message: "Something Went Wrong",
            insertedId: null,
          });
        }

        // checking if the user was existed
        const query = { email: email };
        const existingUserInCredential = await user_credentials.findOne(query);
        const existingUserInData = await user_data.findOne(query);

        // if user is already existed in both collection then return
        if (existingUserInCredential || existingUserInData) {
          return res.send({
            message: "User is already exist with this Email!",
            insertedId: null,
          });
        }

        // now if the user unique then store the user credential (email, password)
        const userCredentials = {
          email,
          password: hashedPassword,
          userToken: null,
        };

        // check userCredential and then store the data
        if (!userCredentials) {
          return res.send({
            message: "Something Went Wrong",
            insertedId: null,
          });
        } else {
          const result = await user_credentials.insertOne(userCredentials);
          res.send(result);
        }
      } catch (error) {
        console.error(error);
      }
    });

    // post operation for storing user data like name, email, image, createdAt
    app.post("/user_data", async (req, res) => {
      try {
        // getting desired data from client side
        const data = req.body;
        const name = data.name;
        const email = data.email;
        const image = data.image;

        // checking if the data is in the server
        if (!data || !name || !email) {
          return res.send({
            message: "Something Went Wrong",
            insertedId: null,
          });
        }

        // final user data
        const userData = {
          name,
          email,
          image,
          createdAt: new Date(),
        };

        // checking if userdata broken or something
        if (!userData) {
          return res.send({
            message: "Something Went Wrong",
            insertedId: null,
          });
        } else {
          const result = await user_data.insertOne(userData);
          res.send(result);
        }
      } catch (error) {
        console.error(error);
      }
    });

    // post operation for authenticate user
    app.post("/user_authentication", async (req, res) => {
      try {
        // getting desired data from client
        const data = req.body;
        const email = data.email;
        const password = data.password;

        // making hash password of incoming password from client
        const hashedPassword = hashPassword(password);

        // checking if data email and password exist or not if exist then go ahead if not then return
        if (!data || !email || !password) {
          return res.send({ message: "Something went wrong!", token: null });
        }

        // validating database password with given password
        const query = { email: email };
        const user = await user_credentials.findOne(query);

        // if user do not exist then return
        if (!user) {
          return res.send({
            message: "Invalid Email or Password",
            token: null,
          });
        }

        // if password do not match then return
        if (hashedPassword !== user.password) {
          return res.send({
            message: "Invalid Email or Password",
            token: null,
          });
        } else {
          // let's generate access token
          const token = generateToken();

          //   updating the state in database
          const updateResult = await user_credentials.updateOne(
            { email: email },
            { $set: { userToken: token } }
          );

          if (!updateResult.modifiedCount > 0) {
            return res.send({ message: "Something went wrong!", token: null });
          } else {
            res.send({ message: "User successfully logged in", token: token });
          }
        }
      } catch (error) {
        console.error(error);
      }
    });

    // post operation for logout
    app.post("/logout", verifyUserToken, async (req, res) => {
      try {
        // getting the token
        const token = req.headers.authorization.split(" ")[1];

        //   update userToken to null
        const result = await user_credentials.updateOne(
          { userToken: token },
          { $set: { userToken: null } }
        );

        // if the user token is not null then return
        if (!result.modifiedCount > 0) {
          return res.send({ message: "Something went wrong!", token: token });
        } else {
          res.send({ message: "User Logged out successfully", token: null });
        }
      } catch (error) {
        console.error(error);
      }
    });

    // post operation for add event
    app.post("/add-event", verifyUserToken, async (req, res) => {
      try {
        // getting desired data from client body
        const data = req.body;

        // check if data is getting correctly
        if (!data) {
          return res.send({
            message: "Something went wrong while adding events",
            insertedId: null,
          });
        }

        // final data
        const finalData = {
          title: data.title,
          organizer: data.organizer,
          organizerEmail: data.organizerEmail,
          eventDate: data.eventDate,
          time: data.time,
          location: data.location,
          description: data.description,
          attendeeCount: 0,
          category: data.category,
          featured: data.featured,
          image: data.image,
          createdAt: new Date(),
          alreadyJoined: [],
        };

        // check if final data getting correctly
        if (!finalData) {
          return res.send({
            message: "Something went wrong while adding events",
            insertedId: null,
          });
        }

        // if all goes well then add the event to the database
        const result = await events.insertOne(finalData);
        res.send(result);
      } catch (error) {
        console.error(error);
      }
    });

    // post operation for join event
    app.post("/join-event/:id", async (req, res) => {
      try {
        const eventId = req.params.id;
        const { id } = req.body;

        // getting specific event by event id
        const event = await events.findOne({
          _id: new ObjectId(eventId),
        });

        // checking if event is there
        if (!event) {
          return res.send({ message: "Something went wrong!", success: false });
        }

        // check if event have the same user id
        if (event.alreadyJoined.includes(id)) {
          return res.json({
            alreadyJoined: true,
            message: "You are already joined to this event!",
          });
        }

        // if everything goes well then go ahead and increment
        await events.updateOne(
          { _id: new ObjectId(eventId) },
          {
            $push: { alreadyJoined: id },
            $inc: { attendeeCount: 1 },
          }
        );

        res.json({
          message: "Successfully Joined to this event!",
          success: true,
        });
      } catch (error) {
        console.error(error);
      }
    });

    // get operations here
    // get operation for featured events
    app.get("/featured-events", async (req, res) => {
      try {
        const query = { featured: "true" };
        const result = await events
          .find(query)
          .sort({ createdAt: -1 })
          .limit(3)
          .toArray();
        res.send(result);
      } catch (error) {
        console.error(error);
      }
    });

    // get operation for search result
    app.get("/get-search-result-data", verifyUserToken, async (req, res) => {
      try {
        const search = req.query.query || "";
        const filter = search
          ? {
              $or: [
                { title: { $regex: search, $options: "i" } },
                { category: { $regex: search, $options: "i" } },
              ],
            }
          : {};

        const result = await events.find(filter).toArray();
        res.json(result);
      } catch (error) {
        console.error(error);
      }
    });

    // get operation for all events
    app.get("/all-events", verifyUserToken, async (req, res) => {
      try {
        const { date, range } = req.query;
        let filter = {};

        // If specific date filter is provided
        if (date) {
          // Directly compare string dates (database stores "YYYY-MM-DD")
          filter.eventDate = date;
        }
        // If date range filter is provided
        else if (range) {
          const today = new Date();
          today.setUTCHours(0, 0, 0, 0);

          // Format dates to match database format
          const formatDate = (dateObj) => {
            return dateObj.toISOString().split("T")[0];
          };

          switch (range) {
            case "currentWeek": {
              const start = new Date(today);
              start.setDate(today.getDate() - today.getDay());

              const end = new Date(start);
              end.setDate(start.getDate() + 7);

              filter.eventDate = {
                $gte: formatDate(start),
                $lt: formatDate(end),
              };
              break;
            }
            case "lastWeek": {
              const start = new Date(today);
              start.setDate(today.getDate() - today.getDay() - 7);

              const end = new Date(start);
              end.setDate(start.getDate() + 7);

              filter.eventDate = {
                $gte: formatDate(start),
                $lt: formatDate(end),
              };
              break;
            }
            case "currentMonth": {
              const start = new Date(today.getFullYear(), today.getMonth(), 1);
              const end = new Date(
                today.getFullYear(),
                today.getMonth() + 1,
                1
              );

              filter.eventDate = {
                $gte: formatDate(start),
                $lt: formatDate(end),
              };
              break;
            }
            case "lastMonth": {
              const start = new Date(
                today.getFullYear(),
                today.getMonth() - 1,
                1
              );
              const end = new Date(today.getFullYear(), today.getMonth(), 1);

              filter.eventDate = {
                $gte: formatDate(start),
                $lt: formatDate(end),
              };
              break;
            }
            default: {
              // Return all events if invalid range
              break;
            }
          }
        }

        const result = await events
          .find(filter)
          .sort({ createdAt: -1 })
          .toArray();

        res.send(result);
      } catch (error) {
        console.error("Error fetching filtered events:", error);
        res.status(500).send({ message: "Server Error" });
      }
    });

    // get operation for user
    app.get("/user", verifyUserToken, async (req, res) => {
      try {
        if (!req.user) {
          return res.status(404).json({ message: "User not found" });
        }
        const user = req.user;
        res.send(user);
      } catch (error) {
        console.error(error);
      }
    });

    // get operation for category wise events
    app.get("/events-by-category", verifyUserToken, async (req, res) => {
      try {
        const category = req.query.category;
        console.log(category);
        const query = { category: category };
        const cursor = events.find(query).sort({ createdAt: -1 });
        const result = await cursor.toArray();
        res.send(result);
      } catch (error) {
        console.error(error);
      }
    });

    // get operation for my event data
    app.get("/my-event-data", verifyUserToken, async (req, res) => {
      try {
        // getting email from user
        const email = req.query.email;
        const query = { organizerEmail: email };
        const cursor = events.find(query).sort({ createdAt: -1 });
        const result = await cursor.toArray();
        res.send(result);
      } catch (error) {
        console.error(error);
      }
    });

    // get operation for details page
    app.get("/details-event/:id", verifyUserToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await events.findOne(query);
        res.send(result);
      } catch (error) {
        console.error(error);
      }
    });

    // put operation
    app.put("/update-event/:id", verifyUserToken, async (req, res) => {
      try {
        // getting id and formdata from client
        const { id } = req.params;
        const updatedData = req.body;

        if (updatedData._id) {
          delete updatedData._id;
        }

        if (!id || !updatedData) {
          return res.send({
            message: "Something went wrong while updating data",
            modifiedCount: 0,
          });
        }

        // updating data in database
        const result = await events.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        res.send(result);
      } catch (error) {
        console.error(error);
      }
    });

    // delete operation
    // delete event
    app.delete("/delete-event/:id", verifyUserToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await events.deleteOne(query);
        res.send(result);
      } catch (error) {
        console.error(error);
      }
    });
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

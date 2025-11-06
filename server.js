require("dotenv").config();
const express = require("express");
const app = express();
const { MongoClient, ServerApiVersion } = require("mongodb");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const PORT = 3000;

// 🧩 Middleware
app.use(cors());
app.use(express.json());

// 🧠 Session middleware
app.use(
  session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
  })
);

// 🔐 Login check middleware
function isLoggedIn(req, res, next) {
  if (req.session.userId) {
    return next();
  } else {
    // Redirect to login page if not logged in
    return res.redirect('/login');
  }
}

// 🗄️ MongoDB Client setup
const client = new MongoClient(process.env.MONGODB_URL, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// 🚀 Main function
async function run() {
  try {
    await client.connect(); // ✅ Ensure MongoDB connection

    const db = client.db("product-landing-page");
    const orderCollection = db.collection("orders");
    const adminCollection = db.collection("admin");

    //  Register route
    app.post("/register", async (req, res) => {
      try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
          return res
            .status(400)
            .json({ message: "Username and password are required." });
        }

        // Check if user already exists
        const existingUser = await adminCollection.findOne({ username });
        if (existingUser) {
          return res
            .status(400)
            .json({ message: "Username already exists." });
        }

        // Hash password
        const hashed = await bcrypt.hash(password, 10);
        const adminInfo = { username, password: hashed };

        // Insert into DB
        const result = await adminCollection.insertOne(adminInfo);

        res.status(201).json({
          message: "User registered successfully!",
          userId: result.insertedId,
        });
      } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    //  Login route
    app.post("/login", async (req, res) => {
      try {
        const { username, password } = req.body;

        // Find user
        const user = await adminCollection.findOne({ username });
        if (!user) {
          return res.status(400).json({ message: "User not found." });
        }

        // Compare password
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
          return res.status(400).json({ message: "Invalid credentials." });
        }

        // Save session
        req.session.userId = username;
        res.json({ message: "Logged in successfully!" });
      } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    //  Logout route
    app.post("/logout", (req, res) => {
      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({ message: "Error logging out" });
        }
        res.json({ message: "Logged out successfully" });
      });
    });

    //  Insert order data
    app.post("/orders", async (req, res) => {
      try {
        const payload = req.body;

        if (!payload.product || !payload.pricing) {
          return res
            .status(400)
            .json({ error: "Missing product or pricing info" });
        }

        const result = await orderCollection.insertOne(payload);

        res.status(201).json({
          message: "Order created successfully.",
          orderId: result.insertedId,
        });
      } catch (err) {
        console.error("Error inserting order:", err);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    //  Get orders by email
    app.get("/orders", async (req, res) => {
      try {
        const { email } = req.query;

        if (!email) {
          return res
            .status(400)
            .json({ error: "Email query parameter is required" });
        }

        const orders = await orderCollection.find({ email }).toArray();
        res.status(200).json(orders);
      } catch (err) {
        console.error("Error fetching orders:", err);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    //  Admin route (requires login)
    app.get("/ordersA",isLoggedIn,  async (req, res) => {
      try {
        const orders = await orderCollection.find().toArray();
        res.status(200).json(orders);
      } catch (err) {
        console.error("Error fetching orders:", err);
        res.status(500).json({ error: "Internal server error" });
      }
    });

     // LOGOUT
    app.post("/logout", (req, res) => {
      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({ message: "Error logging out" });
        }
        res.json({ message: "Logged out successfully" });
      });
    });

    console.log("✅ Connected to MongoDB and routes are ready.");
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}

run().catch(console.dir);

// 🌐 Test route
app.get("/", (req, res) => {
  res.send("Hello, Express!");
});

// 🚀 Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
// const session = require("express-session");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const PORT = 3000;

// 🧩 Middleware
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());

// টোকেন যাচাই
function authenticate(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];
  if (!token)
    return res.status(401).json({ message: "Unauthorized - No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // decoded এ থাকবে userId এবং role
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired token" });
  }
}

// শুধুমাত্র Admin এর জন্য অনুমতি
function authorizeAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ message: "Access denied! Admin only." });
  }
  next();
}

const client = new MongoClient(process.env.MONGODB_URL, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Main function
async function run() {
  try {
    const db = client.db("product-landing-page");
    const orderCollection = db.collection("orders");
    const adminCollection = db.collection("admin");
    const productsCollection = db.collection("products");

    //  Register route
    app.post("/register", async (req, res) => {
      const { name, email, password, role } = req.body;

      try {
        const existing = await adminCollection.findOne({ email });
        if (existing)
          return res.status(400).json({ message: "User already exists" });

        const hashed = await bcrypt.hash(password, 10);
        await adminCollection.insertOne({
          name,
          email,
          password: hashed,
          role: role || "user",
        });

        res.json({ message: "User registered successfully" });
      } catch (err) {
        res.status(500).json({ message: "Server error" });
      }
    });

    // লগইন
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      try {
        const admin = await adminCollection.findOne({ email });
        if (!admin)
          return res.status(400).json({ message: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch)
          return res.status(400).json({ message: "Invalid credentials" });

        const payload = { id: admin._id, role: admin.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        // cookie তে সংরক্ষণ
        res.cookie("token", token, {
          httpOnly: true,
          // sameSite: 'lax',
          secure: false,
          // maxAge: 60 * 60 * 1000,
        });

        res.json({
          message: "Login successful",
          user: { name: admin.name, role: admin.role },
        });
      } catch (err) {
        res.status(500).json({ message: "Server error" });
      }
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
    app.get("/ordersA", authenticate, authorizeAdmin, async (req, res) => {
      try {
        const orders = await orderCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();
        res.status(200).json(orders);
      } catch (err) {
        console.error("Error fetching orders:", err);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    app.get(
      "/orders/recent",
      authenticate,
      authorizeAdmin,
      async (req, res) => {
        try {
          const limit = parseInt(req.query.limit) || 5;

          const recentOrders = await orderCollection
            .find({})
            .sort({ createdAt: -1 }) // descending by createdAt
            .limit(limit)
            .toArray();

          res.status(200).json(recentOrders);
        } catch (err) {
          console.error("Error fetching recent orders:", err);
          res.status(500).json({ error: "Internal server error" });
        }
      }
    );

    app.post("/addProducts", authenticate, authorizeAdmin, async (req, res) => {
      try {
        const { name, price, icons } = req.body;

        // Accept multiple possible main-image fields for compatibility
        const img =
          req.body.img || req.body.productImage || req.body.imageUrl || null;

        // Basic validations
        const priceNum = Number(price);
        const iconsArray = Array.isArray(icons) ? icons.filter(Boolean) : [];

        if (!name || !price || !img || iconsArray.length < 2) {
          return res.status(400).json({
            message:
              "All fields are required: name, price, one main image, and at least two icons.",
          });
        }

        if (Number.isNaN(priceNum) || priceNum < 0) {
          return res
            .status(400)
            .json({ message: "price must be a valid number ≥ 0" });
        }

        const newProduct = {
          name: String(name).trim(),
          price: priceNum,
          img, // normalized field name in DB
          icons: iconsArray, // exactly what you want stored
          createdAt: new Date(),
        };

        const result = await productsCollection.insertOne(newProduct);

        return res.status(201).json({
          message: "Product added successfully",
          product: { _id: result.insertedId, ...newProduct },
        });
      } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Server error" });
      }
    });

    // get products
    app.get("/products", async (req, res) => {
      try {
        const products = await productsCollection.find().toArray();
        res.status(200).json(products);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // product updated
    app.patch(
      "/products/:id",
      authenticate,
      authorizeAdmin,
      async (req, res) => {
        const id = req.params.id;
        const updateData = req.body;

        try {
          const result = await productsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
          );

          if (result.matchedCount === 0) {
            return res.status(404).json({ message: "Product not found" });
          }

          const updatedProduct = await productsCollection.findOne({
            _id: new ObjectId(id),
          });
          res.json({
            message: " Product updated successfully",
            product: updatedProduct,
          });
        } catch (err) {
          console.error("❌ Error updating product:", err);
          res.status(500).json({ message: "Server error", error: err.message });
        }
      }
    );

    app.patch("/orders/:id", async (req, res) => {
      const { id } = req.params;
      const { status } = req.body;

      if (!status) {
        return res.status(400).json({ message: "Status is required" });
      }

      try {
        const result = await orderCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status, updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "Order not found" });
        }

        res.status(200).json({
          message: "Order status updated successfully",
          status,
        });
      } catch (error) {
        console.error(" Error updating order:", error);
        res.status(500).json({ message: "Server error", error: error.message });
      }
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        secure: false, // production এ true দিতে হবে
        sameSite: "strict",
      });

      res.json({ message: "Logged out successfully" });
    });
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}

run().catch(console.dir);

// Test route
app.get("/", (req, res) => {
  res.send("Hello, Express!");
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

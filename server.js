const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;


// ---------- DB CONNECTION ----------
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ---------- MODELS ----------

// User: both OWNER and CUSTOMER
const userSchema = new mongoose.Schema(
  {
    role: { type: String, enum: ["OWNER", "CUSTOMER"], required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

// Property
const propertySchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: { type: String, required: true },
    location: { type: String, required: true },
    type: { type: String, default: "Flat" }, // Flat/House/Plot etc.
    bhk: Number,
    area: Number, // in sq ft
    price: { type: Number, required: true },
    status: {
      type: String,
      enum: ["AVAILABLE", "BOOKED", "SOLD"],
      default: "AVAILABLE",
    },
  },
  { timestamps: true }
);
const Property = mongoose.model("Property", propertySchema);

// Booking (Registration + Transaction in simple form)
const bookingSchema = new mongoose.Schema(
  {
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
    },
    customer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    status: {
      type: String,
      enum: ["BOOKED", "PAID", "CANCELLED"],
      default: "BOOKED",
    },
    amountPaid: { type: Number, default: 0 },
  },
  { timestamps: true }
);
const Booking = mongoose.model("Booking", bookingSchema);

// Cancellation
const cancellationSchema = new mongoose.Schema(
  {
    booking: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Booking",
      required: true,
    },
    refundAmount: { type: Number, required: true },
  },
  { timestamps: true }
);
const Cancellation = mongoose.model("Cancellation", cancellationSchema);

// Loan info
const loanSchema = new mongoose.Schema(
  {
    bankName: String,
    rateOfInterest: Number,
    tenureMonths: Number,
    maxAmount: Number,
    siteLink: String,
  },
  { timestamps: true }
);
const Loan = mongoose.model("Loan", loanSchema);

// Testimonial
const testimonialSchema = new mongoose.Schema(
  {
    customerName: String,
    profession: String,
    message: String,
    satisfaction: { type: Number, min: 1, max: 5 },
  },
  { timestamps: true }
);
const Testimonial = mongoose.model("Testimonial", testimonialSchema);

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "change-this-secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(express.static(path.join(__dirname, "public")));

// Helpers
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Login required" });
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.userId || req.session.role !== role) {
      return res.status(403).json({ error: `${role} access required` });
    }
    next();
  };
}

// ---------- AUTH ROUTES ----------

// Register (owner or customer based on "role")
app.post("/api/register", async (req, res) => {
  try {
    const { role, firstName, lastName, email, phone, password } = req.body;
    if (!["OWNER", "CUSTOMER"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      role,
      firstName,
      lastName,
      email,
      phone,
      passwordHash,
    });

    req.session.userId = user._id;
    req.session.role = user.role;

    res.status(201).json({ message: "Registered successfully", role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    req.session.userId = user._id;
    req.session.role = user.role;

    res.json({ message: "Login successful", role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Current user
app.get("/api/me", async (req, res) => {
  if (!req.session.userId) return res.json(null);
  const user = await User.findById(req.session.userId).select(
    "firstName lastName email role"
  );
  res.json(user);
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out" });
  });
});

// ---------- PROPERTY ROUTES ----------

// Public: list all available properties
app.get("/api/properties", async (req, res) => {
  const props = await Property.find({ status: "AVAILABLE" }).sort({
    createdAt: -1,
  });
  res.json(props);
});

// Owner: list own properties
app.get("/api/my-properties", requireRole("OWNER"), async (req, res) => {
  const props = await Property.find({ owner: req.session.userId }).sort({
    createdAt: -1,
  });
  res.json(props);
});

// Owner: create property
app.post("/api/properties", requireRole("OWNER"), async (req, res) => {
  try {
    const { name, location, type, bhk, area, price } = req.body;
    const prop = await Property.create({
      owner: req.session.userId,
      name,
      location,
      type,
      bhk,
      area,
      price,
    });
    res.status(201).json(prop);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Failed to create property" });
  }
});

// Owner: delete property
app.delete("/api/properties/:id", requireRole("OWNER"), async (req, res) => {
  try {
    const deleted = await Property.findOneAndDelete({
      _id: req.params.id,
      owner: req.session.userId,
    });
    if (!deleted) {
      return res.status(404).json({ error: "Property not found" });
    }
    res.json({ message: "Property deleted" });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Failed to delete property" });
  }
});

// ---------- BOOKING / PAYMENT / CANCELLATION ----------

// Customer: book property
app.post("/api/bookings", requireRole("CUSTOMER"), async (req, res) => {
  try {
    const { propertyId } = req.body;
    const prop = await Property.findById(propertyId);
    if (!prop || prop.status !== "AVAILABLE") {
      return res.status(400).json({ error: "Property not available" });
    }

    const booking = await Booking.create({
      property: propertyId,
      customer: req.session.userId,
    });

    prop.status = "BOOKED";
    await prop.save();

    res.status(201).json(booking);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Booking failed" });
  }
});

// Customer: pay for booking
app.post("/api/bookings/:id/pay", requireRole("CUSTOMER"), async (req, res) => {
  try {
    const { amount } = req.body;
    const booking = await Booking.findById(req.params.id).populate("property");
    if (!booking || booking.customer.toString() !== req.session.userId) {
      return res.status(400).json({ error: "Invalid booking" });
    }

    booking.status = "PAID";
    booking.amountPaid = amount;
    await booking.save();

    booking.property.status = "SOLD";
    await booking.property.save();

    res.json({ message: "Payment recorded", booking });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Payment failed" });
  }
});

// Customer: cancel booking
app.post(
  "/api/bookings/:id/cancel",
  requireRole("CUSTOMER"),
  async (req, res) => {
    try {
      const { refundAmount } = req.body;
      const booking = await Booking.findById(req.params.id).populate("property");
      if (!booking || booking.customer.toString() !== req.session.userId) {
        return res.status(400).json({ error: "Invalid booking" });
      }

      booking.status = "CANCELLED";
      await booking.save();

      booking.property.status = "AVAILABLE";
      await booking.property.save();

      const cancel = await Cancellation.create({
        booking: booking._id,
        refundAmount,
      });

      res.json({ message: "Booking cancelled", cancellation: cancel });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Cancellation failed" });
    }
  }
);

// Customer: view own bookings
app.get("/api/my-bookings", requireRole("CUSTOMER"), async (req, res) => {
  const bookings = await Booking.find({ customer: req.session.userId })
    .populate("property")
    .sort({ createdAt: -1 });
  res.json(bookings);
});

// ---------- LOANS & TESTIMONIALS ----------

// Public: list loans
app.get("/api/loans", async (req, res) => {
  const loans = await Loan.find().sort({ createdAt: -1 });
  res.json(loans);
});

// Owner: add loan
app.post("/api/loans", requireRole("OWNER"), async (req, res) => {
  try {
    const loan = await Loan.create(req.body);
    res.status(201).json(loan);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Failed to add loan" });
  }
});

// Public: list testimonials
app.get("/api/testimonials", async (req, res) => {
  const t = await Testimonial.find().sort({ createdAt: -1 });
  res.json(t);
});

// Customer: add testimonial
app.post("/api/testimonials", requireRole("CUSTOMER"), async (req, res) => {
  try {
    const { customerName, profession, message, satisfaction } = req.body;
    const t = await Testimonial.create({
      customerName,
      profession,
      message,
      satisfaction,
    });
    res.status(201).json(t);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Failed to add testimonial" });
  }
});

// ---------- START SERVER ----------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

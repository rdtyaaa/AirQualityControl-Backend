const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Origin",
      "X-Requested-With",
      "Content-Type",
      "Accept",
      "Authorization",
      "ngrok-skip-browser-warning",
    ],
    credentials: true,
  })
);

app.use(express.json());
app.use(express.static("public"));

const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ role: "admin" });

    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 10);

      const defaultAdmin = new User({
        username: "admin",
        email: "admin@iotairquality.com",
        password: hashedPassword,
        role: "admin",
        location: "System Admin",
      });

      await defaultAdmin.save();
      console.log("✅ Default admin created successfully");
      console.log("📧 Email: admin@iotairquality.com");
      console.log("🔑 Password: admin123");
      console.log("⚠️  Please change the default password after first login");
    } else {
      console.log("ℹ️  Admin user already exists");
    }
  } catch (error) {
    console.error("❌ Error creating default admin:", error.message);
  }
};

mongoose
  .connect(
    process.env.MONGODB_URI || "mongodb://localhost:27017/iot_airquality",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(() => {
    console.log("📦 Connected to MongoDB");
    createDefaultAdmin();
  })
  .catch((error) => {
    console.error("❌ MongoDB connection error:", error);
  });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  location: String,
  createdAt: { type: Date, default: Date.now },
});

const deviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true },
  deviceCode: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  location: String,
  isActive: { type: Boolean, default: true },
  lastSeen: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
});

const sensorDataSchema = new mongoose.Schema({
  deviceId: { type: String, required: true },
  temperature: { type: Number, required: true },
  humidity: { type: Number, required: true },
  airQuality: { type: Number, required: true },
  airQualityLevel: {
    type: String,
    enum: ["Excellent", "Good", "Moderate", "Poor", "Danger"],
  },
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Device = mongoose.model("Device", deviceSchema);
const SensorData = mongoose.model("SensorData", sensorDataSchema);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Access token required",
      code: "TOKEN_MISSING",
    });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET || "fallback_secret",
    (err, user) => {
      if (err) {
        if (err.name === "TokenExpiredError") {
          return res.status(401).json({
            error: "Token expired",
            code: "TOKEN_EXPIRED",
          });
        }
        return res.status(403).json({
          error: "Invalid token",
          code: "TOKEN_INVALID",
        });
      }
      req.user = user;
      next();
    }
  );
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
};

const generateDeviceCode = () => {
  return Math.random().toString(36).substr(2, 8).toUpperCase();
};

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, location } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields required" });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
      location,
    });

    await user.save();

    res.status(201).json({
      message: "User registered successfully",
      userId: user._id,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/refresh", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const newToken = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "24h" }
    );

    res.json({ token: newToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "24h" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        location: user.location,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post(
  "/api/devices/register",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { deviceId, location } = req.body;

      if (!deviceId) {
        return res.status(400).json({ error: "Device ID required" });
      }

      const deviceCode = generateDeviceCode();

      const device = new Device({
        deviceId,
        deviceCode,
        location,
      });

      await device.save();

      res.status(201).json({
        message: "Device registered successfully",
        device: {
          deviceId: device.deviceId,
          deviceCode: device.deviceCode,
          location: device.location,
        },
      });
    } catch (error) {
      if (error.code === 11000) {
        return res.status(400).json({ error: "Device ID already exists" });
      }
      res.status(500).json({ error: error.message });
    }
  }
);

app.post("/api/devices/link", authenticateToken, async (req, res) => {
  try {
    const { deviceCode, location } = req.body;

    if (!deviceCode) {
      return res.status(400).json({ error: "Device code required" });
    }

    const device = await Device.findOne({ deviceCode });
    if (!device) {
      return res.status(404).json({ error: "Invalid device code" });
    }

    device.userId = req.user.userId;
    if (location) device.location = location;
    await device.save();

    res.json({
      message: "Device linked successfully",
      device: {
        deviceId: device.deviceId,
        location: device.location,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/devices/user/:userId", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin" && req.user.userId !== req.params.userId) {
      return res.status(403).json({ error: "Access denied" });
    }

    const devices = await Device.find({ userId: req.params.userId });
    res.json(devices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/devices/info/:deviceId", async (req, res) => {
  try {
    const { deviceId } = req.params;

    const device = await Device.findOne({ deviceId });
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }

    res.json({
      deviceId: device.deviceId,
      deviceCode: device.deviceCode,
      location: device.location,
      isActive: device.isActive,
      isLinked: !!device.userId,
      lastSeen: device.lastSeen,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/devices/auto-register", async (req, res) => {
  try {
    const { deviceId, location } = req.body;

    if (!deviceId) {
      return res.status(400).json({ error: "Device ID required" });
    }

    const existingDevice = await Device.findOne({ deviceId });
    if (existingDevice) {
      return res.json({
        message: "Device already exists",
        device: {
          deviceId: existingDevice.deviceId,
          deviceCode: existingDevice.deviceCode,
          location: existingDevice.location,
        },
      });
    }

    const deviceCode = generateDeviceCode();

    const device = new Device({
      deviceId,
      deviceCode,
      location: location || "Unknown",
    });

    await device.save();

    res.status(201).json({
      message: "Device auto-registered successfully",
      device: {
        deviceId: device.deviceId,
        deviceCode: device.deviceCode,
        location: device.location,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/data/sensor", async (req, res) => {
  try {
    const { deviceId, temperature, humidity, airQuality, airQualityLevel } =
      req.body;

    if (
      !deviceId ||
      temperature === undefined ||
      humidity === undefined ||
      airQuality === undefined ||
      !airQualityLevel
    ) {
      return res.status(400).json({ error: "Missing required sensor data" });
    }

    let device = await Device.findOne({ deviceId });
    if (!device) {
      const deviceCode = generateDeviceCode();
      device = new Device({
        deviceId,
        deviceCode,
        location: "Auto-registered",
      });
      await device.save();

      console.log(
        `Auto-registered new device: ${deviceId} with code: ${deviceCode}`
      );
    }

    const sensorData = new SensorData({
      deviceId,
      temperature,
      humidity,
      airQuality,
      airQualityLevel,
    });

    await sensorData.save();

    device.lastSeen = new Date();
    await device.save();

    res.json({
      message: "Data received successfully",
      deviceCode: device.deviceCode,
    });
  } catch (error) {
    console.error("Sensor data error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/data/latest/:deviceId", authenticateToken, async (req, res) => {
  try {
    const { deviceId } = req.params;

    if (req.user.role !== "admin") {
      const device = await Device.findOne({
        deviceId,
        userId: req.user.userId,
      });
      if (!device) {
        return res.status(403).json({ error: "Access denied" });
      }
    }

    const latestData = await SensorData.findOne({ deviceId }).sort({
      timestamp: -1,
    });

    if (!latestData) {
      return res.status(404).json({ error: "No data found" });
    }

    res.json(latestData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/data/history/:deviceId", authenticateToken, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { hours = 24 } = req.query;

    if (req.user.role !== "admin") {
      const device = await Device.findOne({
        deviceId,
        userId: req.user.userId,
      });
      if (!device) {
        return res.status(403).json({ error: "Access denied" });
      }
    }

    const hoursAgo = new Date(Date.now() - hours * 60 * 60 * 1000);

    const historicalData = await SensorData.find({
      deviceId,
      timestamp: { $gte: hoursAgo },
    }).sort({ timestamp: -1 });

    res.json(historicalData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/dashboard/user/:userId", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin" && req.user.userId !== req.params.userId) {
      return res.status(403).json({ error: "Access denied" });
    }

    const userId = req.params.userId;

    const devices = await Device.find({ userId });

    const dashboardData = await Promise.all(
      devices.map(async (device) => {
        const latestData = await SensorData.findOne({
          deviceId: device.deviceId,
        }).sort({ timestamp: -1 });

        return {
          device: {
            deviceId: device.deviceId,
            location: device.location,
            lastSeen: device.lastSeen,
            isActive: device.isActive,
          },
          latestData: latestData || null,
        };
      })
    );

    res.json(dashboardData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const users = await User.find({}, "-password");
      res.json(users);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(
  "/api/admin/devices",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const devices = await Device.find().populate(
        "userId",
        "username email location"
      );
      res.json(devices);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(
  "/api/admin/analytics",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const totalUsers = await User.countDocuments();
      const totalDevices = await Device.countDocuments();
      const activeDevices = await Device.countDocuments({
        lastSeen: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
      });

      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const airQualityStats = await SensorData.aggregate([
        { $match: { timestamp: { $gte: yesterday } } },
        { $group: { _id: "$airQualityLevel", count: { $sum: 1 } } },
      ]);

      res.json({
        totalUsers,
        totalDevices,
        activeDevices,
        airQualityStats: {
          Excellent:
            airQualityStats.find((s) => s._id === "Excellent")?.count || 0,
          Good: airQualityStats.find((s) => s._id === "Good")?.count || 0,
          Moderate:
            airQualityStats.find((s) => s._id === "Moderate")?.count || 0,
          Poor: airQualityStats.find((s) => s._id === "Poor")?.count || 0,
          Danger: airQualityStats.find((s) => s._id === "Danger")?.count || 0,
        },
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.get("/api/air-quality/:deviceId", authenticateToken, async (req, res) => {
  try {
    const { deviceId } = req.params;

    if (req.user.role !== "admin") {
      const device = await Device.findOne({
        deviceId,
        userId: req.user.userId,
      });
      if (!device) {
        return res.status(403).json({ error: "Access denied" });
      }
    }

    const latestData = await SensorData.findOne({ deviceId }).sort({
      timestamp: -1,
    });

    if (!latestData) {
      return res.status(404).json({ error: "No data available" });
    }

    res.json({
      airQualityLevel: latestData.airQualityLevel,
      timestamp: latestData.timestamp,
      readings: {
        temperature: latestData.temperature,
        humidity: latestData.humidity,
        airQuality: latestData.airQuality,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

app.use((req, res) => {
  res.status(404).json({
    error: "Not found",
    message: "The requested endpoint does not exist",
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Air Quality Monitoring API ready`);
});

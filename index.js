const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { CoreApi } = require("midtrans-client");

dotenv.config();
const PUBLIC_URL = process.env.PUBLIC_URL || path.join(__dirname, "public");

const app = express();
app.use(express.json());
app.use(express.static(PUBLIC_URL));

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error connecting to MongoDB:", err));

const User = require("./model/user");

// Midtrans configuration
const core = new CoreApi({
  isProduction: false, // Set to true for production environment
  serverKey: process.env.MIDTRANS_SERVER_KEY,
  clientKey: process.env.MIDTRANS_CLIENT_KEY,
});

// Middleware to verify JWT
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Authorization header missing" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token missing" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log(err);
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Token expired" });
      } else {
        return res.status(403).json({ message: "Invalid token" });
      }
    }
    req.user = user;
    next();
  });
};

// Middelware multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, PUBLIC_URL);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

app.get("/", (req, res) => {
  res.status(200).json({ message: "Welcome in The North Pay!!!" });
});

app.post("/register", async (req, res) => {
  const { username, password, email, phoneNumber } = req.body;
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({
      username,
      password: hashedPassword,
      email,
      phoneNumber,
      avatar: `${process.env.HOSTNAME}/avatar.jpg`,
    });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log(error);
    if (error?.errorResponse?.errmsg) {
      res.status(400).json({ message: error?.errorResponse?.errmsg });
    } else if (error?._message) {
      res.status(400).json({ message: error?._message });
    } else {
      res.status(500).json({ message: "Internal server error" });
    }
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({
      $or: [{ username: email }, { email: email }],
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid username/email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid username/email or password" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRY || "1h",
    });
    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/change-password", authenticate, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid old password" });
    }
    user.password = newPassword;
    await user.save();
    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/profile", authenticate, async (req, res) => {
  const user = await User.findById(req.user.userId);
  res.status(200).json({
    name: user.username,
    email: user.email,
    phoneNumber: user.phoneNumber,
    avatar: user.avatar,
    balance: user.balance,
    transactions: user.transactions,
  });
});

app.post("/profile", authenticate, upload.single("avatar"), async (req, res) => {
  try {
    const { username, email, phoneNumber } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
      _id: { $ne: user._id },
    });
    if (existingUser) {
      return res.status(400).json({ message: "Username or email already exists" });
    }

    user.username = username;
    user.email = email;
    user.phoneNumber = phoneNumber;

    if (req.file) {
      user.avatar = `${process.env.HOSTNAME}/${req.file.filename}`;
    }

    await user.save();
    res.status(200).json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.get("/contact", authenticate, async (req, res) => {
  try {
    const users = await User.find();
    const response = users.map((user) => ({
      id: user._id,
      name: user.username,
      email: user.email,
      phoneNumber: user.phoneNumber,
      avatar: user.avatar,
    }));
    res.status(200).json(response);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/topup", authenticate, async (req, res) => {
  try {
    let amount = req.body.amount;
    if (!amount) {
      return res.status(400).json({ message: "Amount is required" });
    }
    amount = parseInt(amount, 10);

    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ message: "Invalid amount" });
    }
    const user = await User.findById(req.user.userId);
    const parameter = {
      payment_type: "qris",
      transaction_details: {
        order_id: `TOPUP-${Date.now()}-${user._id}`,
        gross_amount: amount,
      },
      customer_details: {
        first_name: user.username,
        email: user.email,
        phone: user.phoneNumber,
      },
    };
    const transaction = await core.charge(parameter);
    res.status(200).json(transaction);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/midtrans-notification", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    let receivedJson = req.body;
    if (typeof receivedJson === "string") {
      receivedJson = JSON.parse(receivedJson);
    }

    const notification = await core.transaction.notification(receivedJson);

    if (notification.transaction_status === "settlement") {
      const orderId = notification.order_id;
      const grossAmount = notification.gross_amount;

      // Find the user and check if the transaction already exists
      const user = await User.findOne({ _id: orderId.split("-")[2] });

      if (user) {
        const existingTransaction = user.transactions.find((transaction) => transaction.orderId === orderId);

        if (!existingTransaction) {
          await User.findOneAndUpdate(
            { _id: orderId.split("-")[2] },
            {
              $inc: { balance: grossAmount },
              $push: {
                transactions: {
                  orderId,
                  amount: Number(grossAmount),
                  type: "topup",
                  timestamp: new Date(),
                },
              },
            }
          );
        } else {
          console.log("Duplicate transaction detected. Skipping update.");
        }
      }
    }

    res.status(200).json(notification);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/transfer", authenticate, async (req, res) => {
  const { recipientUsername, amount } = req.body;

  try {
    let transferAmount = parseInt(amount, 10);

    if (isNaN(transferAmount) || transferAmount <= 0) {
      return res.status(400).json({ message: "Invalid amount" });
    }

    const sender = await User.findById(req.user.userId);
    const recipient = await User.findOne({ username: recipientUsername });

    if (!recipient) {
      return res.status(404).json({ message: "Recipient not found" });
    }

    if (sender.username === recipientUsername) {
      return res.status(400).json({ message: "You cannot send money to yourself" });
    }

    if (sender.balance < transferAmount) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    sender.balance -= transferAmount;
    sender.transactions.push({
      amount: -transferAmount,
      type: "transfer",
      recipient: recipientUsername,
      timestamp: new Date(),
    });
    await sender.save();

    recipient.balance += transferAmount;
    recipient.transactions.push({
      amount: transferAmount,
      type: "transfer",
      sender: sender.username,
      timestamp: new Date(),
    });
    await recipient.save();

    res.status(200).json({ message: "Transfer successful" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});

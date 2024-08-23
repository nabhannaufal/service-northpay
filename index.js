const path = require("path");
const express = require("express");
const fs = require("fs");
const mongoose = require("mongoose");
const multer = require("multer");
const moment = require("moment");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");
const { CoreApi, Snap } = require("midtrans-client");

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

// Set the locale to Indonesian
moment.locale("id");

// Midtrans configuration
const core = new CoreApi({
  isProduction: false, // Set to true for production environment
  serverKey: process.env.MIDTRANS_SERVER_KEY,
  clientKey: process.env.MIDTRANS_CLIENT_KEY,
});

const snap = new Snap({
  isProduction: false, // Set to true for production environment
  serverKey: process.env.MIDTRANS_SERVER_KEY,
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

// formatter
const formatCurrency = (amount) => {
  const amountString = amount.toString();
  const parts = amountString.split(".");
  let integerPart = parts[0];
  const decimalPart = parts[1] || "";
  const formattedIntegerPart = integerPart.replace(/\B(?=(\d{3})+(?!\d))/g, ".");
  const formattedAmount = decimalPart ? `${formattedIntegerPart},${decimalPart}` : formattedIntegerPart;
  return `IDR ${formattedAmount}`;
};

// create trxid
const createTransactionId = () => {
  const appId = "A302";
  const timeStamp = moment().format("YYMMDDHHmmss");
  const changeableDigit = "0";

  return [appId, timeStamp, changeableDigit].join("");
};

app.get("/", (req, res) => {
  res.status(200).json({ status: "00000", message: "Welcome in The North Pay!!!", description: "Test CICD" });
});

app.post("/register", async (req, res) => {
  const { username, password, email, phoneNumber, fullName } = req.body;
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({
      username,
      password: hashedPassword,
      email,
      phoneNumber,
      fullName,
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
    fullName: user.fullName,
    email: user.email,
    phoneNumber: user.phoneNumber,
    avatar: user.avatar,
    balance: formatCurrency(user.balance),
  });
});

app.post("/update-profile", authenticate, upload.single("avatar"), async (req, res) => {
  try {
    const { username, email, phoneNumber, fullName } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (username && username !== user.username) {
      const existingUserByUsername = await User.findOne({ username, _id: { $ne: user._id } });
      if (existingUserByUsername) {
        return res.status(400).json({ message: "Username already exists" });
      }
    }

    if (email && email !== user.email) {
      const existingUserByEmail = await User.findOne({ email, _id: { $ne: user._id } });
      if (existingUserByEmail) {
        return res.status(400).json({ message: "Email already exists" });
      }
    }

    if (username) {
      user.username = username;
    }
    if (email) {
      user.email = email;
    }
    if (phoneNumber) {
      user.phoneNumber = phoneNumber;
    }

    if (fullName) {
      user.fullName = fullName;
    }

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
      fullName: user.fullName,
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
      transaction_details: {
        order_id: `TOPUP-${Date.now()}-${user._id}`,
        gross_amount: amount,
      },
      credit_card: {
        secure: true,
      },
      customer_details: {
        first_name: user.username,
        email: user.email,
        phone: user.phoneNumber,
      },
    };
    const transaction = await snap.createTransaction(parameter);
    res.status(200).json({
      status: "sucess",
      redirect_url: transaction.redirect_url,
      token: transaction.token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/topup-finish/:trxId", async (req, res) => {
  try {
    const { trxId } = req.params;
    if (!trxId) {
      return res.status(400).json({ message: "Missing transaction_id" });
    }
    const notification = await snap.transaction.status(trxId);

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
                  userId: user._id,
                  transaction_id: createTransactionId(),
                  amount: Number(grossAmount),
                  type: "topup",
                  timestamp: moment(new Date()).format("DD MMMM YYYY, HH:mm"),
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

app.post("/v2/topup", authenticate, async (req, res) => {
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

app.get("/history", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const history = await Promise.all(
      user.transactions.map(async (transaction) => {
        const relatedUser = transaction.userId.equals(user._id) ? user : await User.findById(transaction.userId);

        return {
          orderId: transaction.orderId,
          transaction_id: transaction.transaction_id,
          amount: formatCurrency(transaction.amount),
          type: transaction.type,
          timestamp: transaction.timestamp,
          name: relatedUser ? relatedUser.fullName : null,
          avatar: relatedUser ? relatedUser.avatar : null,
        };
      })
    );

    res.status(200).json({ transaction: history });
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
                  userId: user._id,
                  transaction_id: createTransactionId(),
                  amount: Number(grossAmount),
                  type: "topup",
                  timestamp: moment(new Date()).format("DD MMMM YYYY, HH:mm"),
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

    const orderId = `TRANSFER-${Date.now()}-${req.user.userId}`;
    const sender = await User.findById(req.user.userId);
    const recipient = await User.findOne({ username: recipientUsername });
    const transactionId = createTransactionId();

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
      transaction_id: transactionId,
      userId: recipient._id,
      timestamp: moment(new Date()).format("DD MMMM YYYY, HH:mm"),
      orderId,
    });
    await sender.save();

    recipient.balance += transferAmount;
    recipient.transactions.push({
      amount: transferAmount,
      type: "transfer",
      transaction_id: transactionId,
      userId: sender._id,
      timestamp: moment(new Date()).format("DD MMMM YYYY, HH:mm"),
      orderId,
    });
    await recipient.save();

    res.status(200).json({
      orderId,
      amount: formatCurrency(transferAmount),
      transaction_id: transactionId,
      type: "transfer",
      timestamp: moment(new Date()).format("DD MMMM YYYY, HH:mm"),
      name: recipient.username,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/request", authenticate, async (req, res) => {
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
    const qrCodeData = `northpay_request:${user._id}:${amount}`;

    const qrCodeFilename = `qr-${user._id}-${Date.now()}.png`;
    const qrCodeFilePath = path.join(PUBLIC_URL, qrCodeFilename);

    await QRCode.toFile(qrCodeFilePath, qrCodeData, { errorCorrectionLevel: "H" });

    const qrCodeImageUrl = `${process.env.HOSTNAME}/${qrCodeFilename}`;

    res.status(200).json({
      qrCodeUrl: qrCodeImageUrl,
      amount: formatCurrency(amount),
      qrCodeData,
    });
  } catch (error) {
    console.error("Error generating payment request:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/pay", authenticate, async (req, res) => {
  try {
    const { qrCodeData } = req.body;

    if (!qrCodeData) {
      return res.status(400).json({ message: "QR code data is required" });
    }

    const [prefix, recipientId, amountString] = qrCodeData.split(":");
    const amount = parseInt(amountString, 10);

    if (prefix !== "northpay_request" || isNaN(amount) || amount <= 0) {
      return res.status(400).json({ message: "Invalid QR code" });
    }

    const payer = await User.findById(req.user.userId);
    const recipient = await User.findById(recipientId);

    if (!recipient) {
      return res.status(404).json({ message: "Recipient not found" });
    }

    if (payer.username === recipient.username) {
      return res.status(400).json({ message: "You cannot pay to yourself" });
    }

    if (payer.balance < amount) {
      return res.status(400).json({ message: "Insufficient balance" });
    }

    payer.balance -= amount;
    recipient.balance += amount;

    const orderId = `TRANSFER-${Date.now()}-${payer._id}`;
    const transactionId = createTransactionId();

    payer.transactions.push({
      orderId,
      amount: -amount,
      type: "transfer",
      userId: recipient._id,
      transaction_id: transactionId,
      timestamp: moment(new Date()).format("DD MMMM YYYY, HH:mm"),
    });

    recipient.transactions.push({
      orderId,
      amount: amount,
      type: "transfer",
      userId: payer._id,
      transaction_id: transactionId,
      timestamp: moment(new Date()).format("DD MMMM YYYY, HH:mm"),
    });

    await payer.save();
    await recipient.save();

    res.status(200).json({
      message: "Payment successful",
      amount: formatCurrency(amount),
      recipient: recipient.username,
    });
  } catch (error) {
    console.error("Error processing payment:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});

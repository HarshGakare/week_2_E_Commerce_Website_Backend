const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');

// Initialize dotenv
dotenv.config();

// Initialize Express App
const app = express();

// Use middleware
app.use(cors());
app.use(bodyParser.json());

// Set up multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Store images in the 'uploads' directory
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname); // Get the file extension
    const filename = Date.now() + ext; // Name the file with a timestamp and extension
    cb(null, filename);
  }
});

const upload = multer({ storage });

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('Error connecting to MongoDB: ', err));

// User Schema for Authentication
const User = mongoose.model('User', {
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }, // admin or user
  date: { type: Date, default: Date.now }
});

// Product Schema
const Product = mongoose.model('Product', {
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  stock: { type: Number, required: true },
  image: { type: String }, // Store the image path
  date: { type: Date, default: Date.now }
});

// Order Schema
const Order = mongoose.model('Order', {
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  products: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    quantity: { type: Number }
  }],
  totalAmount: { type: Number, required: true },
  status: { type: String, default: 'pending' }, // pending, completed, canceled
  date: { type: Date, default: Date.now }
});

// Middleware to Verify JWT Token
const verifyToken = (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).send('Access Denied');
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

// User Registration Endpoint
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ email });

  if (existingUser) {
    return res.status(400).send('User already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();

  const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.send("register completed.");
});

// Admin Login Endpoint
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(400).send('User not found');

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid password');

  res.send(' Admins create ');
  user.role = 'admin';

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token });
});

// User Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(400).send('User not found');

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid password');

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.send('user login');
  res.json({ token });
});

// Add Product (Admin Only) with Image Upload
app.post('/product', verifyToken, upload.single('image'), async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access Denied');
  }

  const { name, description, price, category, stock } = req.body;
  const image = req.file ? req.file.path : null; // Get the image path

  const newProduct = new Product({ name, description, price, category, stock, image });
  await newProduct.save();
  res.json(newProduct);
});

// Get All Products
app.get('/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

// Place Order
app.post('/order', verifyToken, async (req, res) => {
  const { products } = req.body;
  let totalAmount = 0;

  // Calculate total amount
  for (let i = 0; i < products.length; i++) {
    const product = await Product.findById(products[i].productId);
    if (!product) return res.status(400).send('Product not found');
    totalAmount += product.price * products[i].quantity;
  }

  const order = new Order({
    userId: req.user.id,
    products,
    totalAmount
  });

  await order.save();
  res.json(order);
});

// Get Orders for User
app.get('/orders', verifyToken, async (req, res) => {
  const orders = await Order.find({ userId: req.user.id }).populate('products.productId');
  res.json(orders);
});

// Update Order Status (Admin Only)
app.patch('/order/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access Denied');
  }

  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).send('Order not found');

  order.status = req.body.status;
  await order.save();

  res.json(order);
});

// Start the Express Server
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

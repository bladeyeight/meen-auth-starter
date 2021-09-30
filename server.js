require('dotenv').config();

// Dependencies
const express = require('express');
const app = express();
const mongoose = require('mongoose');

// Database Configuration
mongoose.connect(process.env.DATABASE_URL, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});


// Routes / Controllers
const userController = require('./controllers/users');
app.use('/users', userController);
const sessionsController = require('./controllers/sessions');
app.use('/sessions', sessionsController);

// Temporary root route. Please remove me when you add views:
app.get("/", (req, res) => {
	res.send("Root route");
  });app.get('/')

// Database Connection Error / Success
const db = mongoose.connection;
db.on('error', (err) => console.log(err.message + ' is mongod not running?'));
db.on('connected', () => console.log('mongo connected'));
db.on('disconnected', () => console.log('mongo disconnected'));

// Middleware
// Body parser middleware: give us access to req.body
app.use(express.urlencoded({ extended: true }));

// Middleware
app.use(
    session({
        secret: process.env.SECRET,
        resave: false,
        saveUninitialized: false
    })); 

	

// Listener
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`server is listening on port: ${PORT}`));
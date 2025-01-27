const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');

// Create an instance of Express
const app = express();
const port = 3000;

// Middleware to parse JSON data (use express built-in parser)
app.use(express.json()); // Replaces bodyParser.json()

app.use(cors());

// Create a connection to the database
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'TaskManagementSystem'
});

// Connect to the database
db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database');
});

// Sign up endpoint
app.post('/api/signup', (req, res) => {
    console.log(req.body); // Log the incoming request body to see if it's correct
  
    const { fullname, username, email, phone_number, role, password } = req.body;
  
    // Check if all fields are provided
    if (!fullname || !username || !email || !phone_number || !role || !password) {
      return res.status(500).json({ message: 'All fields are required' });
    }
  
    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          return res.status(500).json({ message: 'Error hashing password' });
        }
      
        const query = 'INSERT INTO signup (fullname, username, email, phone_number, role, password) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(query, [fullname, username, email, phone_number, role, hashedPassword], (err, result) => {
          if (err) {
            console.error('Error inserting user into database:', err.message); // Log the error message
            return res.status(500).json({ message: 'Error registering user' });
          }
      
          console.log('User inserted successfully:', result); // Log successful insertion
          res.status(201).json({ message: 'User registered successfully' });
        });
      });
});


//Login end point
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
      return res.status(400).json({ message: 'All fields are required' });
  }

  // Query the user by username from the signup table
  const query = 'SELECT username, password, role FROM signup WHERE username = ?';
  db.query(query, [username], (err, results) => {
      if (err) {
          console.error('Database query error:', err);
          return res.status(500).json({ message: 'Internal server error' });
      }

      if (results.length === 0) {
          return res.status(404).json({ message: 'User not found' });
      }

      const user = results[0];  // User info (including role) from signup table

      // Compare provided password with the hashed password in the signup table
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) {
              console.error('Password comparison error:', err);
              return res.status(500).json({ message: 'Internal server error' });
          }

          if (!isMatch) {
              return res.status(401).json({ message: 'Invalid username or password' });
          }

          // Log the login attempt into the login table
          const queryLogLogin = 'INSERT INTO login (username, role) VALUES (?, ?)';
          db.query(queryLogLogin, [user.username, user.role], (err, result) => {
              if (err) {
                  console.error('Error logging user login:', err.message);
                  return res.status(500).json({ message: 'Error logging login information' });
              }

              // Return user information along with role to be used on the frontend for redirection
              res.status(200).json({
                  message: 'Login successful',
                  username: user.username,
                  role: user.role,  // Role fetched from signup table
              });
          });
      });
  });
});

// API endpoint to add a project
app.post('/add-project', (req, res) => {
  const { projectName } = req.body;

  // Validate the input
  if (!projectName || projectName.trim() === '') {
      return res.status(400).json({ error: 'Project name is required.' });
  }
  

  // Insert the project into the database
  const query = 'INSERT INTO projects (name) VALUES (?)';
  db.query(query, [projectName], (err, result) => {
      if (err) {
          console.error('Error inserting project into database:', err);
          return res.status(500).json({ error: 'Failed to add project.' });
      }
      res.status(201).json({ message: 'Project added successfully.', projectId: result.insertId });
  });
});

// API endpoint to fetch all projects
app.get('/projects', (req, res) => {
  const query = 'SELECT * FROM projects';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching projects from database:', err);
      return res.status(500).json({ error: 'Failed to fetch projects.' });
    }
    res.status(200).json(results);
  });
});


// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

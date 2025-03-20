const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

// Load environment variables
dotenv.config();

// Create an instance of Express
const app = express();
const port = 3000;

// Middleware to parse JSON data
app.use(express.json());
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

// Create a function to send OTP email
async function sendOtpEmail(email, otp) {
  let transporter = nodemailer.createTransport({
      service: 'gmail',
      secure: false,
      auth: {
          user: 'shrotaghimire97@gmail.com',  // Use your email here
          pass: 'fdve gkai bxxl lswn',  // Use your email password here
      },
  });

  let info = await transporter.sendMail({
      from: 'info@shrota.com',
      to: email,
      subject: "OTP Verification",
      text: `Your OTP for verification is: ${otp}`,
  });

  console.log("OTP sent: %s", info.messageId);

}


app.post('/api/signup', (req, res) => {
  const { fullname, username, email, phone_number, role, password } = req.body;

  if (!fullname || !username || !email || !phone_number || !role || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  db.query('SELECT * FROM signup WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Database error:', err.message);
      return res.status(500).json({ message: 'Internal server error' });
    }
    if (results.length > 0) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ message: 'Error hashing password' });
      }

      const query = 'INSERT INTO signup (fullname, username, email, phone_number, role, password) VALUES (?, ?, ?, ?, ?, ?)';
      db.query(query, [fullname, username, email, phone_number, role, hashedPassword], (err, result) => {
        if (err) {
          console.error('Error inserting user:', err.message);
          return res.status(500).json({ message: 'Error registering user' });
        }

        // ✅ Generate OTP
        const otp = crypto.randomInt(100000, 999999);
        

        // ✅ Store OTP in the database with timestamp
        const otpQuery = 'INSERT INTO otp_verification (email, otp, created_at) VALUES (?, ?, NOW())';
        db.query(otpQuery, [email, otp], (err) => {
          if (err) {
            console.error('Error storing OTP:', err.message);  // Log error
            return res.status(500).json({ message: 'Error generating OTP' });
          }

          // ✅ Send OTP via email
          sendOtpEmail(email, otp)
            .then(() => {
              res.status(201).json({ message: 'User registered successfully. OTP sent to email.' });
            })
            .catch((error) => {
              console.error('Error sending OTP:', error);
              res.status(500).json({ message: 'Error sending OTP' });
            });
        });
      });
    });
  });
});



app.post('/api/verifyOtp', (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required' });
  }

  // Check OTP in the database
  const query = 'SELECT * FROM otp_verification WHERE email = ? ORDER BY created_at DESC LIMIT 1';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Database error:', err.message);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(400).json({ message: 'Invalid OTP or email' });
    }

    const storedOtp = results[0].otp;

    if (parseInt(otp) === storedOtp) {
      // Fetch user details to get the role
      const userQuery = 'SELECT role FROM signup WHERE email = ?';
      db.query(userQuery, [email], (err, userResults) => {
        if (err) {
          console.error('Error fetching user:', err.message);
          return res.status(500).json({ message: 'Error fetching user data' });
        }

        if (userResults.length === 0) {
          return res.status(400).json({ message: 'User not found' });
        }

        const userRole = userResults[0].role;

        // Delete OTP after successful verification
        db.query('DELETE FROM otp_verification WHERE email = ?', [email], (err) => {
          if (err) {
            console.error('Error deleting OTP:', err.message);
          }
        });

        return res.status(200).json({ message: 'OTP verified successfully', role: userRole });
      });
    } else {
      return res.status(400).json({ message: 'Invalid OTP' });
    }
  });
});




// Login route with JWT
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const query = 'SELECT id, username, password, role FROM signup WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error('Password comparison error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }

      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      return res.status(200).json({
        message: 'Login successful',
        username: user.username,
        role: user.role,
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



// API endpoint to get all projects
app.get('/projects', (req, res) => {
  // Query to get all projects
  const query = 'SELECT * FROM projects';
  db.query(query, (err, result) => {
      if (err) {
          console.error('Error fetching projects:', err);
          return res.status(500).json({ error: 'Failed to fetch projects.' });
      }

      res.json(result); // Return the projects as the response
  });
});



app.delete('/projects/:projectId', (req, res) => {
  const projectId = req.params.projectId;

  if (!projectId) {
      return res.status(400).json({ error: "Project ID is required" });
  }

  const sql = `DELETE FROM projects WHERE id = ?`;
  db.query(sql, [projectId], (err, result) => {
      if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ error: "Failed to delete project" });
      }

      if (result.affectedRows === 0) {
          return res.status(404).json({ error: "Project not found" });
      }

      console.log(`Project with ID ${projectId} deleted successfully.`);
      return res.status(200).json({ success: true });
  });
});



//Generate code
app.post('/generate-invite-code', (req, res) => {
  const projectId = req.body.projectId;

  // Validate projectId
  if (!projectId) {
      return res.status(400).json({ error: "Project ID is required" });
  }

  // Generate a unique 8-character invite code
  const inviteCode = crypto.randomBytes(4).toString('hex').toUpperCase();

  // Store the invite code in the database
  const sql = `UPDATE projects SET invite_code = ? WHERE id = ?`;
  db.query(sql, [inviteCode, projectId], (err, result) => {
      if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ error: "Error generating invite code" }); // Only one response
      }

      // Check if the project ID exists
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: "Project not found" }); // Only one response
      }

      console.log("Generated Invite Code:", inviteCode); // Debugging

      // Send response once
      return res.json({ success: true, inviteCode });
  });
});


app.post('/join-project', (req, res) => {
  const { inviteCode, userId } = req.body;

  if (!inviteCode || !userId) {
      return res.status(400).json({ error: 'Invite code and user ID are required.' });
  }

  db.query(
      'SELECT id FROM projects WHERE invite_code = ?',
      [inviteCode],
      (error, rows) => {
          if (error) {
              console.error('Database error:', error);
              return res.status(500).json({ error: 'Internal server error during query execution.' });
          }

          if (rows.length === 0) {
              return res.status(400).json({ error: 'Invalid invite code.' });
          }

          const projectId = rows[0].id;

          db.query(
              'INSERT INTO user_projects (user_id, project_id) VALUES (?, ?)',
              [userId, projectId],
              (error) => {
                  if (error) {
                      console.error('Error inserting into user_projects:', error);
                      return res.status(500).json({ error: 'Internal server error while inserting into user_projects.' });
                  }

                  console.log("Successfully joined project:", projectId);
                  res.status(200).json({ success: true, projectId });
              }
          );
      }
  );
});













// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

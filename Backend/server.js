const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.JWT_SECRET || "947da71ad91a3f1ddbeb22c911a9b74141d9bea922879c40b3590711ed1be192566558bbcb4bd907435345a3556dd953eb4c96927290a3bd56e65a2100c3811c"
const http = require('http');
const WebSocket = require('ws');
const multer = require('multer');
const path = require('path');







// Load environment variables
dotenv.config();
console.log("SECRET_KEY:", SECRET_KEY);

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const port = 3000;

// Helper function to broadcast messages to all connected WebSocket clients
wss.broadcast = function broadcast(data) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
};
// Middleware
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







app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
      return res.status(400).json({ message: 'All fields are required' });
  }

  const query = 'SELECT id, fullname, username, email, password, role FROM signup WHERE username = ?';
  db.query(query, [username], (err, results) => {
      if (err) return res.status(500).json({ message: 'Internal server error' });

      if (results.length === 0) {
          return res.status(404).json({ message: 'User not found' });
      }

      const user = results[0];

      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ message: 'Error verifying password' });

          if (!isMatch) {
              return res.status(401).json({ message: 'Invalid username or password' });
          }

          // Log user info before token generation
          console.log("User authenticated:", user);

          // Generate JWT token with user-specific data
          const token = jwt.sign(
            { id: user.id, name: user.fullname, username: user.username, email: user.email, role: user.role },  // Unique data per user
            SECRET_KEY,  // Secret key for encryption
            { algorithm: 'HS256', expiresIn: '20h' } // Expiry time for token
        );

          // Log the token
          console.log("Generated Token:", token);

          // Send token and user info in the response
          return res.status(200).json({
            token,
            message: 'Login successful',
            username: user.username,
            role: user.role,
            id: user.id,          
            fullname: user.fullname 
          });
      });
  });
});


//middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1]; // Extract token from "Bearer token" format
  console.log('Token received in middleware:', token);  // Debugging line

  if (!token) {
      return res.status(401).json({ message: 'Unauthorized: No token found' });
  }

  try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded;
     
      console.log('Decoded user:', req.user); // Debugging line
      next();
  } catch (err) {
      console.error('Error verifying token:', err);
      return res.status(401).json({ message: 'Unauthorized: Invalid token' });
  }
};


// Protected route 
app.get('/api/protected', authenticateToken, (req, res) => {
  console.log('Authenticated User ID:', req.user.id); // Confirm the decoded ID

  const query = 'SELECT id, fullname, username, role FROM signup WHERE id = ?';
  db.query(query, [req.user.id], (err, results) => {
      if (err) {
          console.error('Database Query Error:', err);
          return res.status(500).json({ message: 'Internal Server Error' });
      }

      if (results.length === 0) {
          console.log('User Not Found');
          return res.status(404).json({ message: 'User not found' });
      }

      console.log('Fetched User Data:', results[0]);

      // Return user details
      res.json({ message: 'Authenticated', user: results[0] });
  });
});


// Token verification middleware
// Middleware to verify token and extract user_id
function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header
  
  if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
          return res.status(403).json({ error: 'Invalid or expired token.' });
      }
      
      req.userId = decoded.user.id;  // Attach userId to the request object
      next();
  });
}


// API endpoint to add a project
const { v4: uuidv4 } = require('uuid');

// API endpoint to add a project
app.post('/add-project', authenticateToken, (req, res) => {
  const { projectName } = req.body;
  const userId = req.user.id;

  if (!projectName || projectName.trim() === '') {
      return res.status(400).json({ error: 'Project name is required.' });
  }

  // Check if the project already exists for the same user
  const checkQuery = 'SELECT * FROM project WHERE name = ? AND admin_id = ?';
  db.query(checkQuery, [projectName, userId], (err, results) => {
      if (err) {
          console.error('Error checking project existence:', err);
          return res.status(500).json({ error: 'Database error.' });
      }

      if (results.length > 0) {
          return res.status(409).json({ error: 'Project already exists.' }); // HTTP 409 Conflict
      }

      // Generate a unique project key
      const projectKey = crypto.randomBytes(4).toString('hex'); // 8-character key

      // Insert project with generated project key
      const insertQuery = 'INSERT INTO project (name, admin_id, project_key) VALUES (?, ?, ?)';
      db.query(insertQuery, [projectName, userId, projectKey], (err, result) => {
          if (err) {
              console.error('Error inserting project into database:', err);
              return res.status(500).json({ error: 'Failed to add project.' });
          }
          res.status(201).json({ message: 'Project added successfully.', projectId: result.insertId, projectKey });
      });
  });
});


// API endpoint to get all projects for the logged-in user
app.get('/project', authenticateToken, (req, res) => {
  const userId = req.user.id;  // Get user ID from token

  // Query to get projects associated with the logged-in user
  const query = 'SELECT id, name, project_key FROM project WHERE admin_id = ?';
  db.query(query, [userId], (err, result) => {
      if (err) {
          console.error('Error fetching projects:', err);
          return res.status(500).json({ error: 'Failed to fetch projects.' });
      }

      res.json(result); // Return the projects with id and project_key
  });
});


// API endpoint to delete a project using projectKey
app.delete('/project/:projectKey', authenticateToken, (req, res) => {
    const projectKey = req.params.projectKey;
    const userId = req.user.id;  // Get user ID from token

    if (!projectKey) {
        return res.status(400).json({ error: 'Project Key is required' });
    }

    // Query to delete the project only if it belongs to the logged-in user
    const sql = 'DELETE FROM project WHERE project_key = ? AND admin_id = ?';
    db.query(sql, [projectKey, userId], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to delete project' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Project not found or you are not authorized to delete it' });
        }

        console.log(`Project with Key ${projectKey} deleted successfully.`);
        return res.status(200).json({ success: true });
    });
});





//Generate code

app.post('/generate-invite-code', async (req, res) => {
  const { projectId } = req.body;

  if (!projectId) {
      return res.status(400).json({ error: "Project ID is required" });
  }

  // Generate an 8-character invite code
  const inviteCode = crypto.randomBytes(4).toString('hex').toUpperCase();

  // Set expiry time (current time + 10 minutes)
  const expiryTimestamp = Math.floor(Date.now() / 1000) + 600; // 600 sec = 10 min

  try {
      // Check if there's already an invite code
      const checkQuery = `SELECT invite_code, invite_expires_at FROM project WHERE id = ?`;
      db.query(checkQuery, [projectId], (err, results) => {
          if (err) {
              console.error("Database error:", err);
              return res.status(500).json({ error: "Error checking existing invite code" });
          }

          const currentTime = Math.floor(Date.now() / 1000);

          if (results.length > 0) {
              const existingCode = results[0].invite_code;
              const existingExpiry = results[0].expiry_time;

              // If the existing code is still valid (less than 10 seconds old), prevent a new one
              if (existingCode && existingExpiry && (existingExpiry - currentTime) > 590) {
                  const remainingTime = existingExpiry - currentTime;
                  return res.status(400).json({ error: `Please wait ${remainingTime - 590} seconds before generating a new code.` });
              }
          }

          // Update the project with the new invite code and expiry time
          const updateQuery = `UPDATE project SET invite_code = ?, invite_expires_at = ? WHERE id = ?`;
          db.query(updateQuery, [inviteCode, expiryTimestamp, projectId], (err, result) => {
              if (err) {
                  console.error("Database error:", err);
                  return res.status(500).json({ error: "Error saving invite code" });
              }
              return res.json({ success: true, inviteCode });
          });
      });
  } catch (err) {
      console.error("Unexpected error:", err);
      return res.status(500).json({ error: "Server error generating invite code" });
  }
});


// WebSocket server-side logic
wss.on('connection', (ws) => {
  console.log('A new client connected');
  ws.on('message', (message) => {
      console.log('Received:', message);
  });
  
  ws.on('close', () => {
      console.log('Client disconnected');
  });
});

//join-project endpoint to broadcast a message
app.post('/join-project', authenticateToken, (req, res) => {
  const { inviteCode } = req.body;
  const userId = req.user.id;
  const name = req.user.name;  // This is the user's full name
  const email = req.user.email;  // This is the user's email
  


  console.log("Received Request to Join Project");
  console.log("Invite Code:", inviteCode, "User ID:", userId);

  if (!inviteCode || !userId) {
      console.log("❌ Missing inviteCode or userId");
      return res.status(400).json({ error: 'Invite code and user ID are required.' });
  }

  db.query(
      'SELECT project_key, name, invite_expires_at, admin_id FROM project WHERE invite_code = ?'
,
      [inviteCode],
      (error, rows) => {
          if (error) {
              console.error('❌ Database error:', error);
              return res.status(500).json({ error: 'Internal server error during query execution.' });
          }

          if (rows.length === 0) {
              console.log("❌ Invalid Invite Code");
              return res.status(400).json({ error: 'Invalid invite code.' });
          }

          const projectKey = rows[0].project_key;
          const inviteExpiry = rows[0].invite_expires_at;
          const adminId = rows[0].admin_id;
          const projectName = rows[0].name;
          console.log("Project Name:", projectName);


          console.log("🟢 Found Project Key:", projectKey);

          // Check if the invite code has expired
          const currentTime = new Date();
          if (inviteExpiry && new Date(inviteExpiry) < currentTime) {
              console.log("❌ Invite Code Expired");
              return res.status(400).json({ error: 'Invite code has expired.' });
          }

          // Fetch the admin's name for storing in user_project table
          db.query(
              'SELECT fullname FROM signup WHERE id = ?',
              [adminId],
              (adminError, adminResults) => {
                  if (adminError) {
                      console.error('❌ Error fetching admin data:', adminError);
                      return res.status(500).json({ error: 'Error fetching admin data.' });
                  }

                  const adminName = adminResults[0].fullname;

                  // Insert user into user_projects table with admin_name, fullname, and email
                  db.query(
                  'INSERT INTO user_project (user_id, project_key, admin_name, fullname, email) VALUES (?, ?, ?, ?, ?)',
                  [userId, projectKey, adminName, name, email],
                  (insertError) => {
                    if (insertError) return res.status(500).json({ error: 'Failed to join project.' });

                    console.log("✅ User joined project:", projectKey);

                    // ✅ Define the user object here for notification
                    const user = { fullname: name };
                    const message = `${name} joined the project ${projectName}`;

                    // ✅ Save notification to DB
                    db.query(
                      'INSERT INTO notifications (admin_id, message) VALUES (?, ?)',
                      [adminId, message],
                      (notifErr) => {
                        if (notifErr) {
                          console.error('❌ Failed to store notification:', notifErr);
                          // Continue anyway — it's not critical to block the user
                        }
                        const timestamp = new Date().toISOString();
                        // ✅ Broadcast to all admins
                        wss.clients.forEach((client) => {
                          if (client.readyState === WebSocket.OPEN && client.adminId == adminId) {
                            client.send(JSON.stringify({
                              type: 'USER_JOINED',
                              message,
                              timestamp: timestamp
                            }));
                          }
                        });

                      }
                    );
                    res.status(200).json({ success: true, projectKey, projectName });
                  }
                );
                  
              }
          );
      }
  );
});


app.get('/get-project-keys', authenticateToken, (req, res) => {
  const adminId = req.user.id;

  db.query(
      'SELECT project_key FROM project WHERE admin_id = ?',
      [adminId],
      (error, results) => {
          if (error) {
              console.error('❌ Database error:', error);
              return res.status(500).json({ error: 'Internal server error.' });
          }

          if (results.length === 0) {
              return res.status(404).json({ error: 'No projects found for this admin.' });
          }

          const keys = results.map(row => row.project_key);
          res.status(200).json({ projectKeys: keys });
      }
  );
});


app.get('/get-users', authenticateToken, (req, res) => {
  const projectKey = req.query.projectKey;

  const query = `
      SELECT s.id AS user_id, s.fullname, s.email
      FROM user_project up
      JOIN signup s ON up.user_id = s.id
      WHERE up.project_key = ?
  `;

  db.query(query, [projectKey], (err, results) => {
      if (err) {
          console.error('❌ DB error:', err);
          return res.status(500).json({ error: 'Internal server error' });
      }

      res.status(200).json(results);
  });
});


app.get('/my-projects', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query(
    `SELECT p.project_key, p.name AS project_name, up.admin_name 
     FROM user_project up 
     JOIN project p ON up.project_key = p.project_key 
     WHERE up.user_id = ?`,
    [userId],
    (err, results) => {
      if (err) {
        console.error('❌ Error fetching user projects:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const projects = results.map(row => ({
        project_key: row.project_key,     // ✅ Include this
        project_name: row.project_name,
        admin_name: row.admin_name,
      }));

      res.status(200).json({ success: true, projects });
    }
  );
});


// GET endpoint to return logged-in user's profile
app.get('/api/user/profile', authenticateToken, (req, res) => {
  const userId = req.user.id; // assuming your token contains user.id

  db.query(
    'SELECT fullname, username, email, phone_number FROM signup WHERE id = ?',
    [userId],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (results.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json(results[0]);
    }
  );
});



// Storage config
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
      cb(null, 'uploads/profile_pics');
  },
  filename: function (req, file, cb) {
      const ext = path.extname(file.originalname);
      cb(null, Date.now() + '-' + file.fieldname + ext);
  }
});

const upload = multer({ storage: storage });
module.exports = upload;

// Profile pic upload
app.post('/upload-profile-pic', authenticateToken, upload.single('profile'), (req, res) => {
  const userId = req.user.id;
  const filePath = `/uploads/profile_pics/${req.file.filename}`;

  const sql = 'UPDATE signup SET profile_picture = ? WHERE id = ?';
  db.query(sql, [filePath, userId], (err) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ success: true, path: filePath });
  });
});

app.get('/get-profile-pic', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const sql = 'SELECT profile_picture FROM signup WHERE id = ?';
  db.query(sql, [userId], (err, results) => {
      if (err || results.length === 0) {
          return res.status(404).json({ error: 'Not found' });
      }

      res.json({ profilePic: results[0].profile_picture });
  });
});



app.use('/uploads', express.static('uploads'));

// API endpoint to get users for a selected project
app.get('/users-for-project', authenticateToken, (req, res) => {
  const projectKey = req.query.projectKey; // Get projectKey from query parameters

  if (!projectKey) {
      return res.status(400).json({ error: 'Project key is required' });
  }

  const query = 'SELECT s.id, s.fullname, s.email FROM user_project up JOIN signup s ON up.user_id = s.id WHERE up.project_key = ?';
  
  db.query(query, [projectKey], (err, result) => {
      if (err) {
          console.error('Error fetching users for project:', err);
          return res.status(500).json({ error: 'Failed to fetch users.' });
      }

      res.json(result); // Return the users who have joined the project
  });
});


// Set up storage for task attachments
const taskStorage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, 'uploads/tasks');
  },
  filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
  }
});


const uploads = multer({ storage: taskStorage });
module.exports = uploads;

app.post('/assign-task', authenticateToken, upload.array('attachments', 10), (req, res) => {
  const { title, projectKey, userId, dueDate } = req.body;
  const adminId = req.user.id;

  if (!title || !projectKey || !userId || !dueDate) {
      return res.status(400).json({ error: 'All fields are required.' });
  }

  const filePaths = req.files.map(file => file.filename);

  const query = 'INSERT INTO tasks (title, attachments, project_key, assigned_to, due_date, status, assigned_by) VALUES (?, ?, ?, ?, ?, ?, ?)';
  db.query(query, [title, JSON.stringify(filePaths), projectKey, userId, dueDate, 'To-Do', adminId], (err, result) => {
      if (err) {
          console.error('Error assigning task:', err);
          return res.status(500).json({ error: 'Failed to assign task.' });
      }

      return res.status(200).json({ success: true, message: 'Task assigned successfully.' });
  });
});


// Get all tasks assigned by the current admin
app.get('/tasks', authenticateToken, (req, res) => {
  const adminId = req.user.id;
  const query = `
      SELECT 
          t.id, 
          t.title, 
          t.due_date, 
          t.status, 
          s.fullname AS assigned_to_name, 
          p.name AS project_name
      FROM 
          tasks t
      JOIN 
          signup s ON t.assigned_to = s.id
      JOIN 
          project p ON t.project_key = p.project_key
      WHERE 
          t.assigned_by = ?
      ORDER BY 
          t.created_at DESC
  `;

  db.query(query, [adminId], (err, results) => {
      if (err) {
          console.error("Error fetching tasks:", err);
          return res.status(500).json({ error: 'Failed to fetch tasks' });
      }

      res.json(results);
  });
});






app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/user-tasks', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
      SELECT 
          t.id, 
          t.title, 
          t.due_date, 
          t.status, 
          t.attachments, 
          p.name AS project_name, 
          s.fullname AS assigned_by_name
      FROM 
          tasks t
      JOIN 
          project p ON t.project_key = p.project_key
      JOIN 
          signup s ON t.assigned_by = s.id
      WHERE 
          t.assigned_to = ?
      ORDER BY 
          t.created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
      if (err) {
          console.error("Error fetching user tasks:", err);
          return res.status(500).json({ error: 'Internal server error' });
      }

      // Parse JSON string to array before sending
      const tasks = results.map(task => ({
          ...task,
          attachments: task.attachments ? JSON.parse(task.attachments) : []
      }));

      res.json(tasks);
  });
});

const mime = require('mime-types');
const { timeStamp } = require('console');

app.get('/download/:folder/:filename', (req, res) => {
  const { folder, filename } = req.params;
  const filePath = path.join(__dirname, 'uploads', folder, filename);

  const contentType = mime.lookup(filePath) || 'application/octet-stream';
  res.setHeader('Content-Type', contentType);

  res.sendFile(filePath, (err) => {
    if (err) {
      console.error("SendFile error:", err);
      res.status(404).send("File not found");
    }
  });
});



app.get('/get-tasks', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const status = req.query.status || 'to-do'; // Default to 'to-do' if no status is provided

  // Query to get tasks by status
  const query = `
      SELECT 
          t.id, t.title, t.due_date, t.status, t.assigned_to, s.fullname AS assigned_to_name
      FROM 
          tasks t
      JOIN 
          signup s ON t.assigned_to = s.id
      WHERE 
          t.assigned_to = ? AND t.status = ?
      ORDER BY 
          t.due_date DESC
  `;

  db.query(query, [userId, status], (err, result) => {
      if (err) {
          console.error('Error fetching tasks:', err);
          return res.status(500).json({ error: 'Failed to fetch tasks.' });
      }
      res.json(result);
  });
});






// Delete a task by ID
app.delete('/tasks/:id', authenticateToken, (req, res) => {
  const taskId = req.params.id;

  const query = 'DELETE FROM tasks WHERE id = ?';
  
  db.query(query, [taskId], (err, result) => {
      if (err) {
          console.error('Error deleting task:', err);
          return res.status(500).json({ success: false, message: 'Failed to delete task' });
      }

      if (result.affectedRows === 0) {
          return res.status(404).json({ success: false, message: 'Task not found' });
      }

      res.json({ success: true, message: 'Task deleted successfully' });
  });
});


app.get('/project-tasks/:projectKey', authenticateToken, (req, res) => {
  const projectKey = req.params.projectKey;
 // Get the project key from the URL
  const userId = req.user.id; // Assuming the user ID is attached to the request by the authenticateToken middleware

  console.log("Received Project Key:", projectKey);  // Debugging
  console.log("User ID:", userId); // Debugging

  db.query(
      `SELECT t.id, t.title  
       FROM tasks t 
       WHERE t.project_key = ?`,
      [projectKey],
      (err, results) => {
          if (err) {
              console.error('❌ Error fetching tasks:', err);
              return res.status(500).json({ error: 'Internal server error' });
          }

          console.log("Fetched Tasks from DB:", results); // Debugging

          const tasks = results.map(row => ({
              id: row.id,
              name: row.title,
          }));

          if (tasks.length === 0) {
              console.log("No tasks found for this project."); // Debugging
          }

          res.status(200).json({ success: true, tasks });
      }
  );
});


app.get('/tasks-assigned-by-admin', authenticateToken, (req, res) => {
  const adminId = req.user.id;

  const query = `
      SELECT 
          t.id, 
          t.title, 
          t.due_date, 
          t.status, 
          s.fullname AS assigned_to_name, 
          p.name AS project_name
      FROM 
          tasks t
      JOIN 
          signup s ON t.assigned_to = s.id
      JOIN 
          project p ON t.project_key = p.project_key
      WHERE 
          t.assigned_by = ?
      ORDER BY 
          t.created_at DESC
  `;

  db.query(query, [adminId], (err, results) => {
      if (err) {
          console.error("Error fetching assigned tasks:", err);
          return res.status(500).json({ error: 'Failed to fetch tasks' });
      }

      res.json(results);
  });
});


app.get('/tasks-assigned', authenticateToken, (req, res) => {
  const adminId = req.user.id;

  const query = `
      SELECT 
          t.id, 
          t.title, 
          t.due_date, 
          t.status, 
          s.fullname AS assigned_by_name, 
          p.name AS project_name
      FROM 
          tasks t
      JOIN 
          signup s ON t.assigned_by = s.id
      JOIN 
          project p ON t.project_key = p.project_key
      WHERE 
          t.assigned_to = ?
      ORDER BY 
          t.created_at DESC
  `;

  db.query(query, [adminId], (err, results) => {
      if (err) {
          console.error("Error fetching assigned tasks:", err);
          return res.status(500).json({ error: 'Failed to fetch tasks' });
      }

      res.json(results);
  });
});

// Serve static files (uploads) from the 'uploads' directory
app.use('/uploads', express.static('uploads'));

app.post('/submit-task', upload.single('file'), (req, res) => {
    const { project_name, task_title, description } = req.body;
    const filePath = req.file ? req.file.filename : null;

    // First, check if the task is already submitted for the selected project
    const checkQuery = `SELECT * FROM submitted_task WHERE project_name = ? AND task_title = ?`;
    db.query(checkQuery, [project_name, task_title], (err, result) => {
        if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ message: 'Failed to check task' });
        }

        // If result is not empty, that means the task is already submitted
        if (result.length > 0) {
            return res.status(400).json({ message: 'Task already submitted for this project' });
        }

        // Otherwise, insert the new task into the table
        const insertQuery = `INSERT INTO submitted_task (project_name, task_title, file, description) VALUES (?, ?, ?, ?)`;
        db.query(insertQuery, [project_name, task_title, filePath, description], (err, result) => {
            if (err) {
                console.error('DB Error:', err);
                return res.status(500).json({ message: 'Failed to submit task' });
            }
            res.json({ message: 'Task submitted successfully!' });
        });
    });
});


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// Route to fetch task details, including attachments
app.get('/task-details', authenticateToken, (req, res) => {
  const { task_title } = req.query;

  if (!task_title) {
    return res.status(400).json({ message: 'Missing task_title' });
  }

  const query = `
    SELECT 
      st.project_name AS project_key, 
      p.name AS project_name, 
      st.task_title, 
      st.file, 
      st.description 
    FROM submitted_task st
    JOIN project p ON st.project_name = p.project_key
    WHERE st.task_title = ?
  `;

  db.query(query, [task_title], (err, result) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ message: 'Failed to retrieve task details' });
    }

    if (result.length > 0) {
      const task = result[0];
      const fileUrls = task.file ? [`/uploads/profile_pics/${task.file}`] : [];

      res.json({
        project_key: task.project_key,
        project_name: task.project_name,
        title: task.task_title,
        attachments: fileUrls,
        description: task.description
      });
    } else {
      res.status(404).json({ message: 'Task not found' });
    }
  });
});

app.put('/update-task-status/:id', authenticateToken, (req, res) => {
  const taskId = req.params.id;
  const { status } = req.body;

  const query = 'UPDATE tasks SET status = ? WHERE id = ?';
  db.query(query, [status, taskId], (err, result) => {
      if (err) {
          console.error('Error updating task status:', err);
          return res.status(500).json({ error: 'Failed to update status' });
      }

      // Broadcast the status update to all connected clients
      const message = JSON.stringify({ event: 'taskStatusUpdated', taskId, newStatus: status });
      wss.broadcast(message);

      res.json({ message: 'Task status updated successfully' });
  });
});


app.use('/Frontend', express.static(path.join(__dirname, 'Frontend')));

app.post('/api/update-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.id; // Assuming the user ID is in the token

  if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Both old and new passwords are required.' });
  }

  // Fetch the current user data from the database
  db.query('SELECT * FROM signup WHERE id = ?', [userId], async (err, results) => {
      if (err || results.length === 0) {
          return res.status(404).json({ error: 'User not found.' });
      }

      const user = results[0];

      // Compare the old password with the stored password
      const isOldPasswordCorrect = await bcrypt.compare(oldPassword, user.password);
      if (!isOldPasswordCorrect) {
          return res.status(400).json({ error: 'Old password is incorrect.' });
      }

      // Hash the new password before saving it
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);

      // Update the password in the database
      db.query(
          'UPDATE signup SET password = ? WHERE id = ?',
          [hashedNewPassword, userId],
          (err) => {
              if (err) {
                  return res.status(500).json({ error: 'Error updating password.' });
              }

              res.json({ message: 'Password updated successfully.' });
          }
      );
  });
});

//notification system
wss.on('connection', function connection(ws, req) {
  ws.on('message', function incoming(message) {
    const data = JSON.parse(message);

    if (data.type === 'REGISTER_ADMIN') {
      ws.adminId = data.adminId;
      console.log('Registered admin with ID:', ws.adminId);
    }
  });
});



app.get('/api/notifications', (req, res) => {
  const adminId = req.query.adminId;

  if (!adminId) {
    return res.status(400).json({ error: 'Missing adminId' });
  }

  db.query(
    'SELECT id, message, timestamp FROM notifications WHERE admin_id = ? ORDER BY timestamp DESC LIMIT 50',
    [adminId],
    (err, results) => {
      if (err) {
        console.error('❌ Error fetching notifications:', err);
        return res.status(500).json({ error: 'Failed to fetch notifications' });
      }
      res.json(results); 
    }
  );
});



app.delete('/api/notifications/:id', (req, res) => {
  const notificationId = req.params.id;

  if (!notificationId) {
    return res.status(400).json({ error: 'Notification ID is required' });
  }

  // Delete the notification from the database
  db.query(
    'DELETE FROM notifications WHERE id = ?',
    [notificationId],
    (err, results) => {
      if (err) {
        console.error('❌ Error deleting notification:', err);
        return res.status(500).json({ error: 'Failed to delete notification' });
      }

      if (results.affectedRows === 0) {
        return res.status(404).json({ error: 'Notification not found' });
      }

      res.status(200).json({ success: true });
    }
  );
});


// Start the server
server.listen(3000, () => {
  console.log('WebSocket server is running on ws://localhost:3000');
});
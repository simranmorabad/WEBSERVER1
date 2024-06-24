import express from "express";
import pg from 'pg';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';

const app = express();
const port = 3001;

// Add body-parser middleware to parse JSON and urlencoded request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


// Database configuration
const dbConfig = {
  user: 'newuser',
  password: 'root123',
  host: 'localhost', // Use IPv4 explicitly
  port: 5432,
  database: 'postgres'
};

// Create a PostgreSQL pool
const pool = new pg.Pool(dbConfig);

// Function to execute SQL queries
const executeQuery = async (sql, params) => {
  const client = await pool.connect();
  try {
    const { rows } = await client.query(sql, params);
    return rows;
  } catch (error) {
    throw error;
  } finally {
    client.release(); // Release the client back to the pool
  }
};

const generateToken = (id) => {
  const payload = { id };
  const token = jwt.sign(payload, '750598f77b82efd53cbb93c2251dfb3c8ef8839e2e96d243e6bd6018c7708034', { expiresIn: '5m' });
  return token;
};
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).json({ error: 'Token is required' });
  }
  jwt.verify(token, '750598f77b82efd53cbb93c2251dfb3c8ef8839e2e96d243e6bd6018c7708034', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Failed to authenticate token' });
    }
    req.user = decoded; // Attach the decoded token data to req.user
    next();
  });
};

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Check if the username exists in the database
    const sql = 'SELECT * FROM users_table WHERE username = $1';
    const users = await executeQuery(sql, [username]);
    if (users.length > 0) {
      // User exists, check password
      const user = users[0]; // Assuming username is unique
      if (user.password === password) {
        // Passwords match, login successful
        const token = generateToken(user.id); // Use user.id
        res.json({ message: 'Login successful!', token });
        console.log('login sucessful');
      } else {
        // Passwords don't match, send error message
        res.status(401).json({ error: 'Incorrect password. Please try again.' });
      }
    } else {
      // User doesn't exist, send response indicating need to register
      res.status(404).json({ error: 'User not found. Please register.' });
    }
  } catch (error) {
    console.error('Error checking login credentials:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Route for registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Check if the username already exists in the database
    const sql = 'SELECT * FROM users_table WHERE username = $1';
    const users = await executeQuery(sql, [username]);
    if (users.length > 0) {
      // Username already exists, send message
      res.status(400).json({ message: 'User already exists. Please choose a different username.' });
      return;
    }

    // Insert the new user into the database with provided values
    const insertSql = 'INSERT INTO users_table (username, password) VALUES ($1, $2)';
    await executeQuery(insertSql, [username, password]);
    res.json({ message: 'Registration successful!' });
    console.log('registered sucessfully');
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/user/:id', verifyToken,async (req, res) => {
  const userId = req.params.id; // Extract userId from URL parameters

  try {
    // Query to fetch user by ID
    const sql = 'SELECT * FROM users_table WHERE id = $1';
    const users = await executeQuery(sql, [userId]);

    if (users.length === 0) {
      res.status(404).json({ error: 'User not found.' });
    } else {
      // Check if the requested user ID matches the authenticated user
      if (req.user.id === parseInt(userId, 10)) { // Ensure the types match
        // Return user details only if the requested user ID matches the authenticated user
        res.json({ user: users[0] });
      } else {
        res.status(403).json({ error: 'Access denied. You can only access your own user details.' });
      }
    }
  } catch (error) {
    console.error('Error fetching user by ID:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/delete/user/:id', verifyToken, async (req, res) => {
  const userId = req.params.id;

  // Check if the authenticated user has ID 6 and is not trying to delete their own account
  if (req.user.id === 6) {
    if (req.user.id === parseInt(userId, 10)) {
      res.status(403).json({ error: 'Access denied. You cannot delete your own account.' });
    } else {
      // Allow deletion if the authenticated user is ID 6 and is not deleting their own account
      const sql = 'DELETE FROM users_table WHERE id = $1';
      await executeQuery(sql, [userId]);
      res.json({ message: 'User deleted successfully' });
    }
  } else {
    res.status(403).json({ error: 'Access denied. Only user with ID 6 can delete users.' });
  }
});

// Default route
app.get('/', (req, res) => {
  res.send('Welcome to my server!');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

app.get('/protected-route', verifyToken, (req, res) => {
  res.json({ message: 'You have access to this protected route', user: req.user });
});


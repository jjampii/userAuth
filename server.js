const express = require('express')

const mysql = require ('mysql2')

const cors = require('cors')
const jwt  = require('jsonwebtoken')
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json())

const db = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD, 
  database: process.env.DATABASE,
  port: process.env.DBPORT,
  ssl: {
    rejectUnauthorized: false  }
});

db.connect((err) => {
    if (err){
        
        console.error(`error connecting to database ${err}`)
        return
    }
    console.log('connected')

    const createTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`;

db.query(createTableQuery, (err, result) => {
  if (err) {
    console.error('Error creating table:', err);
  } else {
    console.log('✅ Table "users" is ready.');
  }
});
})

app.post('/signUp', (req, res) => {
    const {email, password} = req.body;
    
     if (!email && !password){
        return res.status(400).json({message:'Email and Password are required'})
    }

    if (!email){
        return res.status(400).json({message:'A valid email is required'})
    }
    if (!password){
        return res.status(400).json({message:'Password is required'})
    }
      if (password.length < 8) {
        return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);  // Hash password
    
    db.query('INSERT INTO users (email, password) values (?,?)', [email,hashedPassword], (err, result) =>{
       
        if (err) {
            if (err.code === 'ER_DUP_ENTRY' ){
                return res.status(409).json({message:'Email already exist, Please try another email'})
            }else{
                
                return res.status(500).json({message:'Database error'})
            }
        }
        res.status(201).send({message:'Registration Successful'});
    })
})

app.post('/login', (req, res) => {
    let {email, password} = req.body;

    email = String(email || '').trim();
    password = String(password || '').trim();

      if (!email && !password){
        return res.status(400).json({message:'Email and Password are required'})
    }

    if (!email) {
        return res.status(400).json({message:'Please enter your email'})
    }

    if (!password) {
        return res.status(400).json({message:'Please enter your password'})
    }
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, result) =>{
        
        if (err || result.length == 0 )  {
            return res.status(400).json({message:'No account found with that email address.'})
        }
        const match =  await bcrypt.compare(password, result[0].password)

        if (!match) {
            return res.status(401).json({message:'Incorrect password. Please try again'})

        }

        const token = jwt.sign({
            email: result[0].email
        },
       process.env.JWT_SECRET_KEY

    )
        
        res.status(201).json({message:'Login Success', token, user: {email:result[0].email}});
    })
})

app.get('/home', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token missing' });

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    res.json({ message: `Welcome home, ${decoded.email}!` });
  });
});
app.listen(5000, () => console.log(`server runnning at PORT: ${process.env.PORT || 5000}`));
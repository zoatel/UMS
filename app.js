import mysql from 'mysql2'
import dotenv from 'dotenv'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import pg from 'pg'

dotenv.config()
const {Client} = pg;
const app = express()

app.use(cors())
app.use(express.json());

const port = process.env.PORT || 8080

const client = new Client({
  database: process.env.DATABASE,
  host: process.env.HOST,
  port: process.env.DPORT,
  user: process.env.USER,
  password: process.env.PASSWORD,
  ssl: {
      "rejectUnauthorized": true
    }
});

client.connect();

const generateStudentAccessToken = (user) => {
    return jwt.sign({ seat_no: user.seat_no, name: user.name, email: user.email }, process.env.AT_SECRET_KRY, {
      expiresIn: "5s",
    });
  };
  
const generateStudentRefreshToken = (user) => {
    return jwt.sign({ nat_id: user.nat_id, name: user.name, email: user.email }, process.env.RT_SECRET_KRY);
};

const generateInstructorAccessToken = (user) => {
    return jwt.sign({ nat_id: user.nat_id, name: user.name, email: user.email }, process.env.AT_SECRET_KRY, {
      expiresIn: "5s",
    });
  };
  
const generateInstructorRefreshToken = (user) => {
    return jwt.sign({ nat_id: user.nat_id, name: user.name, email: user.email }, process.env.RT_SECRET_KRY);
};

app.post('/api/student/signup', async (req, res) =>{
    const { SEAT_NO, NAME, EMAIL, PASSWORD, B_DATE, P_NUMBER, NAT_ID } = req.body;
    const hashPass = await bcrypt.hash(PASSWORD, 10);
    const values = [SEAT_NO, NAME, EMAIL, hashPass, B_DATE, P_NUMBER, NAT_ID]
    try {
        const result = await client.query('INSERT INTO STUDENTS (SEAT_NO, NAME, EMAIL, PASSWORD, B_DATE, P_NUMBER, NAT_ID) VALUES ($1,$2,$3,$4,$5,$6,$7)', values)
        //console.log(result)
        res.status(200).json('SIGNED')
    } catch (err) {
        //console.log(err.stack)
        res.status(400).json(err)
    }
})

app.post('/api/instructor/signup', async (req, res) =>{
    const { NAT_ID, NAME, EMAIL, PASSWORD, B_DATE, P_NUMBER } = req.body;
    const hashPass = await bcrypt.hash(PASSWORD, 10);
    const values = [ NAT_ID, NAME, EMAIL, hashPass, B_DATE, P_NUMBER ]
    try {
        const result = await client.query('INSERT INTO INSTRUCTORS (NAT_ID, NAME, EMAIL, PASSWORD, B_DATE, P_NUMBER) VALUES ($1,$2,$3,$4,$5,$6)', values)
        //console.log(result)
        res.status(200).json('SIGNED')
    } catch (err) {
        //console.log(err.stack)
        res.status(400).json(err)
    }
})

app.post("/api/student/login", async (req, res) => {
    const { EMAIL, PASSWORD } = req.body;
    const values = [EMAIL]
    let user = {};
    try {
        const result = await client.query('SELECT * FROM STUDENTS WHERE email = $1', values)
        if(result.rows[0]){
            user = result.rows[0];
        }else{
            return res.status(400).json("INOTREG")
        }
    } catch (err) {
        //console.log(err.stack)
        return res.status(400).json(err)
    }
    const isMatch = await bcrypt.compare(PASSWORD, user.password)
    if (user && isMatch) {
      //Generate an access token
      const accessToken = generateStudentAccessToken(user);
      const refreshToken = generateStudentRefreshToken(user);
      const values2 = [user.seat_no, refreshToken, refreshToken]
      try {
        const result = await client.query('INSERT INTO students_rt (STUDENT_ID, RT) VALUES ($1,$2) ON CONFLICT (STUDENT_ID) DO UPDATE SET RT = $3', values2)
      } catch (err) {
        //console.log(err.stack)
        return res.status(400).json(err)
      }
      res.json({
        seat_no: user.seat_no,
        name: user.name,
        email: user.email,
        accessToken,
        refreshToken,
      });
    } else {
      res.status(400).json("password incorrect!");
    }
})

app.post("/api/instructor/login", async (req, res) => {
    const { EMAIL, PASSWORD } = req.body;
    const values = [EMAIL]
    let user = {};
    try {
        const result = await client.query('SELECT * FROM INSTRUCTORS WHERE email = $1', values)
        if(result.rows[0]){
            user = result.rows[0];
        }else{
            return res.status(400).json("INOTREG")
        }
    } catch (err) {
        //console.log(err.stack)
        return res.status(400).json(err)
    }
    const isMatch = await bcrypt.compare(PASSWORD, user.password)
    if (user && isMatch) {
      //Generate an access token
      const accessToken = generateInstructorAccessToken(user);
      const refreshToken = generateInstructorRefreshToken(user);
      const values2 = [user.nat_id, refreshToken, refreshToken]
      try {
        const result = await client.query('INSERT INTO instructors_rt (INSTRUCTOR_ID, RT) VALUES ($1,$2) ON CONFLICT (INSTRUCTOR_ID) DO UPDATE SET RT = $3', values2)
      } catch (err) {
        //console.log(err.stack)
        return res.status(400).json(err)
      }
      res.json({
        nat_id: user.nat_id,
        name: user.name,
        email: user.email,
        accessToken,
        refreshToken,
      });
    } else {
      res.status(400).json("password incorrect!");
    }
})




app.listen(port, ()=>{
    console.log(`listenning on port ${port}`)
})



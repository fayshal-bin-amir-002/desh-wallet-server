const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express');
var jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();
const app = express();
const port = process.env.PORT || 3000;

app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174']
}));
app.use(express.json());

const user = process.env.DB_USER;
const pass = process.env.DB_PASS;
const saltRounds = 5;
const secret_access_token = process.env.SECRET_ACCESS_TOKEN;

const uri = `mongodb+srv://${user}:${pass}@cluster0.0hiczfr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const database = client.db("deshWalletDB");
        const usersCollection = database.collection("users");
        const sendMoneyCollection = database.collection("sendMoney");
        const cashInCollection = database.collection("cashIn");
        const cashOutCollection = database.collection("cashOut");

        //<---middleware for verify token--->
        const verifyToken = async (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: "Unauthorized Access" });
            }

            const token = req.headers.authorization.split(' ')[1];

            jwt.verify(token, secret_access_token, (error, decoded) => {
                if (error) {
                    return res.status(401).send({ message: "Unauthorized Access" });
                }
                req.decoded = decoded;

                next();
            })
        }

        //<---middleware for verify admin--->
        const verifyAdmin = async (req, res, next) => {
            const user = req.decoded;
            const query = { email: user?.email };
            const result = await usersCollection.findOne(query);
            if (!result || result?.role !== 'admin') {
                return res.status(401).send({ message: "Unauthorized Access" });
            }
            next();
        }

        //<---middleware for verify agent--->
        const verifyAgent = async (req, res, next) => {
            const user = req.decoded;
            const query = { email: user?.email };
            const result = await usersCollection.findOne(query);
            if (!result || result?.role !== 'trainer') {
                return res.status(401).send({ message: "Unauthorized Access" });
            }
            next();
        }

        //<---jwt token req--->
        app.post("/jwt", async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, secret_access_token, { expiresIn: "1h" });
            res.send({ token: token });
        })

        //add new user in db
        app.post("/add-user", async (req, res) => {
            const newUser = req.body;
            const isEmailExists = await usersCollection.findOne({ email: newUser.email });
            const isPhoneExists = await usersCollection.findOne({ phone: newUser.phone });
            if (isEmailExists || isPhoneExists) return res.send({ message: "User already exists!" });
            bcrypt.hash(newUser.pin, saltRounds, async function (err, hash) {
                const user = {
                    ...newUser,
                    pin: hash,
                    status: "pending",
                    role: 'user',
                    balance: 0
                }
                const result = await usersCollection.insertOne(user);
                const regUser = {
                    name: user?.name,
                    email: user?.email,
                    phone: user?.phone,
                    status: user?.status,
                    role: user.role,
                    balance: user?.balance
                }
                res.send({ result, regUser });
            });
        })

        //get user data from db and login info
        app.post("/user", async (req, res) => {
            const user = req.body;
            const isEmailExists = await usersCollection.findOne({ email: user.acc });
            const isPhoneExists = await usersCollection.findOne({ phone: user.acc });
            if (!isEmailExists && !isPhoneExists) return res.send({ message: "Please register first!" });
            let hash;
            let dbUser;
            if (isPhoneExists) hash = isPhoneExists?.pin, dbUser = isPhoneExists;
            if (isEmailExists) hash = isEmailExists?.pin, dbUser = isEmailExists;
            bcrypt.compare(user?.pin, hash, function (err, result) {
                if (!result) {
                    return res.send({ message: "Wrong information!" });
                }
                const loggedUser = {
                    name: dbUser.name,
                    email: dbUser.email,
                    phone: dbUser.phone,
                    status: dbUser.status,
                    role: dbUser.role,
                    balance: dbUser.balance
                }
                res.send(loggedUser);
            });
        })

        //get user data from 
        app.get("/userData/:email", async (req, res) => {
            const email = req.params.email;
            const query = { email: email };
            const options = {
                projection: { _id: 0, name: 1, email: 1, phone: 1, status: 1, role: 1, balance: 1 },
            };
            const result = await usersCollection.findOne(query, options);
            res.send(result);
        })

        //send money to a user
        app.post("/send-money", async (req, res) => {
            const sendMoneyData = req.body;
            console.log(sendMoneyData);
            const query1 = { phone: sendMoneyData.senderNumber };
            const query2 = { phone: sendMoneyData.receiverNumber };

            const updateDoc1 = {
                $inc: {
                    balance: - sendMoneyData.totalAmout
                },
            };
            const updateDoc2 = {
                $inc: {
                    balance: sendMoneyData.sentAmount
                },
            };

            const result1 = await usersCollection.updateOne(query1, updateDoc1);
            const result2 = await usersCollection.updateOne(query2, updateDoc2);

            res.send(result1);

        })

        //get all users
        app.get("/users", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }
            const options = {
                projection: { _id: 1, name: 1, email: 1, phone: 1, status: 1, role: 1, balance: 1 }
            };
            const result = await usersCollection.find({}, options).toArray();

            res.send(result);
        })

        //update a user
        app.patch("/update-user", verifyToken, async (req, res) => {
            const email = req.query.email;
            const phone = req.query.phone;

            if (req?.decoded?.acc !== email && req?.decoded?.acc !== phone) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }
            const { id } = req.body;
            const query = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    status: "verified"
                },
            };
            const updateDoc1 = {
                $inc: {
                    balance: 40
                },
            };
            const result = await usersCollection.updateOne(query, updateDoc);
            const result1 = await usersCollection.updateOne(query, updateDoc1);
            res.send(result);
        })

        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Desh Wallet is running!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})